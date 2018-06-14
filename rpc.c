#include "rpc.h"
#include "log.h"
#include "sock.h"
#include "http_parser.h"
#include "cJSON.h"
#include "sock.h"
#include "policy.h"
#include "hijack.h"
#include <ev.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define RPC_TIMEOUT   1  //1s
#define RPC_ADDR_LEN  64
#define RPC_BUF_LEN   8192
#define RPC_MAX_BODY  4089

#define RPC_TYPE_TOKEN  "type"
#define RPC_POLICY_TOKEN  "policy"

#define MAX_PROC_FD   1024

struct ev_loop *rpc_loop;

extern hjk_process_t  hjk_process;

typedef struct {
    ev_io    rw_watcher;
    ev_timer timeout_watcher;

    char  buffer[RPC_BUF_LEN];
    int   wpos;
    int   done;
    /*
    这里其实最好是记录body在buffer中的索引，但是http_parser库获取不到。
    这里有优化空间。
    */
    char  body[RPC_MAX_BODY]; 
    int   bpos;

    char  addr[RPC_ADDR_LEN];

    int   fd;
    int   listen;

    uint32_t  content_length;

    http_parser parser;
} rpc_connection_t;

static int rpc_on_headers_complete(http_parser *parser);
static int rpc_header_field_cb(http_parser *parser, const char *buf, size_t len);
static int rpc_header_value_cb(http_parser *parser, const char *buf, size_t len);
static int rpc_body_cb(http_parser *parser, const char *buf, size_t len);
static int rpc_on_message_complete(http_parser *parser);

static http_parser_settings parser_settings = {
    .on_headers_complete = rpc_on_headers_complete
   ,.on_message_complete = rpc_on_message_complete
   ,.on_header_field     = rpc_header_field_cb
   ,.on_header_value     = rpc_header_value_cb
   ,.on_body             = rpc_body_cb
};

static int rpc_on_headers_complete(http_parser *parser)
{
    return 0;
}

static int rpc_header_field_cb(http_parser *parser, const char *buf, size_t len)
{
    return 0;
}

static int rpc_header_value_cb(http_parser *parser, const char *buf, size_t len)
{
    return 0;
}

static int rpc_body_cb(http_parser *parser, const char *buf, size_t len)
{
    rpc_connection_t  *conn = (rpc_connection_t *)parser->data;

    if (RPC_MAX_BODY - conn->bpos - 1 < len) {
        return -1;
    }

    memcpy(conn->body + conn->bpos, buf, len);
    conn->bpos += len;

    return 0;
}

static int rpc_on_message_complete(http_parser *parser)
{
    rpc_connection_t *conn = (rpc_connection_t *)parser->data;
    conn->done = 1;

    return 0;
}

static void rpc_conn_free(rpc_connection_t *conn)
{
    close(conn->fd);
    free(conn);
}

static int rpc_req_type(cJSON *root)
{
    cJSON *tnode;

    tnode = cJSON_GetObjectItemCaseSensitive(root, RPC_TYPE_TOKEN);
    if (!tnode || !cJSON_IsNumber(tnode)) {
        return -1;
    }

    return tnode->valuedouble;    
}

//发送响应的时候不走异步, 回复体非常小，默认其会会成功。
static void rpc_req_response(rpc_connection_t *conn)
{
    static char *send_response = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n";
    size_t send_len = strlen(send_response);

    status  s;
    size_t  n = 0;

    s = sock_write(conn->fd, send_response, send_len, &n);
    if (s != OK || n != send_len) {
        log_error("rpc request[client %s] send response failed", conn->addr);
    }

    rpc_conn_free(conn);
    return;
}

static void rpc_pipe_msg(char *buf, size_t len)
{
    int n;

    n = write(hjk_process.fd[1], buf, len);
    if (n != len) {
        log_error("failed send pipe msg to process %d", hjk_process.pid);
    }
}

static void rpc_req_process(rpc_connection_t *conn)
{
    int    i, n;
    int    type;
    cJSON *root, *unode;
    char   buf[MAX_PIPE_BODY];

    root = cJSON_Parse(conn->body);
    if (!root) {
        log_error("rpc request[client %s] body data parse failed", conn->addr);
        goto failed;
    }
    
    type = rpc_req_type(root);
    if (type < uadd || type > idel) {
        log_error("rpc request[client %s] body data with bad type", conn->addr);
        goto failed;
    }

    unode = cJSON_GetObjectItemCaseSensitive(root, RPC_POLICY_TOKEN);
    if (!unode || unode->type != cJSON_Array) {
        log_error("rpc request[client %s] body data with bad elems array", conn->addr);
        goto failed;
    }

    for (i = 0; i < cJSON_GetArraySize(unode); i++) {
        cJSON *subitem = cJSON_GetArrayItem(unode, i);
        if (!subitem || subitem->type != cJSON_String) {
            continue;
        }

        buf[0] = type + '0';

        n = snprintf(buf + 1, MAX_PIPE_BODY - 1, "%s\n", subitem->valuestring);

        rpc_pipe_msg(buf, n + 1);
    }

    cJSON_Delete(root);

    rpc_req_response(conn);
    return;

failed:
    rpc_conn_free(conn);
    return;
}

static void rpc_read_cb(EV_P_ ev_io *w, int revents)
{
    int    parserd;
    status s;
    size_t n;
    
    rpc_connection_t *conn;

    conn = (rpc_connection_t *)w;

    s = sock_read(conn->fd, conn->buffer + conn->wpos, RPC_BUF_LEN - conn->wpos, &n);
    if (s == RETRY) return;

    if (s == ERROR) {
        log_error("failed read rpc request[%s]", strerror(errno));
        goto failed;
    }

    conn->parser.data = conn;

    parserd = http_parser_execute(&conn->parser, &parser_settings, conn->buffer + conn->wpos, n);
    if (parserd != n) {
        log_error("failed parse rpc request[%s]", http_errno_name(HTTP_PARSER_ERRNO(&conn->parser)));
        goto failed;
    }

    conn->wpos += n;

    if (conn->done) {
        ev_io_stop(rpc_loop, w);
        ev_timer_stop(rpc_loop, &conn->timeout_watcher);
        rpc_req_process(conn);
    }

    return;

failed:
    ev_io_stop(rpc_loop, w);
    ev_timer_stop(rpc_loop, &conn->timeout_watcher);
    rpc_conn_free(conn);
    return;
}

static void rpc_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    rpc_connection_t *conn = (rpc_connection_t *)(((char *)w) - offsetof(rpc_connection_t, timeout_watcher));

    log_error("rpc request[client %s] timedout", conn->addr);

    ev_io_stop(rpc_loop, &conn->rw_watcher);
    ev_timer_stop(rpc_loop, w);
    rpc_conn_free(conn);

    return;
}

static void rpc_accept_cb(EV_P_ ev_io *w, int revents)
{
    status   s;
    int      clientfd;
    char     clientaddr[RPC_ADDR_LEN];

    rpc_connection_t  *lconn, *cconn;
    
    lconn = (rpc_connection_t *)w;

    s = sock_accept(lconn->fd, &clientfd, clientaddr, RPC_ADDR_LEN);
    if (s != OK) {
        log_error("rpc accept client connection encounter error[%s]", strerror(errno));
        return;
    }

    sock_nonblocking(clientfd);

    log_debug("rpc accept new client connection %s", clientaddr);

    cconn = (rpc_connection_t *)calloc(1, sizeof(rpc_connection_t));

    http_parser_init(&cconn->parser, HTTP_REQUEST);
    cconn->fd = clientfd;

    memcpy(cconn->addr, clientaddr, RPC_ADDR_LEN);

    ev_io_init(&cconn->rw_watcher, rpc_read_cb, clientfd, EV_READ);
    ev_io_start(rpc_loop, &cconn->rw_watcher);

    ev_timer_init(&cconn->timeout_watcher, rpc_timeout_cb, RPC_TIMEOUT, 0.);
    ev_timer_start(rpc_loop, &cconn->timeout_watcher);
}

static void rpc_ev_fatal_error(const char *msg)
{
    log_fatal("ev event mode fatal error, exit");
    abort();
}

static void rpc_init(const char *ip, int port)
{
    status            s;
    int               listenfd;
    rpc_connection_t *conn;

    s = sock_listen(ip, port, &listenfd);
    if (s == ERROR) {
        log_fatal("failed create rpc service[%s], exit", strerror(errno));
        exit(-1);
    }

    sock_nonblocking(listenfd);

    ev_set_syserr_cb(rpc_ev_fatal_error);

    rpc_loop = ev_loop_new(EVFLAG_AUTO);

    conn = (rpc_connection_t *)calloc(1, sizeof(rpc_connection_t));
    conn->listen = 1;
    conn->fd = listenfd;
    ev_io_init (&conn->rw_watcher, rpc_accept_cb, listenfd, EV_READ);

    ev_io_start(rpc_loop, &conn->rw_watcher);
}

static void rpc_run(void)
{
    ev_run(rpc_loop, 0);
}

void *rpc_service(void *arg)
{
    hjk_cycle_t *cycle = (hjk_cycle_t *)arg;

    rpc_init(cycle->laddr, cycle->lport);
    rpc_run();

    return NULL;
}





