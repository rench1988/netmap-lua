/**
 * @author [rench]
 * @create date 2017-11-21 09:53:44
 * @modify date 2017-11-21 09:53:44
 * @desc [net-hiject]
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <netinet/ether.h>
#include "log.h"
#include "hijack.h"
#include "util.h"
#include "rpc.h"
#include "capture.h"
#include "policy.h"

#define HIJACK_LOG_FILE  "hjk.log"

#define MAX_PIPE_BUF_SIZE  4089

const char http_302_str[] = "http://www.lljjsy.com/";
const char version[] = "2.0.0";
const char build_time[] = __DATE__ " " __TIME__;

static u_char  program[] = "hjk";
static u_char  master_process[] = "master process";
static u_char  worker_process[] = "worker process";

pid_t   hjk_pid;

int            hjk_process_num;
int            hik_process_slot;
hjk_process_t  hjk_process;

void helper(void)
{
    printf("net-hijack version: %s built at %s" LINEFEED, version, build_time);
    printf("Usage: net-hijack [-?haioD]" LINEFEED 
            LINEFEED
            "Options:" LINEFEED 
            "  -?,-h            : this help" LINEFEED
            "  -a cpu id	    : use setaffinity" LINEFEED
            "  -i interface     : set capture interface" LINEFEED
            "  -o interface     : set inject interface" LINEFEED
            "  -D mac           : set inject mac address" LINEFEED
            "  -l address       : rpc listen address" LINEFEED
            "  -p port          : rpc listen port" LINEFEED
            "  -P http location : http 302 redirect location" LINEFEED);
}

void hjk_log_init(int debug)
{
    FILE *fp;

    fp = fopen(HIJACK_LOG_FILE, "w");
    if (!fp) {
        printf("failed create log file[%s], exit" LINEFEED, strerror(errno));
        exit(-1);
    }

    log_set_fp(fp);
    log_set_level(debug ? LOG_DEBUG : LOG_INFO);
    log_set_quiet(1);
}

int hjk_worker_process_pipe_msg(char *buf, int n)
{
    static const char sp = '\n';

    int   tn = n;
    char *start, *end;
    char  tmp[MAX_PIPE_BUF_SIZE];
    
    for (start = buf; (end = memchr(start, sp, n)) != NULL; start = end + 1) {
        if (end - start - 1 <= 0 || end - start - 1 >= MAX_PIPE_BUF_SIZE) {
            continue;
        }

        memcpy(tmp, start + 1, end - start - 1);
        *(tmp + (end - start - 1)) = 0;

        switch (*start - '0') {
            case uadd:
                log_info("process %d receive url[%s] add cmd", hjk_pid, tmp);
                policy_add_url(tmp);
                break;
            case udel:
                log_info("process %d receive url[%s] del cmd", hjk_pid, tmp);
                policy_del_url(tmp);
                break;
            case iadd:
                log_info("process %d receive ip[%s] add cmd", hjk_pid, tmp);
                policy_add_ip(tmp);
                break;
            case idel:
                log_info("process %d receive ip[%s] del cmd", hjk_pid, tmp);
                policy_del_ip(tmp);
                break;
            default:
                break;
        }
            
        tn = tn - (end - start + 1);
        if (tn <= 0) {
            return n;
        }
    }

    return start - buf;
}

void *hjk_worker_listen_pipe(void *arg)
{
    uintptr_t   fd = (uintptr_t)arg;

    int      parserd;
    ssize_t  n;
    char     buf[MAX_PIPE_BUF_SIZE];
    int      wpos = 0;

    while (1) {
        n = read(fd, buf + wpos, MAX_PIPE_BUF_SIZE - wpos);
        if (n <= 0) {
            log_fatal("worker process pipe broken[%s], exit", strerror(errno));
            exit(-1);
        }

        parserd = hjk_worker_process_pipe_msg(buf, n);
        if (parserd != n) {
            wpos = n - parserd;
            memmove(buf, buf + parserd, n - parserd);
        } else {
            wpos = 0;
        }
    }

    return NULL;
}

void hjk_worker_process_cycle(hjk_conf_t *conf)
{
    pthread_t  t_pipe;

    setproctitle((char *)program, (char *)worker_process);

    hjk_pid = getpid();

    log_info("worker process[%d] start to running...", hjk_pid);

    close(hjk_process.fd[1]);

    pthread_create(&t_pipe, NULL, hjk_worker_listen_pipe, (void *)(uintptr_t)hjk_process.fd[0]);
    pthread_detach(t_pipe);

    cap_service(conf);
}

pid_t hjk_spawn_process(hjk_conf_t *conf)
{
    pid_t pid;

    if (pipe(hjk_process.fd)) {
        goto failed;
    }

    pid = fork();

    switch (pid) {
        case -1: 
            goto failed;
        case 0: 
            hjk_worker_process_cycle(conf);
        default:
            break;
    }   
    
    return pid;

failed:
    log_error("failed spawn worker process[%s]", strerror(errno));
    exit(-1);
} 

void hjk_master_process_cycle(hjk_conf_t *conf)
{
    pid_t      pid;
    pthread_t  tid;

    setproctitle((char *)program, (char *)master_process);

    pid = hjk_spawn_process(conf);
        
    close(hjk_process.fd[0]);

    hjk_process.pid   = pid;

    pthread_create(&tid, NULL, rpc_service, conf);
    pthread_detach(tid);
}

int main(int argc, const char *argv[])
{
    int             opt;
    int             status;
    int             debug;
    pid_t           pid;
    hjk_conf_t      conf;

    struct ether_addr *e;

    debug = 0;

    bzero(&conf, sizeof(conf));

    while ((opt = getopt(argc, (char * const*)argv, "i:o:a:D:C:l:p:P:dh")) != -1) {
        switch (opt) {
            case 'i':
                sprintf(conf.iether, "netmap:%s", optarg);    
                break;
            case 'o':
                sprintf(conf.oether, "netmap:%s", optarg);
                break;
            case 'a':
                conf.affinity = atoi(optarg);
                break;
            case 'D':
                e = ether_aton(optarg);
                if (e == NULL) {
                    printf("invalid MAC address '%s'\n", optarg);
                    return 1;                    
                }
                bcopy(e, &conf.dst_mac, 6);
                break;
            case 'd':
                debug = 1;
                break;
            case 'C':
                conf.nmr = optarg;
                break;
            case 'l':
                conf.laddr = optarg;
                break;
            case 'p':
                conf.lport = atoi(optarg);
                break;
            case 'b':
                conf.burst = atoi(optarg);
                break;
            case 'P':
                conf.http_302_str = optarg;
                break;
            case 'h':
            case '?':
                helper();
                break;
            default:
                break;
        }
    }

    if (strlen(conf.iether) == 0 || strlen(conf.oether) == 0) {
        printf("capture or inject interface can't be null" LINEFEED);
        exit(0);
    }

    if (conf.laddr == NULL || conf.lport == 0) {
        printf("rpc service information can't be null" LINEFEED);
        exit(0);
    }

    if (conf.http_302_str == NULL) {
        conf.http_302_str = http_302_str;
    }

    hwaddr_mac(conf.oether, &conf.src_mac);

    hjk_log_init(debug);

    printf("program start..." LINEFEED);

    initproctitle(argc, (char **)argv);

    daemonize();

    setrlimit_core();

    hjk_master_process_cycle(&conf);

    while ((pid = waitpid(-1, &status, 0)) != -1) {
        log_error("worker process[%d] shutdown[%s]", pid, WIFEXITED(status) ? "exited" : "unexpected");
    }

    log_error("program unexpected exit");

    return 0;
}


