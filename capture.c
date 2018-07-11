#include "capture.h"
#include "log.h"
#include "http_parser.h"
#include "util.h"
#include "https.h"
#include "dns.h"
#include "gtpu.h"
#include "ethertype.h"
#include "inject.h"
#include <luajit-2.0/lua.h>
#include <luajit-2.0/lualib.h>
#include <luajit-2.0/lauxlib.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <hiredis.h>

#define CAP_HTTP_PORT    80
#define CAP_HTTPS_PORT   443
#define CAP_DNS_PORT     53
#define CAP_GTP_PORT     2152

#define CAP_REDIS_CONNECT_INTERVAL  15

#define CAP_MAX_HOST_LEN  512

struct cap_stats {
	uint64_t pkts, bytes, events, drop, send, procs;
    uint64_t dns, http, https;
	uint64_t min_space;
	struct   timeval t;
};

typedef struct cap_http_request_s {
    int    hflag;
    int    hostLen;
    int    urlLen;
    char  *host;
    char  *url;
} cap_http_request_t;

typedef struct cap_worker_s {
    int        wid;
    pthread_t  tid;

    int    affinity;
    int    done;

    lua_State *L;

    struct nm_desc   *inm;
    struct nm_desc   *onm;

    struct cap_stats  ctr;
} cap_worker_t;

typedef struct cap_gtp_encap_hdr_s {
    struct iphdr    *ip_hdr;
    struct udphdr   *udp_hdr;
} cap_gtp_encap_hdr_t;

typedef struct cap_pkt_s {
    struct ether_header *ether_hdr;
    struct iphdr        *ip_hdr;
    struct tcphdr       *tcp_hdr;
    struct udphdr       *udp_hdr;

    gtpuHdr_t *gtp_hdr;

    cap_gtp_encap_hdr_t gtp_encap_hdr;
    
    const char *domain;
    const char *uri;
} cap_pkt_t;


static int http_headers_complete_cb(http_parser *parser);
static int http_header_field_cb(http_parser *parser, const char *buf, size_t len);
static int http_header_value_cb(http_parser *parser, const char *buf, size_t len);
static int http_url_cb(http_parser *parser, const char *buf, size_t len);

static int cap_process_udp(cap_pkt_t *pkt, u_char *cp, size_t len,
                            struct cap_stats    *stats,
                            cap_worker_t        *worker);

static int cap_process_tcp(cap_pkt_t *pkt, u_char *cp, size_t len,
                            struct cap_stats    *stats,
                            cap_worker_t        *worker);

//static void cap_worker_connect_redis(cap_worker_t *worker);

#define PKT_SRC_ADDR_FIELD      "src_addr"
#define PKT_DST_ADDR_FIELD      "dst_addr"
#define PKT_SRC_PORT_FIELD      "src_port"
#define PKT_DST_PORT_FIELD      "dst_port"
#define PKT_TEID_FIELD          "teid"
#define PKT_GTP_DST_FIELD       "gtp_dst_addr"
#define PKT_DOMAIN_FIELD        "domain"
#define PKT_URI_FIELD           "uri"


static int cap_lua_record(lua_State *L);
static int cap_lua_inject(lua_State *L);
/*
typedef struct cap_lua_log_s {
    char      *src_addr;
    char      *dst_addr;
    char      *gtp_dst_addr;
    char      *domain;
    char      *uri;
    uint32_t   teid;
    int        src_port;
    int        dst_port;
} cap_lua_log_t;
*/
static const struct luaL_reg hjk_lib[] = {
    {"record", cap_lua_record},
    {"inject", cap_lua_inject},
    {NULL, NULL}  /* sentinel */
};
/*
static int cap_lua_log_info_get(lua_State *L, cap_lua_log_t *cap_log)
{
    lua_getfield(L, -1, PKT_TEID_FIELD);
    if (lua_isnumber(L, -1)) {
        cap_log->teid = lua_tonumber(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, PKT_GTP_DST_FIELD);
    if (lua_isstring(L, -1)) {
        cap_log->gtp_dst_addr = strdup(lua_tostring(L, -1));
    }
    lua_pop(L, 1);    

    lua_getfield(L, -1, PKT_SRC_ADDR_FIELD);
    if (lua_isstring(L, -1)) {
        cap_log->src_addr = strdup(lua_tostring(L, -1));
    }
    lua_pop(L, 1);    

    lua_getfield(L, -1, PKT_DST_ADDR_FIELD);
    if (lua_isstring(L, -1)) {
        cap_log->dst_addr = strdup(lua_tostring(L, -1));
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, PKT_DOMAIN_FIELD);
    if (lua_isstring(L, -1)) {
        cap_log->domain = strdup(lua_tostring(L, -1));
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, PKT_URI_FIELD);
    if (lua_isstring(L, -1)) {
        cap_log->uri = strdup(lua_tostring(L, -1));
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, PKT_SRC_PORT_FIELD);
    if (lua_isnumber(L, -1)) {
        cap_log->src_port = lua_tonumber(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, PKT_DST_PORT_FIELD);
    if (lua_isnumber(L, -1)) {
        cap_log->dst_port = lua_tonumber(L, -1);
    }
    lua_pop(L, 1);    

    return 0;
}

static int cap_lua_log_info_free(cap_lua_log_t *cap_log)
{
    if (cap_log->src_addr) {
        free(cap_log->src_addr);
    }

    if (cap_log->dst_addr) {
        free(cap_log->dst_addr);
    }

    if (cap_log->domain) {
        free(cap_log->domain);
    }

    if (cap_log->uri) {
        free(cap_log->uri);
    }

    if (cap_log->gtp_dst_addr) {
        free(cap->log->gtp_dst_addr);
    }

    return 0;
}
*/
static int cap_lua_record(lua_State *L)
{
/*    
    cap_lua_log_t cap_log;

    bzero(&cap_log, sizeof(cap_lua_log_t));

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting exactly 1 arguments");
    }

    if (!lua_istable(L, 1)) {
        return luaL_error(L, "expecting lua table as arguments");
    }

    cap_lua_log_info_get(L, &cap_log);
*/
    char   src_addr_buf[32] = {0};
    char   dst_addr_buf[32] = {0};
    char   gtp_dest_buf[32] = {0};

    int    src_port = 0, dst_port = 0;
    struct in_addr   in;

    lua_getglobal(L, "pkt");
    cap_pkt_t *pkt = lua_touserdata(L, -1);

    in.s_addr = pkt->ip_hdr->saddr;
    snprintf(src_addr_buf, sizeof(src_addr_buf), "%s", inet_ntoa(in));

    in.s_addr = pkt->ip_hdr->daddr;
    snprintf(dst_addr_buf, sizeof(dst_addr_buf), "%s", inet_ntoa(in));

    if (pkt->gtp_encap_hdr.ip_hdr != NULL) {
        in.s_addr = pkt->gtp_encap_hdr.ip_hdr->daddr;
        snprintf(gtp_dest_buf, sizeof(gtp_dest_buf), "%s", inet_ntoa(in));
    }

    if (pkt->tcp_hdr != NULL) {
        src_port = ntohs(pkt->tcp_hdr->source);
        dst_port = ntohs(pkt->tcp_hdr->dest);
    } else if (pkt->udp_hdr != NULL) {
        src_port = ntohs(pkt->udp_hdr->source);;
        dst_port = ntohs(pkt->udp_hdr->dest);;
    }


    log_info("pkt: [src_addr: %s, dst_addr: %s, src_port: %d, dst_port %d, domain: %s tunnel: %08x-%s]",
                src_addr_buf, dst_addr_buf, src_port, dst_port, pkt->domain, pkt->gtp_hdr->teid, gtp_dest_buf);

    //cap_lua_log_info_free(&cap_log);

    return 0;
}

static int cap_lua_inject(lua_State *L)
{
/*
    uint16_t vlanID;

    vlanID = 0;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting exactly 1 arguments");
    }

    if (!lua_istable(L, 1)) {
        return luaL_error(L, "expecting lua table as arguments");
    }    
*/
    static u_char inject_data[5] = {'h', 'e', 'l', 'l', 'o'};

    cap_pkt_t    *pkt; 
    cap_worker_t *worker;
    struct ether_addr mac, *res;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting exactly 1 arguments");
    }

    if (!lua_isstring(L, 1)) {
        return luaL_error(L, "expecting lua table as arguments");
    }

    res = ether_aton_r(lua_tostring(L, -1), &mac);
    if (res == NULL) {
        return luaL_error(L, "illegal mac address as arguments");
    }

    lua_getglobal(L, "pkt");
    pkt = lua_touserdata(L, -1);    

    lua_getglobal(L, "worker");
    worker = lua_touserdata(L, -1);

    if (pkt->tcp_hdr) {
        inject_tcp_packet(worker->onm, pkt->ip_hdr, pkt->tcp_hdr, mac.ether_addr_octet, 0, inject_data, sizeof(inject_data));
    } else if (pkt->udp_hdr) {
        inject_udp_packet(worker->onm, pkt->ip_hdr, pkt->udp_hdr, mac.ether_addr_octet, 0, inject_data, sizeof(inject_data));
    }


    return 0;
}


static http_parser_settings parser_settings = {
    .on_headers_complete = http_headers_complete_cb
   ,.on_header_field     = http_header_field_cb
   ,.on_header_value     = http_header_value_cb
   ,.on_url              = http_url_cb
};

static int http_headers_complete_cb(http_parser *parser)
{
    return -1;
}

static int http_header_field_cb(http_parser *parser, const char *buf, size_t len)
{
    cap_http_request_t *req = (cap_http_request_t *)parser->data;

    if (len == 4 && strncasecmp(buf, "host", 4) == 0) {
        req->hflag = 1;
    } else {
        req->hflag = 0;
    }

    return 0;
}

static int http_header_value_cb(http_parser *parser, const char *buf, size_t len)
{
    cap_http_request_t *req = (cap_http_request_t *)parser->data;

    if (req->hflag == 0) {
        return 0;
    }

    req->host = (char *)malloc(len + 1);
    memcpy(req->host, buf, len);

    req->host[len] = 0;
    req->hostLen = len;

    return -1;
}

static int http_url_cb(http_parser *parser, const char *buf, size_t len)
{
    cap_http_request_t *req = (cap_http_request_t *)parser->data;

    req->url = (char *)malloc(len + 1);
    memcpy(req->url, buf, len);

    req->url[len] = 0;
    req->urlLen = len;

    return 0;
}

#if 0
static int cap_domain_has_processed(const char *host, cap_worker_t *worker)
{
    int         ret = 0;
    redisReply *reply;

    reply = redisCommand(worker->c, "SISMEMBER domain_set %s", host);
    if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 0) {
        ret = 1;
        goto done;
    }

    freeReplyObject(reply);

    reply = redisCommand(worker->c, "SISMEMBER green_set %s", host);
    if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 0) {
        ret = 1;
        goto done;
    }    

    freeReplyObject(reply);

    reply = redisCommand(worker->c, "SISMEMBER hdd_set %s", host);
    if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 0) {
        ret = 1;
    }

done:
    if (reply != NULL) {
        freeReplyObject(reply);
    }    

    return ret;
}
#endif

#if 0
static void cap_process_domain(const char *host, cap_worker_t *worker)
{
    redisReply *reply;

    if (worker->c == NULL || worker->c->err || host == NULL) {
        return;
    }

    if (cap_domain_has_processed(host, worker)) {
        return;
    }

    reply = redisCommand(worker->c, "SADD domain_set %s", host);

    if (reply != NULL) {
        freeReplyObject(reply);
    }

    if (worker->c == NULL || worker->c->err) {
        log_error("worker %d redis connection is down", worker->wid);
    }

    return;
}
#endif

static void l_pushtablestring(lua_State* L , char* key , char* value) 
{
    lua_pushstring(L, key);
    lua_pushstring(L, value);
    lua_settable(L, -3);
}

static void l_pushtablenumber(lua_State *L, char *key, int number)
{
    lua_pushstring(L, key);
    lua_pushnumber(L, number);
    lua_settable(L, -3);
}

static int cap_process_lua_script(lua_State *L, cap_pkt_t *pkt)
{
    struct in_addr  in;

    lua_settop(L, 0);

    lua_getglobal(L, "capture");

    lua_newtable(L);

    in.s_addr = pkt->gtp_encap_hdr.ip_hdr->daddr;
    l_pushtablestring(L, PKT_GTP_DST_FIELD, inet_ntoa(in));

    l_pushtablenumber(L, PKT_TEID_FIELD, pkt->gtp_hdr->teid);

    in.s_addr = pkt->ip_hdr->saddr;
    l_pushtablestring(L, PKT_SRC_ADDR_FIELD, inet_ntoa(in));

    in.s_addr = pkt->ip_hdr->daddr;
    l_pushtablestring(L, PKT_DST_ADDR_FIELD, inet_ntoa(in));

    if (pkt->tcp_hdr != NULL) {
        l_pushtablenumber(L, PKT_SRC_PORT_FIELD, ntohs(pkt->tcp_hdr->source));
        l_pushtablenumber(L, PKT_DST_PORT_FIELD, ntohs(pkt->tcp_hdr->dest));
    } else {
        l_pushtablenumber(L, PKT_SRC_PORT_FIELD, ntohs(pkt->udp_hdr->source));
        l_pushtablenumber(L, PKT_DST_PORT_FIELD, ntohs(pkt->udp_hdr->dest));
    }

    if (pkt->domain != NULL) {
        l_pushtablestring(L, PKT_DOMAIN_FIELD, (char *)pkt->domain);
    }

    if (pkt->uri != NULL) {
        l_pushtablestring(L, PKT_URI_FIELD, (char *)pkt->uri);
    }

    if (lua_pcall(L, 1, 0, 0)) {
        log_error("failed execute lua capture function: %s", lua_tostring(L, -1));
    }

    return 0;
}

static int cap_process_http_inject(cap_pkt_t *pkt, u_char *http_data, size_t n,
                                        struct cap_stats    *stats,
                                        cap_worker_t        *worker)
{
    int          parserd;
    http_parser  parser;

    cap_http_request_t   req;

    if (http_data[0] != 'G' && http_data[0] != 'P') {
        return 0;
    }

    bzero(&req, sizeof(cap_http_request_t));

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &req;
    parserd = http_parser_execute(&parser, &parser_settings, (char *)http_data, n);
    if (parserd != n && HTTP_PARSER_ERRNO(&parser) != HPE_CB_header_value) {
        goto ret;
    }

    stats->procs++;
    //cap_process_domain(req.host, worker);

    pkt->domain = req.host;
    pkt->uri = req.url;

    cap_process_lua_script(worker->L, pkt);

ret:
    if (req.host != NULL) {
        free(req.host);
    }

    if (req.url != NULL) {
        free(req.url);
    }

    return 0;
}

static int cap_process_https_inject(cap_pkt_t *pkt, u_char *https_data, size_t n,
                                        struct cap_stats    *stats,
                                        cap_worker_t        *worker)
{
    int   ret;
    char  host[CAP_MAX_HOST_LEN];

    ret = parse_tls_header((const char *)https_data, n, host, CAP_MAX_HOST_LEN);
    if (ret <= 0) {
        return 0;
    }

    stats->procs++;

    //cap_process_domain(host, worker);
    pkt->domain = host;

    cap_process_lua_script(worker->L, pkt);

    return 0;
}

static int cap_process_gtp_cap(cap_pkt_t *pkt, u_char *data, size_t len,
                                    struct cap_stats    *stats,
                                    cap_worker_t        *worker)
{
    int             parsered;
    //struct iphdr   *ip_hdr;
    gtpuHdr_t       gtp_hdr;

    parsered = gtpu_header_parse(data, len, &gtp_hdr);
    if (parsered == -1) {
        return 0;
    }

    pkt->gtp_hdr = &gtp_hdr;

    len -= parsered;
    data += parsered;

    if (gtp_hdr.msg_type != 0xff || 
        len <= sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return 0;
    }

    pkt->gtp_encap_hdr.ip_hdr = pkt->ip_hdr;
    pkt->gtp_encap_hdr.udp_hdr = pkt->udp_hdr;

    pkt->ip_hdr = NULL;
    pkt->udp_hdr = NULL;
    pkt->tcp_hdr = NULL;

    pkt->ip_hdr = (struct iphdr *)data;
    if (pkt->ip_hdr->version != IPVERSION) {
        return 0; 
    }   

    data += (pkt->ip_hdr->ihl * 4);
    len -= (pkt->ip_hdr->ihl * 4);

    switch (pkt->ip_hdr->protocol) {
        case IPPROTO_TCP:
            return cap_process_tcp(pkt, data, len, stats, worker);
        case IPPROTO_UDP:
            return cap_process_udp(pkt, data, len, stats, worker);
        default:
            return 0;
    }

    return 0;
}

static int cap_process_dns_cap(cap_pkt_t *pkt, u_char *data, size_t len,
                                   struct cap_stats    *stats,
                                   cap_worker_t        *worker)
{
    dns_message_t        msg;
    struct dns_question *qs;

    memset(&msg, 0x00, sizeof(dns_message_t));

    if (dns_message_parse(data, len, &msg)) {
        return 0;
    }

    stats->procs++;

    qs = msg.questions;
    while (qs != NULL) {
        if (qs->type == dns_rr_a) {
            cap_process_lua_script(worker->L, pkt);
            break;
        }
        qs = qs->next;
    }

    dns_message_free(&msg);

    return qs != NULL;
}

static int cap_process_tcp(cap_pkt_t *pkt, u_char *cp, size_t len, 
                            struct cap_stats    *stats,
                            cap_worker_t        *worker)
{
    uint8_t              tcp_hl;

    if (len <= sizeof(struct tcphdr)) return 0;

    pkt->tcp_hdr = (struct tcphdr *)cp;
    tcp_hl = pkt->tcp_hdr->doff * 4;

    cp = cp + tcp_hl;
    len = len - tcp_hl;

    if (len <= 0) {
        return 0;
    }

    switch (ntohs(pkt->tcp_hdr->dest)) {
        case CAP_HTTP_PORT:
            stats->http++;
            return cap_process_http_inject(pkt, cp, len, stats, worker);
        case CAP_HTTPS_PORT:
            stats->https++;
            return cap_process_https_inject(pkt, cp, len, stats, worker);
        default:
            break;
    }

    return 0;
}

static int cap_process_udp(cap_pkt_t *pkt, u_char *cp, size_t len,
                            struct cap_stats    *stats,
                            cap_worker_t        *worker)
{
    static int udp_header_size = 8;

    if (len <= sizeof(struct udphdr)) {
        return 0;
    }

    pkt->udp_hdr = (struct udphdr *)cp;

    cp += udp_header_size;
    len -= udp_header_size;

    if (ntohs(pkt->udp_hdr->len) != len + udp_header_size) {
        return 0;
    }

    switch (ntohs(pkt->udp_hdr->dest)) {
    case CAP_DNS_PORT:
        stats->dns++;
        return cap_process_dns_cap(pkt, cp, len, stats, worker);
    case CAP_GTP_PORT:
        return cap_process_gtp_cap(pkt, cp, len, stats, worker);
    default:
        return 0;
    }

    return 0;
}

static const char *
norm2(char *buf, double val, char *fmt)
{
	char *units[] = { "", "K", "M", "G", "T" };
	u_int i;

	for (i = 0; val >=1000 && i < sizeof(units)/sizeof(char *) - 1; i++)
		val /= 1000;
	sprintf(buf, fmt, val, units[i]);
	return buf;
}

static __inline const char *
norm(char *buf, double val)
{
	return norm2(buf, val, "%.3f %s");
}

static uint64_t cap_wait_for_next_report(struct timeval *prev, struct timeval *cur)
{
    static int interval = 10000;

	struct timeval delta;

	delta.tv_sec = interval / 1000;
	delta.tv_usec = (interval % 1000) * 1000;
	if (select(0, NULL, NULL, NULL, &delta) < 0 && errno != EINTR) {
		perror("select");
		abort();
	}
	gettimeofday(cur, NULL);
	timersub(cur, prev, &delta);
	return delta.tv_sec * 1000000 + delta.tv_usec;
}

#if 0
static int parse_nmr_config(const char *conf, struct nmreq *nmr) {
    char *w, *tok;
    int i, v;

    nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
    nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
    if (conf == NULL || !*conf)
        return 0;
    w = strdup(conf);
    for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
        v = atoi(tok);
        switch (i) {
        case 0:
            nmr->nr_tx_slots = nmr->nr_rx_slots = v;
            break;
        case 1:
            nmr->nr_rx_slots = v;
            break;
        case 2:
            nmr->nr_tx_rings = nmr->nr_rx_rings = v;
            break;
        case 3:
            nmr->nr_rx_rings = v;
            break;
        default:
            log_error("ignored config: %s", tok);
            break;
        }
    }
    log_info("txr %d txd %d rxr %d rxd %d", nmr->nr_tx_rings, nmr->nr_tx_slots,
      nmr->nr_rx_rings, nmr->nr_rx_slots);
    free(w);
    return (nmr->nr_tx_rings || nmr->nr_tx_slots || nmr->nr_rx_rings ||
            nmr->nr_rx_slots)
               ? NM_OPEN_RING_CFG
               : 0;
}
#endif

static int cap_ether_header_parser(cap_pkt_t *pkt, u_char *data, int len)
{
    int                  parsered;
    uint16_t             eth;
    //struct ether_header *eth_hdr;
    ether_vlan_hdr_t    *vlan_hdr;

    parsered = 0;

    pkt->ether_hdr = (struct ether_header *)data;
    eth = ntohs(pkt->ether_hdr->ether_type);

    if (eth != ETHERTYPE_IP && eth != ETHERTYPE_8021Q) {
        return -1;
    }

    parsered += ETHER_HDR_LEN;

    if (eth == ETHERTYPE_8021Q) {
        parsered += ETHERTYPE_VLAN_LEN;

        vlan_hdr = (ether_vlan_hdr_t *)(data + ETHER_HDR_LEN);

        if (ntohs(vlan_hdr->eth) != ETHERTYPE_IP) {
            return -1;
        }
    }

    return parsered;
}

static int cap_ip_header_parser(cap_pkt_t *pkt, u_char *data, int len)
{
    pkt->ip_hdr = (struct iphdr *)data;
    if (pkt->ip_hdr->version != IPVERSION) {
        return -1;
    }

    return pkt->ip_hdr->ihl * 4;
}

static int cap_process_packets_helper(u_char *data, int len, struct cap_stats *stats, cap_worker_t *worker)
{
    int                  ret, parsered;
    u_char              *cp;
    cap_pkt_t            pkt;

    bzero(&pkt, sizeof(cap_pkt_t));

    cp = data;
    parsered = 0;

    lua_pushlightuserdata(worker->L, &pkt);
    lua_setglobal(worker->L, "pkt");

    ret = cap_ether_header_parser(&pkt, cp, len);
    if (ret < 0 || len - ret <= sizeof(struct iphdr)) {
        return 0;
    }
    parsered += ret;

    ret = cap_ip_header_parser(&pkt, cp + parsered, len - parsered);
    if (ret < 0 || len - parsered - ret <= 0) {
        return 0;
    }
    parsered += ret;

    switch (pkt.ip_hdr->protocol) {
        case IPPROTO_TCP:
            ret = cap_process_tcp(&pkt, cp + parsered, len - parsered, stats, worker);
            break;
        case IPPROTO_UDP:
            ret = cap_process_udp(&pkt, cp + parsered, len - parsered, stats, worker);
            break;
        default:
            ret = 0;
            break;
    }

    lua_pushnil(worker->L);
    lua_setglobal(worker->L, "pkt");

    return ret;
}

static int cap_process_packets(struct netmap_ring *ring, struct cap_stats *stats, cap_worker_t *worker)
{
    int      cur, rx, n, s;

    cur = ring->cur;
    n = nm_ring_space(ring);
    
    for (rx = 0; rx < n; rx++) {
        struct netmap_slot *slot = &ring->slot[cur];
        char *p = NETMAP_BUF(ring, slot->buf_idx);

        stats->bytes += slot->len;

        //dump_payload(p, slot->len, ring, cur);
        s = cap_process_packets_helper((u_char *)p, slot->len, stats, worker);
        if (s > 0) {
            stats->send += s;
        }

        cur = nm_ring_next(ring, cur);
    }
    ring->head = ring->cur = cur;

    stats->pkts += rx;
    
    return (rx);
}

#if 0
static void cap_worker_connect_redis(cap_worker_t *worker)
{
    time_t  now = time(NULL);

    if (now - worker->redis_conn_time < CAP_REDIS_CONNECT_INTERVAL) {
        return;
    }

    worker->redis_conn_time = now;

    if (worker->c) {
        redisFree(worker->c);
        worker->c = NULL;
    }

    redisContext *c = redisConnect(worker->redis_addr, worker->redis_port);
    if (c == NULL || c->err) {
        if (c) {
            log_error("worker %d failed connect redis: %s", worker->wid, c->errstr);
            redisFree(c);
        } else {
            //unexpected
        }

        return;
    }

    log_info("worker %d connect redis successful", worker->wid);

    worker->c = c;

    return;
}
#endif

static void *cap_worker(void *arg)
{
    cap_worker_t *worker = (cap_worker_t *)arg;

    int i;
    int ret;

    struct netmap_if   *nifp;
    struct netmap_ring *rxring;

    struct cap_stats cur;

    struct pollfd pfd = {.fd = worker->inm->fd, .events = POLLIN};

    cur.pkts = cur.bytes = cur.events = cur.drop = cur.min_space = cur.send = 0;
    cur.http = cur.https = cur.dns = 0;
    cur.t.tv_usec = cur.t.tv_sec = 0; //  unused, just silence the compiler    

    setaffinity(worker->tid, worker->affinity);

    log_info("thread %d start running, bind cpu id %d", worker->wid, worker->affinity);

    for (;;) {
        i = poll(&pfd, 1, 1000);
        if (i > 0 && !(pfd.revents & POLLERR))
            break;
        if (i < 0) {
            log_error("netmap poll() error: %s", strerror(errno));
            goto done;
        }
        if (pfd.revents & POLLERR) {
            log_error("netmap fd error");
            goto done;
        }

        log_info("waiting for initial packets, poll returns %d %d", i,
           pfd.revents);
    }

    nifp = worker->inm->nifp;

    while (1) {
        #if 0
        if (worker->c == NULL || worker->c->err) {
            cap_worker_connect_redis(worker);
        }
        #endif

        ret = poll(&pfd, 1, 1 * 1000);
        
        if (ret == 0) {
            continue;
        }

        if (ret == -1 ||
            pfd.revents & POLLERR) {
            log_error("netmap poll error: %s", strerror(errno));
            goto done;
        }

        uint64_t cur_space = 0;
        for (i = worker->inm->first_rx_ring; i <= worker->inm->last_rx_ring; i++) {
            int m;

            rxring = NETMAP_RXRING(nifp, i);
            m = rxring->head + rxring->num_slots - rxring->tail;
            if (m >= (int)rxring->num_slots)
                m -= rxring->num_slots;

            cur_space += m;
            if (nm_ring_empty(rxring))
                continue;

            m = cap_process_packets(rxring, &cur, worker);
            if (m > 0)
                cur.events++;
        }

        cur.min_space = worker->ctr.min_space;
        if (cur_space < cur.min_space)
            cur.min_space = cur_space;
        worker->ctr = cur;
    }

done:
    worker->done = 1;
    return NULL;
}

static void cap_log_status(cap_worker_t *workers, int nring)
{
    int    i;
    struct cap_stats prev, cur;

    prev.pkts = prev.bytes = prev.events = prev.send = 0;
    prev.http = prev.https = prev.dns = 0;
    gettimeofday(&prev.t, NULL);

    for (;;) {
        char b1[40], b2[40], b3[40], b4[70], b5[40], b6[40], b7[40];
        uint64_t pps, usec;
        struct cap_stats x;
        double abs;

        usec = cap_wait_for_next_report(&prev.t, &cur.t);

        cur.pkts = cur.bytes = cur.events = cur.send = 0;
        cur.http = cur.https = cur.dns = 0;
        cur.min_space = 0;
        if (usec < 10000) /* too short to be meaningful */
            continue;
        /* accumulate counts for all threads */

        for (i = 0; i < nring; i++) {
            cur.pkts += workers[i].ctr.pkts;
            cur.bytes += workers[i].ctr.bytes;
            cur.events += workers[i].ctr.events;
            cur.send += workers[i].ctr.send;
            cur.min_space += workers[i].ctr.min_space;
            cur.http += workers[i].ctr.http;
            cur.https += workers[i].ctr.https;
            cur.dns += workers[i].ctr.dns;

            workers[i].ctr.min_space = 99999;
        }

        x.pkts = cur.pkts - prev.pkts;
        x.bytes = cur.bytes - prev.bytes;
        x.events = cur.events - prev.events;
        x.send = cur.send - prev.send;
        x.http = cur.http - prev.http;
        x.https = cur.https - prev.https;
        x.dns = cur.dns - prev.dns;

        pps = (x.pkts * 1000000 + usec / 2) / usec;
        abs = (x.events > 0) ? (x.pkts / (double)x.events) : 0;

        strcpy(b4, "");

        log_info("%spps %s(%spkts %shttp %shttps %sdns %sbps in %llu usec) %.2f avg_batch %d min_space",
          norm(b1, pps), b4, norm(b2, (double)x.pkts), norm(b5, (double)x.http),
          norm(b6, (double)x.https), norm(b7, (double)x.dns), norm(b3, (double)x.bytes * 8),
          (unsigned long long)usec, abs, (int)cur.min_space);
        prev = cur;
    }    
}

static int cap_iether_rings(const char *ether_name)
{
    int result;

    struct nm_desc     *nmd;
    struct netmap_if   *nifp;

    nmd = nm_open(ether_name, NULL, 0, NULL);
    if (nmd == NULL) {
        log_error("failed to open %s: %s", ether_name, strerror(errno));
        exit(1);
    }

    nifp = nmd->nifp;  
    result = nifp->ni_rx_rings;

    nm_close(nmd);

    return result;    
}

static lua_State *cap_script_create(const char *script)
{
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    luaL_openlib(L, "hjk", hjk_lib, 0);

    if (!script || luaL_dofile(L, script)) {
        log_error("failed create lua environment: %s", lua_tostring(L, -1));
        lua_close(L);
        exit(-1);
    }

    return L;
}

void cap_service(hjk_cycle_t *cycle)
{
    int             i;
    int             rings;

    struct nmreq    base_nmd;

    char            iether_name[64];
    char            oether_name[64];

    cap_worker_t   *workers;

    bzero(&base_nmd, sizeof(base_nmd));

    base_nmd.nr_flags |= NR_ACCEPT_VNET_HDR;

    snprintf(iether_name, sizeof(iether_name), "netmap:%s/R", cycle->iether);
    rings = cap_iether_rings(iether_name);

    log_info("found %d network adapter ring(s), spawn %d threads to running", rings, rings);

    workers = (cap_worker_t *)calloc(rings, sizeof(cap_worker_t));

    for (i = 0; i < rings; i++) {
        snprintf(iether_name, sizeof(iether_name), "netmap:%s-%d/R", cycle->iether, i);
        snprintf(oether_name, sizeof(oether_name), "netmap:%s-%d/T", cycle->oether, i);

        workers[i].inm = nm_open(iether_name, &base_nmd, 0, NULL);
        if (workers[i].inm == NULL) {
            log_error("failed to open %s: %s", iether_name, strerror(errno));
            exit(1);
        }

        workers[i].onm = nm_open(oether_name, NULL, 0, NULL);
        if (workers[i].onm == NULL) {
            log_error("failed to open %s: %s", oether_name, strerror(errno));
            exit(1);
        }

        workers[i].L = cap_script_create(cycle->script);

        lua_pushlightuserdata(workers[i].L, &workers[i]);
        lua_setglobal(workers[i].L, "worker");

        workers[i].wid = i;
        //workers[i].redis_addr = strdup(cycle->raddr);
        //workers[i].redis_port = cycle->rport;
        workers[i].affinity = (cycle->affinity + i) % sysconf(_SC_NPROCESSORS_ONLN);;

        pthread_create(&workers[i].tid, NULL, cap_worker, &workers[i]);
        pthread_detach(workers[i].tid);
    }

    cap_log_status(workers, rings);
}
