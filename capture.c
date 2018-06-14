#include "capture.h"
#include "log.h"
#include "http_parser.h"
#include "util.h"
#include "https.h"
#include "dns.h"
#include "gtpu.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
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

    char   *redis_addr;
    int     redis_port;
    time_t  redis_conn_time;

    struct nm_desc   *nm;
    struct cap_stats  ctr;

    redisContext *c;
} cap_worker_t;


static int http_headers_complete_cb(http_parser *parser);
static int http_header_field_cb(http_parser *parser, const char *buf, size_t len);
static int http_header_value_cb(http_parser *parser, const char *buf, size_t len);
static int http_url_cb(http_parser *parser, const char *buf, size_t len);

static int cap_process_udp(u_char *cp, size_t len,
                            struct ether_header *eth_hdr,
                            struct iphdr        *ip_hdr,
                            struct cap_stats    *stats,
                            cap_worker_t        *worker);

static int cap_process_tcp(u_char *cp, size_t len,
                            struct ether_header *eth_hdr,
                            struct iphdr        *ip_hdr,
                            struct cap_stats    *stats,
                            cap_worker_t        *worker);

static void cap_worker_connect_redis(cap_worker_t *worker);


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

static void cap_process_domain(const char *host, cap_worker_t *worker)
{
    redisReply *reply;

    if (worker->c == NULL || worker->c->err || host == NULL) {
        return;
    }

    reply = redisCommand(worker->c, "EXISTS %s", host);
    if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 0) {
        goto leave;
    }

    freeReplyObject(reply);

    reply = redisCommand(worker->c, "HSET %s crawed 0", host);

leave:
    if (reply != NULL) {
        freeReplyObject(reply);
    }

    if (worker->c == NULL || worker->c->err) {
        log_error("worker %d redis connection is down", worker->wid);
    }

    return;
}

static int cap_process_http_inject(u_char *http_data, size_t n,
                                        struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr,
                                        struct cap_stats    *stats,
                                        cap_worker_t        *worker)
{
    int          parserd;
    http_parser  parser;
    //char        *pos;

    cap_http_request_t   req;
/*
    if (http_data[0] != 'G' && http_data[0] != 'P') {
        return 0;
    }
*/
    bzero(&req, sizeof(cap_http_request_t));

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &req;
    parserd = http_parser_execute(&parser, &parser_settings, (char *)http_data, n);
    if (parserd != n && HTTP_PARSER_ERRNO(&parser) != HPE_CB_header_value) {
        goto ret;
    }

    stats->procs++;
    cap_process_domain(req.host, worker);

ret:
    if (req.host != NULL) {
        free(req.host);
    }

    if (req.url != NULL) {
        free(req.url);
    }

    return 0;
}

static int cap_process_https_inject(u_char *https_data, size_t n,
                                        struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr,
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

    cap_process_domain(host, worker);

    return 0;
}

static int cap_process_gtp_cap(u_char *data, size_t len, 
                                    struct ether_header *eth_hdr, 
                                    struct cap_stats    *stats,
                                    cap_worker_t        *worker)
{
    int             parsered;
    struct iphdr   *ip_hdr;
    gtpuHdr_t       gtp_hdr;

    parsered = gtpu_header_parse(data, len, &gtp_hdr);
    if (parsered == -1) {
        return 0;
    }

    len -= parsered;
    data += parsered;

    if (gtp_hdr.msg_type != 0xff || 
        len <= sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return 0;
    }

    ip_hdr = (struct iphdr *)data;
    if (ip_hdr->version != 4) {
        return 0; 
    }   

    data += (ip_hdr->ihl * 4);
    len -= (ip_hdr->ihl * 4);

    switch (ip_hdr->protocol) {
        case IPPROTO_TCP:
            return cap_process_tcp(data, len, eth_hdr, ip_hdr, stats, worker);
        case IPPROTO_UDP:
            return cap_process_udp(data, len, eth_hdr, ip_hdr, stats, worker);
        default:
            return 0;
    }

    return 0;
}

static int cap_process_dns_cap(u_char *data, size_t len,
                                   struct ether_header *eth_hdr,
                                   struct iphdr        *ip_hdr,
                                   struct udphdr       *udp_hdr,
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
            cap_process_domain(qs->name, worker);
            break;
        }
        qs = qs->next;
    }

    dns_message_free(&msg);

    return qs != NULL;
}

static int cap_process_tcp(u_char *cp, size_t len,
                           struct ether_header *eth_hdr,
                           struct iphdr        *ip_hdr,
                           struct cap_stats    *stats,
                           cap_worker_t        *worker)
{
    uint8_t              tcp_hl;
    struct tcphdr       *tcp_hdr;

    if (len <= sizeof(struct tcphdr)) return 0;

    tcp_hdr = (struct tcphdr *)cp;
    tcp_hl = tcp_hdr->doff * 4;

    cp = cp + tcp_hl;
    len = len - tcp_hl;

    if (len <= 0) {
        return 0;
    }

    switch (ntohs(tcp_hdr->dest)) {
        case CAP_HTTP_PORT:
            stats->http++;
            return cap_process_http_inject(cp, len, eth_hdr, ip_hdr, tcp_hdr, stats, worker);
        case CAP_HTTPS_PORT:
            stats->https++;
            return cap_process_https_inject(cp, len, eth_hdr, ip_hdr, tcp_hdr, stats, worker);
        default:
            break;
    }

    return 0;
}

static int cap_process_udp(u_char *cp, size_t len,
                            struct ether_header *eth_hdr,
                            struct iphdr        *ip_hdr,
                            struct cap_stats    *stats,
                            cap_worker_t        *worker)
{
    static int udp_header_size = 8;

    struct udphdr *udp_hdr;

    if (len <= sizeof(struct udphdr)) {
        return 0;
    }

    udp_hdr = (struct udphdr *)cp;

    cp += udp_header_size;
    len -= udp_header_size;

    if (ntohs(udp_hdr->len) != len + udp_header_size) {
        return 0;
    }

    switch (ntohs(udp_hdr->dest)) {
    case CAP_DNS_PORT:
        stats->dns++;
        return cap_process_dns_cap(cp, len, eth_hdr, ip_hdr, udp_hdr, stats, worker);
    case CAP_GTP_PORT:
        return cap_process_gtp_cap(cp, len, eth_hdr, stats, worker);
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

static int cap_process_packets_helper(u_char *data, int len, struct cap_stats *stats, cap_worker_t *worker)
{
    u_char              *cp;
    uint16_t             eth_t;
    struct ether_header *eth_hdr;
    struct iphdr        *ip_hdr;

    cp  =  data;

    eth_hdr = (struct ether_header *)cp;
    eth_t = ntohs(eth_hdr->ether_type);

	if(eth_t != 0x0800 && eth_t != 0x8100) {
        return 0;
    }

    cp = cp + ETHER_HDR_LEN;
    len = len - ETHER_HDR_LEN;

	if (eth_t == 0x8100) {
		cp = cp + 2;

		if (cp[0] != 0x88 && cp[1] != 0x64)
			return 0;
		
        cp = cp + 10;  

        len = len - 12;     
    }

    if (len <= sizeof(ip_hdr)) return 0;
    
	ip_hdr = (struct iphdr *) cp;
    if (ip_hdr->version != 4) {
        return 0; 
    }

    cp = cp + (ip_hdr->ihl * 4);
    len = len - (ip_hdr->ihl * 4);

    switch (ip_hdr->protocol) {
        case IPPROTO_TCP:
            return cap_process_tcp(cp, len, eth_hdr, ip_hdr, stats, worker);
        case IPPROTO_UDP:
            return cap_process_udp(cp, len, eth_hdr, ip_hdr, stats, worker);
        default:
            return 0;
    }

    return 0;
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

static void *cap_worker(void *arg)
{
    cap_worker_t *worker = (cap_worker_t *)arg;

    int i;
    int ret;

    struct netmap_if   *nifp;
    struct netmap_ring *rxring;

    struct cap_stats cur;

    struct pollfd pfd = {.fd = worker->nm->fd, .events = POLLIN};

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

    nifp = worker->nm->nifp;

    while (1) {
        if (worker->c == NULL || worker->c->err) {
            cap_worker_connect_redis(worker);
        }

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
        for (i = worker->nm->first_rx_ring; i <= worker->nm->last_rx_ring; i++) {
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

void cap_service(hjk_cycle_t *cycle)
{
    int             i;
    int             rings;

    struct nmreq    base_nmd;
    //struct nm_desc *inmd;

    char            ether_name[64];

    cap_worker_t   *workers;

    bzero(&base_nmd, sizeof(base_nmd));
    //parse_nmr_config(conf->nmr, &base_nmd);

    base_nmd.nr_flags |= NR_ACCEPT_VNET_HDR;

    snprintf(ether_name, sizeof(ether_name), "netmap:%s/R", cycle->iether);
    rings = cap_iether_rings(ether_name);

    log_info("found %d network adapter ring(s), spawn %d threads to running", rings, rings);

    workers = (cap_worker_t *)calloc(rings, sizeof(cap_worker_t));

    for (i = 0; i < rings; i++) {
        snprintf(ether_name, sizeof(ether_name), "netmap:%s-%d/R", cycle->iether, i);

        workers[i].nm = nm_open(ether_name, &base_nmd, 0, NULL);
        if (workers[i].nm == NULL) {
            log_error("failed to open %s: %s", ether_name, strerror(errno));
            exit(1);
        }

        workers[i].wid = i;
        workers[i].redis_addr = strdup(cycle->raddr);
        workers[i].redis_port = cycle->rport;
        workers[i].affinity = (cycle->affinity + i) % sysconf(_SC_NPROCESSORS_ONLN);;

        pthread_create(&workers[i].tid, NULL, cap_worker, &workers[i]);
        pthread_detach(workers[i].tid);
    }

    cap_log_status(workers, rings);
}
