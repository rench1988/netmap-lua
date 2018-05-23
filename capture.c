#include "capture.h"
#include "lkf_queue.h"
#include "policy.h"
#include "log.h"
#include "http_parser.h"
#include "util.h"
#include "https.h"
#include "inject.h"
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
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#define CAP_HTTP_PORT    80
#define CAP_HTTPS_PORT   443
#define CAP_DNS_PORT     53
#define CAP_GTP_PORT     2152

#define MIN_BURST_SIZE  512

#define MAX_PACKET_LEN  65535

#define MAX_PACKET_STATUE  1000000
#define MAX_HOST_LEN   256

static const char http_302_str[] = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n"
                                "Cache-Control:no-store, no-cache\r\nExpires: Sat, 18 Jul 1988 05:00:00\r\n"
                                "Pragma: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nLocation: ";

char pushaddr[MAX_URL_LEN];

extern int  hik_process_slot;

extern pid_t   hjk_pid;

struct cap_ctrs {
	uint64_t pkts, bytes, events, drop, send;
	uint64_t min_space;
	struct   timeval t;
};

typedef struct {
    int  hflag;
    char host[MAX_HOST_LEN];
    char url[MAX_URL_LEN];
} cap_url_t;

typedef struct cap_worker_s {
    pthread_t  tid;

    int    affinity;
    int    burst;
    int    done;
    struct nm_desc *inm;
    struct nm_desc *onm;

    struct cap_ctrs ctr;

    pkt_inject_t injector;
} cap_worker_t;


static int cap_on_headers_complete(http_parser *parser);
static int cap_header_field_cb(http_parser *parser, const char *buf, size_t len);
static int cap_header_value_cb(http_parser *parser, const char *buf, size_t len);
static int cap_url_cb(http_parser *parser, const char *buf, size_t len);

static int cap_process_udp(u_char *cp, size_t len,
                            struct ether_header *eth_hdr,
                            struct iphdr        *ip_hdr,
                            pkt_inject_t        *injector);

static int cap_process_tcp(u_char *cp, size_t len,
                            struct ether_header *eth_hdr,
                            struct iphdr        *ip_hdr,
                            pkt_inject_t        *injector);

static int cap_inject_app_hello(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
                               struct tcphdr *tcp_hdr, pkt_inject_t  *injector);

static int cap_inject_app_302(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
                           struct tcphdr *tcp_hdr, cap_url_t *url, pkt_inject_t *injector);

static int cap_inject_dns(struct iphdr        *ip_hdr,
                           struct udphdr       *udp_hdr,
                           dns_message_t       *msg,
                           struct dns_question *qs,
                           pkt_inject_t        *injector);


static http_parser_settings parser_settings = {
    .on_headers_complete = cap_on_headers_complete
   ,.on_header_field     = cap_header_field_cb
   ,.on_header_value     = cap_header_value_cb
   ,.on_url              = cap_url_cb
};

static int cap_on_headers_complete(http_parser *parser)
{
    return -1;
}

static int cap_header_field_cb(http_parser *parser, const char *buf, size_t len)
{
    cap_url_t *url = (cap_url_t *)parser->data;

    if (len == 4 && strncasecmp(buf, "host", 4) == 0) {
        url->hflag = 1;
    } else {
        url->hflag = 0;
    }

    return 0;
}

static int cap_header_value_cb(http_parser *parser, const char *buf, size_t len)
{
    cap_url_t *url = (cap_url_t *)parser->data;

    if (url->hflag == 0) {
        return 0;
    }

    if (len >= MAX_HOST_LEN) {
        return 1;
    }

    memcpy(url->host, buf, len);

    return -1;
}

static int cap_url_cb(http_parser *parser, const char *buf, size_t len)
{
    cap_url_t *url = (cap_url_t *)parser->data;

    if (len >= MAX_URL_LEN) {
        return -1;
    }

    memcpy(url->url, buf, len);

    return 0;
}

static int cap_process_http_inject(u_char *http_data, size_t n,
                                        struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr,
                                        pkt_inject_t        *injector)
{
    int         parserd;
    http_parser parser;
    char       *pos;
    char        tmp[MAX_URL_LEN];
    cap_url_t   url;

    if (http_data[0] != 'G' && http_data[0] != 'P') {
        return 0;
    }

    memset(&url, 0x00, sizeof(cap_url_t));

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &url;
    parserd = http_parser_execute(&parser, &parser_settings, (char *)http_data, n);
    if (parserd != n && HTTP_PARSER_ERRNO(&parser) != HPE_CB_header_value) {
        return 0;
    }

    pos = strchr(url.url, '?');
    if (pos != NULL) {
        *pos = 0;
    }

    memset(tmp, 0x00, sizeof(tmp));
    snprintf(tmp, MAX_URL_LEN, "%s%s", url.host, url.url);

    log_debug("http cap: %s", tmp);

    if (!policy_url_meet(tmp)) {
        return 0; 
    }

    return cap_inject_app_302(eth_hdr, ip_hdr, tcp_hdr, &url, injector);
}

static int cap_process_https_inject(u_char *https_data, size_t n,
                                        struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr,
                                        pkt_inject_t        *injector)
{
    int   ret;
    char  host[MAX_HOST_LEN];

    ret = parse_tls_header((const char *)https_data, n, host, MAX_HOST_LEN);
    if (ret <= 0) {
        return 0;
    }

    if (host[ret - 1] != URL_SPLIT && ret < MAX_HOST_LEN - 1) {
        host[ret] = URL_SPLIT;
        host[ret + 1] = 0;
    }

    log_debug("https cap: %s", host);

    if (!policy_url_meet(host)) {
        return 0;
    }

    return cap_inject_app_hello(eth_hdr, ip_hdr, tcp_hdr, injector);
}

static int cap_process_gtp_inject(u_char *data, size_t len, struct ether_header *eth_hdr, pkt_inject_t *injector)
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
            return cap_process_tcp(data, len, eth_hdr, ip_hdr, injector);
        case IPPROTO_UDP:
            return cap_process_udp(data, len, eth_hdr, ip_hdr, injector);
        default:
            return 0;
    }

    return 0;
}

static int cap_process_dns_inject(u_char *data, size_t len,
                                   struct ether_header *eth_hdr,
                                   struct iphdr        *ip_hdr,
                                   struct udphdr       *udp_hdr,
                                   pkt_inject_t        *injector)
{
    dns_message_t        msg;
    struct dns_question *qs;

    memset(&msg, 0x00, sizeof(dns_message_t));

    if (dns_message_parse(data, len, &msg)) {
        return 0;
    }

    qs = msg.questions;
    while (qs != NULL) {
        if (policy_url_meet(qs->name) && qs->type == dns_rr_a) {
            cap_inject_dns(ip_hdr, udp_hdr, &msg, qs, injector);
            break;
        }
        qs = qs->next;
    }

    dns_message_free(&msg);

    return qs != NULL;
}

static int cap_inject_dns(struct iphdr        *ip_hdr,
                           struct udphdr       *udp_hdr,
                           dns_message_t       *msg,
                           struct dns_question *qs,
                           pkt_inject_t        *injector)
{
    int  l;
    u_char sendData[1500];

    l = dns_gen_response(msg, qs, (char *)sendData, sizeof(sendData));
    if (l == -1) {
        return 0;
    }

    return inject_udp_packet(injector, ip_hdr, udp_hdr, sendData, l);
}

static int cap_inject_app_hello(struct ether_header *eth_hdr,
                                  struct iphdr        *ip_hdr,
                                  struct tcphdr       *tcp_hdr,
                                  pkt_inject_t        *injector)
{
    int    app_len;
    char   app_packet[32];

    app_len = snprintf(app_packet, 32, "hello");

    return inject_tcp_packet(injector, ip_hdr, tcp_hdr, (u_char *)app_packet, app_len);
}

static int cap_inject_app_302(struct ether_header *eth_hdr,
                              struct iphdr        *ip_hdr,
                              struct tcphdr       *tcp_hdr,
                              cap_url_t           *url,
                              pkt_inject_t        *injector)
{
    int   app_len;
    char  app_packet[2 * MAX_URL_LEN];

    app_len = snprintf(app_packet, 2 * MAX_URL_LEN, "%s%s?domain=%s&uri=%s\r\n\r\n", http_302_str, pushaddr, 
                                    url->host, url->url);

    return inject_tcp_packet(injector, ip_hdr, tcp_hdr, (u_char *)app_packet, app_len);
}

static int cap_process_tcp(u_char *cp, size_t len,
                           struct ether_header *eth_hdr,
                           struct iphdr        *ip_hdr,
                           pkt_inject_t        *injector)
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
/*
    if (!policy_ip_meet(ip_hdr->saddr)) {
        return;
    }
*/
    switch (ntohs(tcp_hdr->dest)) {
        case CAP_HTTP_PORT:
            return cap_process_http_inject(cp, len, eth_hdr, ip_hdr, tcp_hdr, injector);
        case CAP_HTTPS_PORT:
            return cap_process_https_inject(cp, len, eth_hdr, ip_hdr, tcp_hdr, injector);
        default:
            break;
    }

    return 0;
}

static int cap_process_udp(u_char *cp, size_t len,
                            struct ether_header *eth_hdr,
                            struct iphdr        *ip_hdr,
                            pkt_inject_t        *injector)
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
        return cap_process_dns_inject(cp, len, eth_hdr, ip_hdr, udp_hdr, injector);
    case CAP_GTP_PORT:
        return cap_process_gtp_inject(cp, len, eth_hdr, injector);
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

static int cap_process_packets_helper(u_char *data, int len, pkt_inject_t *injector)
{
    u_char              *cp;
    uint16_t             eth_t;
    struct ether_header *eth_hdr;
    struct iphdr        *ip_hdr;

    cp  =  data;

    eth_hdr = (struct ether_header *)cp;
    eth_t = ntohs(eth_hdr->ether_type);

	// We only care about IP packets containing at least a full IP+TCP header.
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
            return cap_process_tcp(cp, len, eth_hdr, ip_hdr, injector);
        case IPPROTO_UDP:
            return cap_process_udp(cp, len, eth_hdr, ip_hdr, injector);
        default:
            return 0;
    }

    return 0;
}

static int cap_process_packets(struct netmap_ring *ring, int limit, 
                    pkt_inject_t *injector, uint64_t *bytes, uint64_t *send)
{
    int      cur, rx, n, s;
    uint64_t b = 0;

    if (bytes == NULL)
        bytes = &b;

    cur = ring->cur;
    n = nm_ring_space(ring);
    if (n < limit)
        limit = n;
    for (rx = 0; rx < limit; rx++) {
        struct netmap_slot *slot = &ring->slot[cur];
        char *p = NETMAP_BUF(ring, slot->buf_idx);

        *bytes += slot->len;

        //dump_payload(p, slot->len, ring, cur);
        s = cap_process_packets_helper((u_char *)p, slot->len, injector);
        if (s > 0) {
            *send += s;
        }

        cur = nm_ring_next(ring, cur);
    }
    ring->head = ring->cur = cur;

    return (rx);
}

static void *cap_worker(void *arg)
{
    cap_worker_t *worker = (cap_worker_t *)arg;

    int i;
    int ret;

    struct netmap_if   *nifp;
    struct netmap_ring *rxring;

    struct cap_ctrs cur;

    struct pollfd pfd = {.fd = worker->inm->fd, .events = POLLIN};

    cur.pkts = cur.bytes = cur.events = cur.drop = cur.min_space = cur.send = 0;
    cur.t.tv_usec = cur.t.tv_sec = 0; //  unused, just silence the compiler    

    setaffinity(worker->tid, worker->affinity);

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
        for (i = worker->inm->first_rx_ring; i < worker->inm->last_rx_ring; i++) {
            int m;

            rxring = NETMAP_RXRING(nifp, i);
            m = rxring->head + rxring->num_slots - rxring->tail;
            if (m >= (int)rxring->num_slots)
                m -= rxring->num_slots;

            cur_space += m;
            if (nm_ring_empty(rxring))
                continue;

            m = cap_process_packets(rxring, worker->burst, &worker->injector, &cur.bytes, &cur.send);
            cur.pkts += m;
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

static void cap_log_status(cap_worker_t *worker)
{
    struct cap_ctrs prev, cur;

    prev.pkts = prev.bytes = prev.events = prev.send = 0;
    gettimeofday(&prev.t, NULL);

    for (;;) {
        char b1[40], b2[40], b3[40], b4[70], b5[40];
        uint64_t pps, usec;
        struct cap_ctrs x;
        double abs;

        usec = cap_wait_for_next_report(&prev.t, &cur.t);

        cur.pkts = cur.bytes = cur.events = cur.send = 0;
        cur.min_space = 0;
        if (usec < 10000) /* too short to be meaningful */
            continue;
        /* accumulate counts for all threads */
        
        cur.pkts += worker->ctr.pkts;
        cur.bytes += worker->ctr.bytes;
        cur.events += worker->ctr.events;
        cur.send += worker->ctr.send;
        cur.min_space += worker->ctr.min_space;
        worker->ctr.min_space = 99999;

        x.pkts = cur.pkts - prev.pkts;
        x.bytes = cur.bytes - prev.bytes;
        x.events = cur.events - prev.events;
        x.send = cur.send - prev.send;
        pps = (x.pkts * 1000000 + usec / 2) / usec;
        abs = (x.events > 0) ? (x.pkts / (double)x.events) : 0;

        strcpy(b4, "");

        log_info("%spps %s(%spkts %sinjections %sbps in %llu usec) %.2f avg_batch %d min_space",
          norm(b1, pps), b4, norm(b2, (double)x.pkts), norm(b5, (double)x.send),
          norm(b3, (double)x.bytes * 8), (unsigned long long)usec, abs,
          (int)cur.min_space);
        prev = cur;

        if (worker->done)
            break;
    }    
}

void cap_service(hjk_conf_t *conf)
{
    struct nmreq    base_nmd;
    struct nm_desc *inmd, *onmd;

    cap_worker_t worker;

    bzero(&base_nmd, sizeof(base_nmd));
    parse_nmr_config(conf->nmr, &base_nmd);

    base_nmd.nr_flags |= NR_ACCEPT_VNET_HDR;

    inmd = nm_open(conf->iether, &base_nmd, 0, NULL);
    if (inmd == NULL) {
        log_error("failed to open %s: %s", conf->iether, strerror(errno));
        exit(1);
    }

    onmd = nm_open(conf->oether, &base_nmd, 0, NULL);
    if (onmd == NULL) {
        log_error("failed to open %s: %s", conf->oether, strerror(errno));
        exit(1);
    }

    strncpy(pushaddr, conf->http_302_str, sizeof(pushaddr) - 1);

    bzero(&worker, sizeof(cap_worker_t));

    worker.inm = inmd;
    worker.onm = onmd;
    worker.burst = conf->burst < MIN_BURST_SIZE ? MIN_BURST_SIZE : conf->burst;
    worker.affinity = conf->affinity % sysconf(_SC_NPROCESSORS_ONLN);

    worker.injector.nmd = onmd;
    bcopy(&conf->dst_mac, &worker.injector.dst, sizeof(worker.injector.dst));
    bcopy(&conf->src_mac, &worker.injector.src, sizeof(worker.injector.src));

    pthread_create(&worker.tid, NULL, cap_worker, &worker);
    pthread_detach(worker.tid);

    cap_log_status(&worker);
}
