#include "capture.h"
#include "conf.h"
#include "lkf_queue.h"
#include "urls.h"
#include "log.h"
#include "http_parser.h"
#include "util.h"
#include "https.h"
#include "inject.h"
#include "dns.h"
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
#define DEFAULT_CAP_RING_NUM    128
#define DEFAULT_CAP_FILTER      "greater 100 and dst port 80"
#define DEFAULT_CAP_BUF_SIZE    512 * 1024 * 1024  //512m

#define CAP_HTTP_PORT    80
#define CAP_HTTPS_PORT   443
#define CAP_DNS_PORT     53

#define MAX_PACKET_LEN  65535

#define MAX_PACKET_STATUE  1000000
#define MAX_HOST_LEN   256

static const char http_302_str[] = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n"
                                "Cache-Control:no-store, no-cache\r\nExpires: Sat, 18 Jul 1988 05:00:00\r\n"
                                "Pragma: no-cache\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nLocation: ";

char pushaddr[MAX_URL_LEN];

net_inject_t  *nij;

extern int  hik_process_slot;

extern pid_t   hjk_pid;

typedef struct {
    int  hflag;
    char host[MAX_HOST_LEN];
    char url[MAX_URL_LEN];
} cap_url_t;

static int cap_on_headers_complete(http_parser *parser);
static int cap_header_field_cb(http_parser *parser, const char *buf, size_t len);
static int cap_header_value_cb(http_parser *parser, const char *buf, size_t len);
static int cap_url_cb(http_parser *parser, const char *buf, size_t len);


static void cap_service_packet_inject_app_rst(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
                                            struct tcphdr *tcp_hdr);
static void cap_service_packet_inject_rst(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
                                        struct tcphdr *tcp_hdr);
static void cap_service_packet_inject_app(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
                                      struct tcphdr *tcp_hdr, cap_url_t *url);
static void cap_service_packet_inject_dns(struct iphdr        *ip_hdr,
                                          struct udphdr       *udp_hdr,
                                          dns_message_t       *msg,
                                          struct dns_question *qs);


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

static void cap_service_http_hijack(u_char *http_data, size_t n,
                                        struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr)
{
    int         parserd;
    http_parser parser;
    char       *pos;
    char        tmp[MAX_URL_LEN];
    cap_url_t   url;

    if (http_data[0] != 'G' && http_data[0] != 'P') {
        return;
    }

    memset(&url, 0x00, sizeof(cap_url_t));

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &url;
    parserd = http_parser_execute(&parser, &parser_settings, (char *)http_data, n);
    if (parserd != n && HTTP_PARSER_ERRNO(&parser) != HPE_CB_header_value) {
        return;
    }

    pos = strchr(url.url, '?');
    if (pos != NULL) {
        *pos = 0;
    }

    memset(tmp, 0x00, sizeof(tmp));
    snprintf(tmp, MAX_URL_LEN, "%s%s", url.host, url.url);

    if (!has_url(tmp)) {
        return; 
    }

    cap_service_packet_inject_app(eth_hdr, ip_hdr, tcp_hdr, &url);
    cap_service_packet_inject_rst(eth_hdr, ip_hdr, tcp_hdr);    

    return;
}

static void cap_service_https_hijack(u_char *https_data, size_t n,
                                        struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr)
{
    int   ret;
    char  host[MAX_HOST_LEN];

    ret = parse_tls_header((const char *)https_data, n, host, MAX_HOST_LEN);
    if (ret <= 0) {
        return;
    }

    if (host[ret - 1] != URL_SPLIT && ret < MAX_HOST_LEN - 1) {
        host[ret] = URL_SPLIT;
        host[ret + 1] = 0;
    }

    if (!has_url(host)) {
        return;
    }

    cap_service_packet_inject_app_rst(eth_hdr, ip_hdr, tcp_hdr);
    cap_service_packet_inject_rst(eth_hdr, ip_hdr, tcp_hdr);

    return;
}

static void cap_service_dns_hijack(u_char *data, size_t len,
                                   struct ether_header *eth_hdr,
                                   struct iphdr        *ip_hdr,
                                   struct udphdr       *udp_hdr)
{
    dns_message_t        msg;
    struct dns_question *qs;

    memset(&msg, 0x00, sizeof(dns_message_t));

    if (dns_message_parse(data, len, &msg)) {
        return;
    }

    qs = msg.questions;
    while (qs != NULL) {
        if (has_url(qs->name) && qs->type == dns_rr_a) {
            cap_service_packet_inject_dns(ip_hdr, udp_hdr, &msg, qs);
            break;
        }
        qs = qs->next;
    }

    dns_message_free(&msg);

    return;
}

static void cap_service_packet_inject_dns(struct iphdr        *ip_hdr,
                                          struct udphdr       *udp_hdr,
                                          dns_message_t       *msg,
                                          struct dns_question *qs)
{
    int  l;
    u_char sendData[1500];

    l = dns_gen_response(msg, qs, (char *)sendData, sizeof(sendData));
    if (l == -1) {
        return;
    }

    if (inject_src_dns_packet(nij, ip_hdr, udp_hdr, sendData, l)) {
        log_error("failed send inject dns packet to client[%s]", nij->errbuf);
    }

    return;
}

static void cap_service_packet_inject_app_rst(struct ether_header *eth_hdr,
                                            struct iphdr        *ip_hdr,
                                            struct tcphdr       *tcp_hdr)
{
    if (inject_src_rst(nij, ip_hdr, tcp_hdr)) {
        log_error("failed send inject rst packet to client[%s]", nij->errbuf);
    }

    return;    
}

static void cap_service_packet_inject_rst(struct ether_header *eth_hdr,
                                        struct iphdr        *ip_hdr,
                                        struct tcphdr       *tcp_hdr)
{
    if (inject_dst_rst(nij, ip_hdr, tcp_hdr)) {
        log_error("failed send rst to source website[%s]", nij->errbuf);
    }

    return;
}

static void cap_service_packet_inject_app(struct ether_header *eth_hdr,
                                      struct iphdr        *ip_hdr,
                                      struct tcphdr       *tcp_hdr,
                                      cap_url_t *url)
{
    int   inject_len;
    char  inject_packet[2 * MAX_URL_LEN];

    inject_len = snprintf(inject_packet, 2 * MAX_URL_LEN, "%s%s?domain=%s&uri=%s\r\n\r\n", http_302_str, pushaddr, 
                                    url->host, url->url);
    
    if (inject_src_data(nij, ip_hdr, tcp_hdr, (u_char *)inject_packet, inject_len)) {
        log_error("failed send inject packet to client[%s]", nij->errbuf);
    }

    return;
}

static void cap_service_working_tcp(u_char *cp, size_t len,
                                    struct ether_header *eth_hdr,
                                    struct iphdr        *ip_hdr)
{
    uint16_t             tcp_dl;
    uint8_t              tcp_hl;
    struct tcphdr       *tcp_hdr;

    if (len <= sizeof(struct tcphdr)) return;

    tcp_hdr = (struct tcphdr *)cp;
    tcp_hl = tcp_hdr->doff * 4;
    tcp_dl = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - tcp_hl;

    cp = cp + tcp_hl;
    len = len - tcp_hl;

    if (len <= 0) {
        return;
    }

    switch (ntohs(tcp_hdr->dest)) {
        case CAP_HTTP_PORT:
            cap_service_http_hijack(cp, len, eth_hdr, ip_hdr, tcp_hdr);
            break;
        case CAP_HTTPS_PORT:
            cap_service_https_hijack(cp, len, eth_hdr, ip_hdr, tcp_hdr);
            break;
        default:
            break;
    }

    return;
}

static void cap_service_working_udp(u_char *cp, size_t len,
                                    struct ether_header *eth_hdr,
                                    struct iphdr        *ip_hdr)
{
    static int udp_header_size = 8;

    struct udphdr *udp_hdr;

    if (len <= sizeof(struct udphdr)) {
        return;
    }

    udp_hdr = (struct udphdr *)cp;

    if (ntohs(udp_hdr->dest) != CAP_DNS_PORT) {
        return;
    }

    cp += udp_header_size;
    len -= udp_header_size;

    cap_service_dns_hijack(cp, len, eth_hdr, ip_hdr, udp_hdr);

    return;
}

static void cap_service_working_helper(u_char *raw, struct pcap_pkthdr *pkthdr)
{
    u_char              *cp;
    uint16_t             eth_t;
    size_t               len;
    struct ether_header *eth_hdr;
    struct iphdr        *ip_hdr;

    cp = raw;
    len = pkthdr->caplen;

    eth_hdr = (struct ether_header *)cp;
    eth_t = ntohs(eth_hdr->ether_type);

	// We only care about IP packets containing at least a full IP+TCP header.
	if(eth_t != 0x0800 && eth_t != 0x8100) {
        return;
    }

    cp = cp + ETHER_HDR_LEN;
    len = len - ETHER_HDR_LEN;

	/* Is PPOE packet*/
	if (eth_t == 0x8100) {
		cp = cp + 2;

		if (cp[0] != 0x88 && cp[1] != 0x64)
			return;
		
		/* Skip PPP header region*/
        cp = cp + 10;  

        len = len - 12;     
    }

    if (len <= sizeof(ip_hdr)) return;
    
	ip_hdr = (struct iphdr *) cp;
    if (ip_hdr->version != 4) {
        return; 
    }

    cp = cp + (ip_hdr->ihl * 4);
    len = len - (ip_hdr->ihl * 4);

    switch (ip_hdr->protocol) {
        case IPPROTO_TCP:
            cap_service_working_tcp(cp, len, eth_hdr, ip_hdr);
            break;
        case IPPROTO_UDP:
            cap_service_working_udp(cp, len, eth_hdr, ip_hdr);
            break;
        default:
            return;
    }

    return;
}

static void cap_service_config(pcap_t *pcap, cap_conf_t *conf, char *cap_dev)
{
    char           errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32    netp;
    bpf_u_int32    mask;

    struct bpf_program  fp;

    char *filter = conf->filter ? conf->filter : DEFAULT_CAP_FILTER;

    log_info("[%d]'s filter %s", hjk_pid, filter);

    pcap_lookupnet(cap_dev, &netp, &mask, errbuf);

    if (pcap_set_immediate_mode(pcap, 1) ||
        pcap_activate(pcap) ||
        pcap_compile(pcap, &fp, filter, 0, netp) ||
        pcap_setfilter(pcap, &fp) ||
        pcap_setdirection(pcap, PCAP_D_IN)) {
        goto pcap_set_failed;
    }

    return;

pcap_set_failed:
    log_error("failed set capture configuration, %s", pcap_geterr(pcap));
    exit(-1);
}

void cap_service(cap_conf_t *conf, char *cap_dev, char *net_dev, int mtu, char *pushurl, char *macaddr)
{
    //int            ret;
    uint32_t       pn;
    const u_char  *raw;
    char           perrbuf[PCAP_ERRBUF_SIZE];
    char           nerrbuf[LIBNET_ERRBUF_SIZE];
    pcap_t        *pcap;

    struct pcap_pkthdr   pkthdr;
    struct pcap_stat     ps;

    pcap = pcap_create(cap_dev, perrbuf);
    if (!pcap) {
        log_error("failed init capture handler, %s", perrbuf);
        exit(-1);
    }

    cap_service_config(pcap, conf, cap_dev);

    nij = inject_new(net_dev, macaddr, mtu, nerrbuf, LIBNET_ERRBUF_SIZE);
    if (nij == NULL) {
        log_error("failed init injection device, %s", nerrbuf);
        exit(-1);
    }        

    if (set_pthread_affinity(conf->core)) {
        log_fatal("capture service, failed stick process %d to core %d", hjk_pid, conf->core);
        exit(1);
    }    

    strncpy(pushaddr, pushurl, MAX_URL_LEN - 1);
    
    pn = 0;
    while (1) {
		raw = pcap_next(pcap, &pkthdr);
		if (raw == NULL) {
            continue;
        }

        pn++;

        if (pkthdr.caplen > MAX_PACKET_LEN) {
            log_warn("capture very big packet, discard it");
            continue;
        }

        cap_service_working_helper((u_char *)raw, &pkthdr);

        if (pn > MAX_PACKET_STATUE) {
            pcap_stats(pcap, &ps);
            log_info("[%d]capture status: %d(ps_recv)  %d(ps_drop)  %d(ps_ifdrop)", hjk_pid, ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
            pn = 0;
        }
	}    
}
