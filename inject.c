#include "inject.h"
#include "log.h"
#include "ethertype.h"
#include "pg_inet.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>

uint8_t srcmac[6] = {0xf8,0x98,0xef,0xa4,0x0f,0x55};

#define MAX_PKT_SIZE  16384

/* Compute the checksum of the given ip header. */
static uint32_t checksum(const void *data, uint16_t len, uint32_t sum) {
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

static uint16_t wrapsum(uint32_t sum) {
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

#if 0
static void dump_payload(const char *_p, int len) {
    char buf[128];
    int i, j, i0;
    const unsigned char *p = (const unsigned char *)_p;

    /* get the length in ASCII of the length of the packet. */

    /* hexdump routine */
    for (i = 0; i < len;) {
        memset(buf, sizeof(buf), ' ');
        sprintf(buf, "%5d: ", i);
        i0 = i;
        for (j = 0; j < 16 && i < len; i++, j++)
            sprintf(buf + 7 + j * 3, "%02x ", (uint8_t)(p[i]));
        i = i0;
        for (j = 0; j < 16 && i < len; i++, j++)
            sprintf(buf + 7 + j + 48, "%c", isprint(p[i]) ? p[i] : '.');
        log_info("send pkt: %s\n", buf);
    }
}
#endif

static u_char *inject_fill_2lay_data(u_char *buf, uint8_t *src, uint8_t *dst, uint16_t eth_type, uint16_t vlanID)
{
    uint16_t  size;
    uint16_t *vp;

    size = sizeof(struct ether_header);

    struct ether_header *eh = (struct ether_header *)buf;

    bcopy(src, eh->ether_shost, ETHERTYPE_MAC_LEN);
    bcopy(dst, eh->ether_dhost, ETHERTYPE_MAC_LEN);

    eh->ether_type = vlanID ? htons(ETHERTYPE_8021Q) : htons(eth_type);

    if (vlanID) {
        vp = (uint16_t *)(buf + sizeof(*eh));

        *vp = 0;
        *vp = htons(vlanID);

        vp += 1;
        *vp = htons(eth_type);

        size += 4;
    }

    return buf + size;
}

static int inject_fill_ipv4_header(u_char *buf, struct iphdr *ip_hdr, int pkt_len, int protocol) {
    struct iphdr  *ip = (struct iphdr *)buf;

    ip->check = 0;

    ip->version = IPVERSION;
    ip->ihl = sizeof(*ip) >> 2;
    ip->id = 0;
    ip->tos = IPTOS_LOWDELAY;
    ip->tot_len = htons(pkt_len - sizeof(struct ether_header));
    ip->frag_off = htons(0x4000); /* Don't fragment */
    ip->ttl = IPDEFTTL;
    ip->protocol = protocol;
    ip->daddr = ip_hdr->saddr;
    ip->saddr = ip_hdr->daddr;
    ip->check = wrapsum(checksum(ip, sizeof(*ip), 0));

    return sizeof(struct iphdr);    
}

static int inject_fill_ipv6_header(u_char *buf, struct ipv6hdr *ipv6_hdr, int pkt_len, int protocol) 
{
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)buf;

    ipv6->priority = 0;
    ipv6->version = IPV6VERSION;

    memset(ipv6->flow_lbl, 0x00, sizeof(ipv6->flow_lbl));

    ipv6->payload_len = htons(pkt_len - sizeof(struct ether_header) - sizeof(struct ipv6hdr));
    ipv6->nexthdr = protocol;
    ipv6->hop_limit = 48;

    memcpy(&ipv6->saddr, &ipv6_hdr->daddr, sizeof(struct in6_addr));
    memcpy(&ipv6->daddr, &ipv6_hdr->saddr, sizeof(struct in6_addr));

    return sizeof(struct ipv6hdr);
}

static u_char *inject_fill_3lay_data(u_char *buf, struct ipv6hdr *ipv6_hdr, 
                                    struct iphdr *ip_hdr, int pkt_len, int protocol)
{
    if (ipv6_hdr) {
        return buf + inject_fill_ipv6_header(buf, ipv6_hdr, pkt_len, protocol);
    }

    return buf + inject_fill_ipv4_header(buf, ip_hdr, pkt_len, protocol);
}

static u_char *inject_fill_udp_data(u_char *buf, struct udphdr *udp_hdr, uint16_t eth,
                    u_char *app_data, int app_len)
{
    struct udphdr   *udp = (struct udphdr *)buf;
    struct iphdr    *ip;
    struct ipv6hdr  *ipv6;

    udp->check = 0;

    ip = NULL;
    ipv6 = NULL;

    if (eth == ETHERTYPE_IP) {
        ip = (struct iphdr *)(buf - sizeof(*ip));
    } else {
        ipv6 = (struct ipv6hdr *)(buf - sizeof(*ipv6));
    }

    udp->source = udp_hdr->dest;
    udp->dest = udp_hdr->source;
    udp->len = htons(app_len + sizeof(struct udphdr));    

    if (eth == ETHERTYPE_IP) {
        udp->check = wrapsum(checksum(
            udp, sizeof(*udp),       /* udp header */
            checksum(app_data, /* udp payload */
                 app_len,
                 checksum(&ip->saddr, /* pseudo header */
                        2 * sizeof(ip->saddr),
                        IPPROTO_UDP + (u_int32_t)ntohs(udp->len)))));
    } else {
        udp->check = wrapsum(checksum(
            udp, sizeof(*udp),       /* udp header */
            checksum(app_data, /* udp payload */
                 app_len,
                 checksum(&ipv6->saddr, /* pseudo header */
                        2 * sizeof(ipv6->saddr),
                        IPPROTO_UDP + (u_int32_t)ntohs(udp->len)))));        
    }

    return buf + sizeof(struct udphdr);
}

static u_char *inject_fill_tcp_data(u_char *buf, struct tcphdr *tcp_hdr, uint16_t eth,
                    u_char *app_data, int app_len, uint32_t ack)
{
    struct tcphdr  *tcp = (struct tcphdr *)buf;
    struct iphdr   *ip;
    struct ipv6hdr *ipv6;

    tcp->check = 0;

    ip = NULL;
    ipv6 = NULL;

    if (eth == ETHERTYPE_IP) {
        ip = (struct iphdr *)(buf - sizeof(*ip));
    } else {
        ipv6 = (struct ipv6hdr *)(buf - sizeof(*ipv6));
    }

    tcp->source = tcp_hdr->dest;
    tcp->dest = tcp_hdr->source;
    tcp->seq = tcp_hdr->ack_seq;
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5;
    tcp->fin = 1;
    tcp->ack = 1;
    tcp->window = htons(8192);
    tcp->urg = 0;

    if (eth == ETHERTYPE_IP) {
        tcp->check = wrapsum(checksum(
            tcp, sizeof(*tcp),       /* tcp header */
            checksum(app_data, /* tcp payload */
                     app_len,
                     checksum(&ip->saddr, /* pseudo header */
                        2 * sizeof(ip->saddr),
                        IPPROTO_TCP + app_len + sizeof(struct tcphdr)))));        
    } else {
        tcp->check = wrapsum(checksum(
            tcp, sizeof(*tcp),       /* tcp header */
            checksum(app_data, /* tcp payload */
                     app_len,
                     checksum(&ipv6->saddr, /* pseudo header */
                        2 * sizeof(ipv6->saddr),
                        IPPROTO_TCP + app_len + sizeof(struct tcphdr)))));
    }

    return buf + sizeof(struct tcphdr);
}

static int inject_prepare_tcp_pkt(u_char *buf, uint8_t *dstmac, uint16_t vlanID, 
                        struct ipv6hdr *ipv6_hdr, struct iphdr *ip_hdr, 
                        struct tcphdr *tcp_hdr, u_char *data, int len)
{
    int        pktlen;
    uint16_t   eth;
    uint32_t   ack;
    u_char    *dp = buf;

    if (ipv6_hdr) {
        pktlen = sizeof(struct ether_header) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + len;
        ack = ntohl(tcp_hdr->seq) + ntohs(ipv6_hdr->payload_len) - sizeof(struct ipv6hdr) - (tcp_hdr->doff << 2);
        eth = ETHERTYPE_IPV6;
    } else {
        pktlen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + len;
        ack = ntohl(tcp_hdr->seq) + ntohs(ip_hdr->tot_len) - (ip_hdr->ihl << 2) - (tcp_hdr->doff << 2);
        eth = ETHERTYPE_IP;
    }

    dp = inject_fill_2lay_data(dp, (uint8_t *)srcmac, dstmac, eth, vlanID);
    dp = inject_fill_3lay_data(dp, ipv6_hdr, ip_hdr, pktlen, IPPROTO_TCP);
    dp = inject_fill_tcp_data(dp, tcp_hdr, eth, data, len, ack);

    memcpy(dp, data, len);

    return dp - buf + len;
}

static int inject_prepare_udp_pkt(u_char *buf, uint8_t *dstmac, uint16_t vlanID, 
                        struct ipv6hdr *ipv6_hdr, struct iphdr *ip_hdr, 
                        struct udphdr *udp_hdr, u_char *data, int len)
{
    int       pktlen;
    uint16_t  eth;
    u_char   *dp = buf;

    if (ipv6_hdr) {
        pktlen = sizeof(struct ether_header) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + len;
        eth = ETHERTYPE_IPV6;
    } else {
        pktlen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + len;
        eth = ETHERTYPE_IP;
    }

    dp = inject_fill_2lay_data(dp, (uint8_t *)srcmac, dstmac, eth, vlanID);
    dp = inject_fill_3lay_data(dp, ipv6_hdr, ip_hdr, pktlen, IPPROTO_UDP);
    dp = inject_fill_udp_data(dp, udp_hdr, eth, data, len);

    memcpy(dp, data, len);

    return dp - buf + len;
}

/*
static int inject_packet_send(pcap_t *opcap, u_char *pkt, int pktlen)
{
    int   i;
    int   cur;

    struct netmap_if *nifp;
    struct netmap_ring *txring = NULL;

    if (ioctl(nmd->fd, NIOCTXSYNC, NULL) < 0) {
        log_error("ioctl error on nic: %s", strerror(errno));
        return -1;
    }

    nifp = nmd->nifp;

    for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; i++) {
        txring = NETMAP_TXRING(nifp, i);
        if (nm_ring_empty(txring))
            continue;
        
        cur = txring->cur;

        struct netmap_slot *slot = &txring->slot[cur];

        char *p = NETMAP_BUF(txring, slot->buf_idx);

        slot->flags = 0;

        nm_pkt_copy(pkt, p, pktlen);
        slot->len = pktlen;

        slot->flags &= ~NS_MOREFRAG;
        slot->flags |= NS_REPORT;

        cur = nm_ring_next(txring, cur);

        txring->head = txring->cur = cur;
        break;
    }

    if (ioctl(nmd->fd, NIOCTXSYNC, NULL) < 0) {
        log_error("ioctl error on nic: %s", strerror(errno));
        return -1;
    }

    return i <= nmd->last_tx_ring ? 1 : 0;
}
*/

static int inject_packet_send(pcap_t *opcap, u_char *pkt, int pktlen) {
    return pcap_inject(opcap, pkt, pktlen);
}

int inject_tcp_packet(pcap_t *opcap, struct ipv6hdr *ipv6_hdr, struct iphdr *ip_hdr, 
                    struct tcphdr *tcp_hdr, uint8_t *mac, uint16_t vlanID, u_char *data, 
                    int len)
{
    int    pktlen;
    u_char pkt[MAX_PKT_SIZE];

    pktlen = inject_prepare_tcp_pkt(pkt, mac, vlanID, ipv6_hdr, ip_hdr, tcp_hdr, data, len);

    return inject_packet_send(opcap, pkt, pktlen);
}

int inject_udp_packet(pcap_t *opcap, struct ipv6hdr *ipv6_hdr, struct iphdr *ip_hdr, 
                    struct udphdr *udp_hdr, uint8_t *mac, uint16_t vlanID, u_char *data, 
                    int len)
{
    int    pktlen;
    u_char pkt[MAX_PKT_SIZE];

    pktlen = inject_prepare_udp_pkt(pkt, mac, vlanID, ipv6_hdr, ip_hdr, udp_hdr, data, len);

    //dump_payload(pkt, pktlen);

    return inject_packet_send(opcap, pkt, pktlen);
}
