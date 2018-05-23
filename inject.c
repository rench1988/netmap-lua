#include "inject.h"
#include "log.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

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

static u_char *inject_fill_2lay_data(u_char *buf, struct ether_addr *src, struct ether_addr *dst)
{
    struct ether_header *eh = (struct ether_header *)buf;

    bcopy(src, eh->ether_shost, 6);
    bcopy(dst, eh->ether_dhost, 6);

    eh->ether_type = htons(ETHERTYPE_IP);

    return buf + sizeof(struct ether_header);
}

static u_char *inject_fill_3lay_data(u_char *buf, struct iphdr *ip_hdr, int pkt_len, int protocol)
{
    struct iphdr  *ip = (struct iphdr *)buf;

    ip->version = IPVERSION;
    ip->ihl = sizeof(*ip) >> 2;
    ip->id = 0;
    ip->tos = IPTOS_LOWDELAY;
    ip->tot_len = ntohs(pkt_len - sizeof(struct ether_header));
    ip->frag_off = htons(0x4000); /* Don't fragment */
    ip->ttl = IPDEFTTL;
    ip->protocol   = protocol;
    ip->daddr = ip_hdr->saddr;
    ip->saddr = ip_hdr->daddr;
    ip->check = wrapsum(checksum(ip, sizeof(*ip), 0));

    return buf + sizeof(struct iphdr);
}

static u_char *inject_fill_udp_data(u_char *buf, struct udphdr *udp_hdr, 
                    u_char *app_data, int app_len)
{
    struct udphdr *udp = (struct udphdr *)buf;
    struct iphdr  *ip;

    ip = (struct iphdr *)(buf - sizeof(*ip));

    udp->source = udp_hdr->dest;
    udp->dest = udp_hdr->source;
    udp->len = htons(app_len + sizeof(struct udphdr));    

    udp->check = wrapsum(checksum(
        udp, sizeof(*udp),       /* udp header */
        checksum(app_data, /* udp payload */
                 app_len,
                 checksum(&ip->saddr, /* pseudo header */
                        2 * sizeof(ip->saddr),
                        IPPROTO_UDP + (u_int32_t)ntohs(udp->len)))));

    return buf + sizeof(struct udphdr);
}

static u_char *inject_fill_tcp_data(u_char *buf, struct tcphdr *tcp_hdr, 
                    u_char *app_data, int app_len, uint32_t ack)
{
    struct tcphdr *tcp = (struct tcphdr *)buf;
    struct iphdr  *ip;

    ip = (struct iphdr *)(buf - sizeof(*ip));

    tcp->source = tcp_hdr->dest;
    tcp->dest = tcp_hdr->source;
    tcp->seq = tcp_hdr->ack_seq;
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5;
    tcp->fin = 1;
    tcp->ack = 1;
    tcp->window = htons(8192);
    tcp->urg = 0;

    tcp->check = wrapsum(checksum(
        tcp, sizeof(*tcp),       /* tcp header */
        checksum(app_data, /* tcp payload */
                 app_len,
                 checksum(&ip->saddr, /* pseudo header */
                        2 * sizeof(ip->saddr),
                        IPPROTO_TCP + app_len + sizeof(struct tcphdr)))));

    return buf + sizeof(struct tcphdr);
}

static int inject_prepare_tcp_pkt(pkt_inject_t *injector, u_char *buf, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr,
                    u_char *data, int len)
{
    u_char    *dp = buf;

    int pkt_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + len;
    
    uint32_t ack = ntohl(tcp_hdr->seq) + ntohs(ip_hdr->tot_len) - (ip_hdr->ihl << 2) - (tcp_hdr->doff << 2);

    dp = inject_fill_2lay_data(dp, &injector->src, &injector->dst);
    dp = inject_fill_3lay_data(dp, ip_hdr, pkt_len, IPPROTO_TCP);
    dp = inject_fill_tcp_data(dp, tcp_hdr, data, len, ack);

    memcpy(dp, data, len);

    return dp - buf + len;
}

static int inject_prepare_udp_pkt(pkt_inject_t *injector, u_char *buf, struct iphdr *ip_hdr, struct udphdr *udp_hdr, 
                    u_char *data, int len)
{
    u_char   *dp = buf;

    int  pkt_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + len;   

    dp = inject_fill_2lay_data(dp, &injector->src, &injector->dst);
    dp = inject_fill_3lay_data(dp, ip_hdr, pkt_len, IPPROTO_UDP);
    dp = inject_fill_udp_data(dp, udp_hdr, data, len);

    memcpy(dp, data, len);

    return dp - buf + len;
}

static int inject_packet_send(pkt_inject_t *injector, u_char *pkt, int pktlen)
{
    int   i;
    int   cur;

    struct netmap_if *nifp;
    struct netmap_ring *txring = NULL;

    if (ioctl(injector->nmd->fd, NIOCTXSYNC, NULL) < 0) {
        log_error("ioctl error on nic: %s", strerror(errno));
        return -1;
    }

    nifp = injector->nmd->nifp;

    for (i = injector->nmd->first_tx_ring; i <= injector->nmd->last_tx_ring; i++) {
        txring = NETMAP_TXRING(nifp, i);
        if (nm_ring_empty(txring))
            continue;
        
        cur = txring->cur;

        struct netmap_slot *slot = &txring->slot[cur];

        char *p = NETMAP_BUF(txring, slot->buf_idx);

        nm_pkt_copy(pkt, p, pktlen);
        slot->len = pktlen;

        slot->flags &= ~NS_MOREFRAG;
        slot->flags |= NS_REPORT;

        cur = nm_ring_next(txring, cur);

        txring->head = txring->cur = cur;
        break;
    }

    if (ioctl(injector->nmd->fd, NIOCTXSYNC, NULL) < 0) {
        log_error("ioctl error on nic: %s", strerror(errno));
        return -1;
    }

    return i <= injector->nmd->last_tx_ring ? 1 : 0;
}

int inject_tcp_packet(pkt_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, 
                    u_char *data, int len)
{
    int    pktlen;
    u_char pkt[MAX_PKT_SIZE];

    pktlen = inject_prepare_tcp_pkt(injector, pkt, ip_hdr, tcp_hdr, data, len);

    return inject_packet_send(injector, pkt, pktlen);
}

int inject_udp_packet(pkt_inject_t *injector, struct iphdr *ip_hdr, struct udphdr *udp_hdr, 
                    u_char *data, int len)
{
    int    pktlen;
    u_char pkt[MAX_PKT_SIZE];

    pktlen = inject_prepare_udp_pkt(injector, pkt, ip_hdr, udp_hdr, data, len);

    return inject_packet_send(injector, pkt, pktlen);
}

