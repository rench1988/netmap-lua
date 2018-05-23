#ifndef __inject_h__
#define __inject_h__

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ethernet.h>

typedef struct pkt_inject_s {
    struct nm_desc *nmd;

    struct ether_addr src;
    struct ether_addr dst;
} pkt_inject_t;


int inject_tcp_packet(pkt_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, u_char *data, int len);
int inject_udp_packet(pkt_inject_t *injector, struct iphdr *ip_hdr, struct udphdr *udp_hdr, u_char *data, int len);

#endif

