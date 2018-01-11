#ifndef __inject_h__
#define __inject_h__

#include <libnet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

typedef struct {
    libnet_t *l;

    uint8_t  smac[6];
    uint8_t  dmac[6];
    uint16_t mss;

    libnet_ptag_t data_tag;
    libnet_ptag_t tcp_tag;
    libnet_ptag_t udp_tag;
    libnet_ptag_t ipv4_tag;
    libnet_ptag_t ether_tag;

    char  errbuf[LIBNET_ERRBUF_SIZE];
} net_inject_t;


net_inject_t *inject_new(const char *dev, char *str_mac, uint16_t mtu, char *errbuf, size_t errlen);
void  inject_destroy(net_inject_t *injector);
int inject_dst_rst(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr);
int inject_src_rst(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr);
int inject_src_data(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr,
                     u_char *data, size_t datalen);
int inject_src_dns_packet(net_inject_t *injector, struct iphdr *ip_hdr, struct udphdr *udp_hdr,
                            u_char *data, size_t datalen);                     

#endif

