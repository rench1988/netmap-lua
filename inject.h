#ifndef __inject_h__
#define __inject_h__

#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>


int inject_tcp_packet(struct nm_desc *nmd, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, 
            uint8_t *mac, uint16_t vlanID, u_char *data, int len);
int inject_udp_packet(struct nm_desc *nmd, struct iphdr *ip_hdr, struct udphdr *udp_hdr, 
            uint8_t *mac, uint16_t vlanID, u_char *data, int len);

#endif
