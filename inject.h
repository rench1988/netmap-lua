#ifndef __inject_h__
#define __inject_h__

#include <stdint.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <pcap/pcap.h>


int inject_tcp_packet(pcap_t *opcap, struct ipv6hdr *ipv6_hdr, struct iphdr *ip_hdr,
                    struct tcphdr *tcp_hdr, uint8_t *mac, uint16_t vlanID, u_char *data, 
                    int len);
int inject_udp_packet(pcap_t *opcap, struct ipv6hdr *ipv6_hdr, struct iphdr *ip_hdr, 
                    struct udphdr *udp_hdr, uint8_t *mac, uint16_t vlanID, u_char *data, 
                    int len);

#endif
