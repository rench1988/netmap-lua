#include "inject.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#define NET_INJECT_MIN_MTU          552 
#define NET_INJECT_MAX_HEADER_SIZE  40

static int inject_src_one_packet(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr,
                                    u_char *data, size_t datalen, size_t offset)
{
    int      size;
    uint16_t tcp_dl;

    size = LIBNET_IPV4_H + LIBNET_TCP_H + datalen;
    tcp_dl = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - tcp_hdr->doff * 4;

    injector->tcp_tag = libnet_build_tcp(ntohs(tcp_hdr->dest),                       /* source port	        */
                                         ntohs(tcp_hdr->source),                     /* dest port	        */
                                         ntohl(tcp_hdr->ack_seq) + offset,           /* seq number	        */
                                         ntohl(tcp_hdr->seq) + tcp_dl,               /* ack number	        */
#ifdef WITH_FIN        
                                         TH_FIN|TH_PUSH|TH_ACK,                      /* control	            */ 
#else
                                         TH_PUSH|TH_ACK,
#endif
                                         tcp_hdr->window,                            /* window		        */
                                         0,                                          /* checksum TBD        */
                                         0,                                          /* urgent?	            */
                                         LIBNET_TCP_H + datalen,                     /* TCP PDU size        */
                                         data,				                         /* data		        */
                                         datalen,	          			             /* datasize	        */
                                         injector->l,                                /* libnet context      */
                                         injector->tcp_tag);                         /* libnet protocol tag */
    if (injector->tcp_tag == -1) {
        goto failed;
    }

    injector->ipv4_tag = libnet_build_ipv4(size,                  /* total packet len	   */
                                           0,                     /* tos			       */
                                           ip_hdr->id,            /* id			           */
                                           0,                     /* frag			       */
                                           51,                    /* ttl			       */
                                           IPPROTO_TCP,           /* proto		           */
                                           0,                     /* checksum TBD          */
                                           ip_hdr->daddr,         /* saddr		           */
                                           ip_hdr->saddr,         /* daddr		           */
                                           NULL,    			  /* data			       */
                                           0,      				  /* datasize?	           */
                                           injector->l,           /* libnet context        */
                                           injector->ipv4_tag);   /* libnet protocol tag   */
    if (injector->ipv4_tag == -1) {
        goto failed;
    }

    injector->ether_tag = libnet_build_ethernet((void *)injector->dmac,     // dst
                                                (void *)injector->smac,     // src
                                                ETHERTYPE_IP,               // prot
                                                NULL,                       // payload
                                                0,                          // paylen
                                                injector->l,                // libnet
                                                injector->ether_tag);       // ptag
    if (injector->ether_tag == -1) {
        goto failed;
    } 

	if(libnet_write(injector->l) == -1) {
        goto failed;
    }    

    return 0;

failed:
    snprintf(injector->errbuf, LIBNET_ERRBUF_SIZE, "%s", libnet_geterror(injector->l));
    return -1;
}

net_inject_t *inject_new(const char *dev, char *str_mac, uint16_t mtu, char *errbuf, size_t errlen)
{
    int                       length;
    uint8_t                  *dmacaddr;
    char                      lerrbuf[LIBNET_ERRBUF_SIZE];
    libnet_t                 *l;
    net_inject_t             *ni;
    struct libnet_ether_addr *mac_addr;

    l = libnet_init(LIBNET_LINK_ADV, dev, lerrbuf);
    if (l == NULL) {
        goto failed;
    }

    mtu = mtu < NET_INJECT_MIN_MTU ? NET_INJECT_MIN_MTU : mtu;

    ni = (net_inject_t *)calloc(1, sizeof(net_inject_t));

    mac_addr = libnet_get_hwaddr(l);

    dmacaddr = libnet_hex_aton(str_mac, &length);
    if (dmacaddr == NULL) {
        snprintf(lerrbuf, LIBNET_ERRBUF_SIZE, "mac address[%s] is illegal", str_mac);
        goto failed;
    }

    ni->l = l;
    ni->data_tag = LIBNET_PTAG_INITIALIZER;
    ni->tcp_tag = LIBNET_PTAG_INITIALIZER;
    ni->ipv4_tag = LIBNET_PTAG_INITIALIZER;
    ni->ether_tag = LIBNET_PTAG_INITIALIZER;
    ni->mss = mtu - NET_INJECT_MAX_HEADER_SIZE;

    memcpy(ni->smac, mac_addr->ether_addr_octet, 6);
    memcpy(ni->dmac, dmacaddr, 6);

    free(dmacaddr);

    return ni;

failed:
    snprintf(errbuf, errlen, "%s", lerrbuf);
    return NULL;
}

int inject_src_data(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr,
                     u_char *data, size_t datalen)
{
    int    sended;
    size_t pload;

    sended = 0;

    while (datalen > 0) {
        pload = datalen > injector->mss ? injector->mss : datalen;

        if (inject_src_one_packet(injector, ip_hdr, tcp_hdr, data + sended, pload, sended)) {
            return -1;
        }

        sended += pload;
        datalen -= pload;        
    }

    return 0;
}

int inject_src_rst(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr)
{
    uint16_t tcp_dl;

    static const char *data = "hello";
    size_t datalen = 5;

    tcp_dl = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - tcp_hdr->doff * 4;

    injector->tcp_tag = libnet_build_tcp(ntohs(tcp_hdr->dest),   
                            ntohs(tcp_hdr->source),                 
                            ntohl(tcp_hdr->ack_seq),                 
                            ntohl(tcp_hdr->seq) + tcp_dl,            
                            TH_PUSH|TH_ACK, //TH_RST | TH_ACK | TH_PUSH,
                            tcp_hdr->window,                           
                            0,                                       
                            0,                                       
                            LIBNET_TCP_H + datalen,	                        
                            (uint8_t *)data,                                  
                            datalen,                                    
                            injector->l,                             
                            injector->tcp_tag); 
    if (injector->tcp_tag == -1) {
        goto failed;
    }

	injector->ipv4_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + datalen, 
		                    0,                                
		                    ip_hdr->id,                    
		                    0,                               
		                    51,							      
		                    IPPROTO_TCP,                      
		                    0,                                
		                    ip_hdr->daddr,            
		                    ip_hdr->saddr,            
		                    NULL,                             
		                    0,                                
		                    injector->l,                       
		                    injector->ipv4_tag);                     
	if (injector->ipv4_tag == -1) {
		goto failed;
    }
    
	injector->ether_tag = libnet_build_ethernet((void *)injector->dmac,  
		                    (void *)injector->smac,                           
		                    ETHERTYPE_IP,                             
		                    NULL,                                    
		                    0,                                        
		                    injector->l,                              
		                    injector->ether_tag);                                
	if (injector->ether_tag == -1) {
		goto failed;
	}

	if(libnet_write(injector->l) == -1) {
        goto failed;
    }

    return 0;

failed:
    snprintf(injector->errbuf, LIBNET_ERRBUF_SIZE, "%s", libnet_geterror(injector->l));
    return -1;
}

int inject_dst_rst(net_inject_t *injector, struct iphdr *ip_hdr, struct tcphdr *tcp_hdr)
{
	injector->tcp_tag = libnet_build_tcp(ntohs(tcp_hdr->source),      
		                    ntohs(tcp_hdr->dest),                       
		                    ntohl(tcp_hdr->seq),                            
                            ntohl(tcp_hdr->ack_seq),                            
                            TH_FIN, //TH_RST,
		                    tcp_hdr->window,                   
		                    0,                             
		                    0,                             
		                    LIBNET_TCP_H,                  
		                    NULL,                          
		                    0,                             
		                    injector->l,                    
		                    injector->tcp_tag);                     
	if (injector->tcp_tag == -1) {
		goto failed;
    }
    
	injector->ipv4_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 
		                    0,                            
		                    ip_hdr->id,                
		                    0,                            
		                    51,							  
		                    IPPROTO_TCP,                  
		                    0,                            
		                    ip_hdr->saddr,        
		                    ip_hdr->daddr,        
		                    NULL,                         
		                    0,                            
		                    injector->l,                   
		                    injector->ipv4_tag);                    
	if (injector->ipv4_tag == -1) {
		goto failed;
	}    

	injector->ether_tag = libnet_build_ethernet((void*)injector->dmac,  
		                    (void*)injector->smac,                           
		                    ETHERTYPE_IP,                            
		                    NULL,                                    
		                    0,                                       
		                    injector->l,                              
		                    injector->ether_tag);                               
	if (injector->ether_tag == -1) {
		goto failed;
	}

	if(libnet_write(injector->l) == -1) {
		goto failed;
	}
    
    return 0;
    
failed:
    snprintf(injector->errbuf, LIBNET_ERRBUF_SIZE, "%s", libnet_geterror(injector->l));
    return -1;
}
