#ifndef __dns_h__
#define __dns_h__

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define DNS_HEADER_SIZE       12
#define DNS_LABEL_MAX_SIZE    63
#define DNS_PACKET_MAX_SIZE   512
#define DNS_DOMAIN_MAX_SIZE   255

enum {
	/* Operation Code */
    dns_query  = 0,  /* standard query */
    dns_iquery = 1,  /* inverse query */
    dns_status = 2,  /* server status request */
    dns_notify = 4,  /* request zone transfer */
    dns_update = 5   /* change resource records */
};

enum {
	dns_qr_query = 0,
	dns_qr_response = 1
};

enum {
	dns_op_query  = 0,
	dns_op_iquery = 1,
	dns_op_status = 2,
	dns_op_notify = 4,
	dns_op_updata = 5
};

enum {
	dns_rc_ok = 0,
	dns_rc_formatError = 1,
	dns_rc_serverFailure = 2,
	dns_rc_nameError = 3,
	dns_rc_notImplememted = 4,
	dns_rc_refused = 5
};

enum {
    dns_rr_a  = 1,
    dns_rr_ns = 2,
    dns_rr_cname = 5,
    dns_rr_soa = 6,
    dns_rr_ptr = 12,
    dns_rr_mx = 15,
    dns_rr_txt = 16,
    dns_rr_aaaa = 28,
    dns_rr_srv = 33
};

struct dns_header {
	uint16_t  id;

	uint8_t  qr;
	uint8_t  opcode;
	uint8_t  aa;
	uint8_t  tc;
	uint8_t  rd;
	uint8_t  ra;
	uint8_t  rcode;

	uint16_t qdCount;
	uint16_t anCount;
	uint16_t nsCount;
	uint16_t arCount;
};

struct dns_question {
	char       name[DNS_DOMAIN_MAX_SIZE];
	uint16_t   type;
	uint16_t   class;

	struct dns_question *next;
};

struct dns_resourceRecord {
    char      *name;
    uint16_t   type;
    uint16_t   class;
    uint16_t   ttl;
    uint16_t   datalen;
	uint8_t    data[16];

    struct dns_resourceRecord *next; 
};

typedef struct {
	struct dns_header     header;
	struct dns_question  *questions;

	struct dns_resourceRecord *answers;
	struct dns_resourceRecord *authorities;
	struct dns_resourceRecord *additionals;
} dns_message_t;


int dns_message_parse(u_char *data, size_t datalen, dns_message_t *msg);
void dns_message_free(dns_message_t *msg);
int dns_gen_response(dns_message_t *msg, struct dns_question *q, char *dst, size_t dstlen);

#endif

