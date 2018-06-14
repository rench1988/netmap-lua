#ifndef __gtpu_h__
#define __gtpu_h__

#include <stdint.h>
#include <stddef.h>

typedef unsigned char u_char;

typedef struct gtpuHdr_s {
	uint8_t  version_flags;
	uint8_t  msg_type;
	uint16_t tot_len;
	uint32_t teid;
//	uint16_t seq_no;		/**< Optional fields if E, S or PN flags set */
//	uint8_t npdu_no;
//	uint8_t next_ext_hdr_type;
} __attribute__((__packed__)) gtpuHdr_t;

int gtpu_header_parse(u_char *data, size_t len, gtpuHdr_t *gtppHdr);


#endif
