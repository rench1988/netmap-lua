#include "gtpu.h"
#include <string.h>
#include <arpa/inet.h>

#define GTPu_VERSION	0x20
#define GTPu_PT_FLAG	0x10
#define GTPu_E_FLAG		0x04
#define GTPu_S_FLAG		0x02
#define GTPu_PN_FLAG	0x01

#define GTPu_HTYPE_OFFSET   1
#define GTPu_HLENTH_OFFSET  2
#define GTPu_HTEID_OFFSET   3

#define GTPu_HEADER_MANDATORY_LEN  8

int gtpu_header_parse(u_char *data, size_t len, gtpuHdr_t *gtppHdr)
{
    //uint8_t el;
    size_t  parsered = 0;

    memset((char *)gtppHdr, 0, sizeof(gtpuHdr_t));

    if (len < GTPu_HEADER_MANDATORY_LEN) {
        return -1;
    }

    gtppHdr->version_flags = *data;
    gtppHdr->msg_type = *(data + GTPu_HTYPE_OFFSET);
    gtppHdr->tot_len = ntohs(*((uint16_t *)(data + GTPu_HLENTH_OFFSET)));
    gtppHdr->teid = *((uint32_t *)(data + GTPu_HTEID_OFFSET));

    data += GTPu_HEADER_MANDATORY_LEN;
    parsered += GTPu_HEADER_MANDATORY_LEN;

    if (gtppHdr->version_flags & GTPu_S_FLAG) {
        data += 4;
        parsered += 4;
    }
/*
    if (gtppHdr->version_flags & GTPu_PN_FLAG) {
        data += 1;
        parsered += 1;
    }
*/
    if (len - parsered <= 0) {
        return -1;
    }
/*
    if (gtppHdr->version_flags & GTPu_E_FLAG) {
        while (data[parsered]) {
            data++;
            parsered++;

            if (len - parsered <= 0) {
                return -1;
            }

            el = data[parsered] >> 2;

            data += el;
            parsered += el;

            if (len - parsered <= 0) {
                return -1;
            }
        }
    }
*/
    return parsered;    
}



