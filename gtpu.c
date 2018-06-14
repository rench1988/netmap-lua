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
#define GTPu_HTEID_OFFSET   4

#define GTPu_HEADER_MANDATORY_LEN  8

int gtpu_header_parse(u_char *data, size_t len, gtpuHdr_t *gtppHdr)
{
    uint8_t  el;
    size_t   parsered = 0;

    memset((char *)gtppHdr, 0, sizeof(gtpuHdr_t));

    if (len < GTPu_HEADER_MANDATORY_LEN) {
        return -1;
    }

    memcpy(gtppHdr, data, GTPu_HEADER_MANDATORY_LEN);

    if ((gtppHdr->version_flags & 0xf0) != 0x30) {
        return -1;
    }

    gtppHdr->tot_len = ntohs(gtppHdr->tot_len);
    gtppHdr->teid = ntohl(gtppHdr->teid);

    if (gtppHdr->tot_len + GTPu_HEADER_MANDATORY_LEN != len) {
        return -1;
    }

    //data += GTPu_HEADER_MANDATORY_LEN;
    parsered += GTPu_HEADER_MANDATORY_LEN;

    if (gtppHdr->version_flags & (GTPu_S_FLAG | GTPu_E_FLAG | GTPu_PN_FLAG)) {
        //data += 4;
        parsered += 4;
    }

    if (len <= parsered) {
        return -1;
    }

    if (gtppHdr->version_flags & GTPu_E_FLAG) {
        while (data[parsered - 1]) {
            if (len <= parsered) {
                return -1;
            }

            el = data[parsered] * 4;

            //data += el;
            parsered += el;

            if (len <= parsered) {
                return -1;
            }
        }
    }

    return parsered;    
}
