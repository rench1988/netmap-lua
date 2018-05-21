#include "dns.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

static int dns_encode_domain(const char *domain, char *dst, size_t dstlen)
{
    int  i, len;
    const char *beg;
    const char *pos;

    i = 0;
    len = 0;
    beg = domain;

    while ((pos = strchr(beg, '.'))) {
        len = pos - beg;
        if (dstlen - i < len + 1) {
            return -1;
        }

        dst[i++] = len;
        memcpy(dst + i, beg, len);
        i += len;

        beg = pos + 1;
    }

    len = strlen(domain) - (beg - domain);
    if (dstlen - i < len + 2) {
        return -1;
    }

    dst[i++] = len;
    memcpy(dst + i, beg, len);
    i += len;

    dst[i++] = 0;

    return i;
}

static int dns_encode_rr(dns_message_t *msg, char *dst, size_t dstlen)
{
    int  cur, l;
    struct dns_resourceRecord *rr;

    cur = 0;
    rr = msg->answers;

    while (rr) {
        l = dns_encode_domain(rr->name, dst + cur, dstlen - cur);
        if (l == -1) {
            return -1;
        }

        cur += l;
        if (dstlen - cur < 10) {
            return -1;
        }

        *((uint16_t *)(dst + cur)) = htons(rr->type);
        *((uint16_t *)(dst + cur + 2)) = htons(rr->class);
        *((uint32_t *)(dst + cur + 4)) = htonl(rr->ttl);
        *((uint16_t *)(dst + cur + 8)) = htons(rr->datalen);

        cur += 10;
        if (dstlen - cur < rr->datalen) {
            return -1;
        }

        memcpy(dst + cur, rr->data, rr->datalen);

        cur += rr->datalen;
        rr = rr->next;
    }

    return cur;
}

static int dns_resp_msg_encode(dns_message_t *msg, char *dst, size_t dstlen)
{
    int    l, cur;
    struct dns_question *q;

    if (dstlen <= DNS_HEADER_SIZE) {
        return -1;
    }

    cur = 0;

    *(uint16_t *)dst = htons(msg->header.id);
    *(dst + 2) |= 0x80;
    *(dst + 2) |= 0x04;
    *(dst + 3) &= 0xf0;

    *((uint16_t *)(dst + 4)) = htons(msg->header.qdCount);
    *((uint16_t *)(dst + 6)) = htons(msg->header.anCount);

    cur += DNS_HEADER_SIZE;

    q = msg->questions;
    while (q) {
        l = dns_encode_domain(q->name, dst + cur, dstlen - cur); 
        if (l == -1) {
            return -1;
        }

        cur += l;
        if (dstlen - cur < 4) {
            return -1;
        }

        *((uint16_t *)(dst + cur)) = htons(q->type);
        *((uint16_t *)(dst + cur + 2)) = htons(q->class);

        cur += 4;

        q = q->next;
    }

    return cur + dns_encode_rr(msg, dst + cur, dstlen - cur);
}

static void dns_gen_msg(dns_message_t *msg, struct dns_question *q) 
{
    struct dns_resourceRecord *rr;

    msg->header.qr = 1; 
    msg->header.aa = 1; 
    msg->header.ra = 0;
    msg->header.rcode = dns_rc_ok;

    msg->header.anCount = 1;
    msg->header.nsCount = 0;
    msg->header.arCount = 0;

    rr = calloc(1, sizeof(struct dns_resourceRecord));
    rr->name = q->name;
    rr->type = q->type;
    rr->class = q->class;
    rr->ttl = 60 * 60;
    rr->datalen = 4;
    rr->data[0] = 192;
    rr->data[1] = 168;
    rr->data[2] = 1;
    rr->data[3] = 7;
    rr->next = NULL;
    
    msg->answers = rr;
}

static int dns_domain_parse(u_char *data, size_t datalen, char *dst, size_t dstlen) 
{
    int i, s, l;

    i = 0;
    s = 0;
    l = 0;

    while (data[i]) {
        l = data[i];

        if (l >= dstlen - s - 1) {
            return -1;
        }
        if (s != 0) {
            dst[s++] = '.';
        }

        ++i;
        memcpy(dst + s, data + i, l);  
        s += l;
        i += l;      
    }

    dst[s] = 0;

    return i + 1;
}

static void dns_header_parse(u_char *data, struct dns_header *header)
{
    header->id = ntohs(*((uint16_t *)data));

    header->qr = (*(data + 2) & 0x80) >> 7;
    header->opcode = (*(data + 2) & 0x78) >> 3;
    header->aa = (*(data + 2) & 0x04) >> 2;
    header->tc = (*(data + 2) & 0x02) >> 1;
    header->rd = (*(data + 2) & 0x01);
    header->ra = (*(data + 3) & 0x80) >> 7;
    header->rcode = (*(data + 3) & 0x0f);

    header->qdCount = ntohs(*((uint16_t *)(data + 4)));
    header->anCount = ntohs(*((uint16_t *)(data + 6)));
    header->nsCount = ntohs(*((uint16_t *)(data + 8)));
    header->arCount = ntohs(*((uint16_t *)(data + 10)));
}

static int dns_question_parse(u_char *data, size_t datalen, struct dns_question *qs)
{
    int  ret;

    ret = dns_domain_parse(data, datalen, qs->name, sizeof(qs->name));
    if (ret == -1) {
        return -1;
    }

    qs->type = ntohs(*((uint16_t *)(data + ret)));
    qs->class = ntohs(*((uint16_t *)(data + ret + 2)));

    return 0;
}

int dns_gen_response(dns_message_t *msg, struct dns_question *q, char *dst, size_t dstlen)
{
    dns_gen_msg(msg, q);

    return dns_resp_msg_encode(msg, dst, dstlen);
}

int dns_message_parse(u_char *data, size_t datalen, dns_message_t *msg)
{
    int                  i;
    int                  ret;
    struct dns_question *qs;

    if (datalen < DNS_HEADER_SIZE || datalen > DNS_PACKET_MAX_SIZE) {
        return -1;
    }

    dns_header_parse(data, &msg->header);

    if (msg->header.qr != dns_qr_query || msg->header.opcode != dns_op_query) {
        return -1;
    }

    data += DNS_HEADER_SIZE;
    datalen -= DNS_HEADER_SIZE;

    qs = msg->questions;
    for (i = 0; i < msg->header.qdCount; ++i) {
        struct dns_question *q = calloc(1, sizeof(struct dns_question));
        
        q->next = qs;
        msg->questions = q;

        ret = dns_question_parse(data, datalen, q);
        if (ret == -1) {
            goto failed;
        }

        data += ret;
        datalen -= ret;
        qs = q;
    }

    return 0;

failed:
    dns_message_free(msg);
    return -1;
}

void dns_message_free(dns_message_t *msg)
{
    struct dns_resourceRecord *rr, *rnext;
    struct dns_question       *qs, *qnext;

    qs = msg->questions;
    while (qs != NULL) {
        qnext = qs->next;
        free(qs);
        qs = qnext;
    }

    rr = msg->answers;
    while (rr != NULL) {
        rnext = rr->next;
        free(rr);
        rr = rnext;
    }

    return;
}
