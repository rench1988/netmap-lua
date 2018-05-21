#ifndef __policy_h__
#define __policy_h__

#include <stddef.h>
#include <stdint.h>

#define MAX_URL_LEN  4098

#define URL_SPLIT  '/'

typedef enum {
    uadd = 1,  //add url
    udel,      //del url
    iadd,      //add ip address
    idel       //del ip address
} utype;

int policy_add_url(const char *url);
int policy_del_url(const char *url);
int policy_url_meet(const char *url);
int policy_add_ip(const char *ip);
int policy_del_ip(const char *ip);
int policy_ip_meet(uint32_t ip);

#endif

