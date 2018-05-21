#include "policy.h"
#include "uthash.h"
#include <pthread.h>
#include <arpa/inet.h>

typedef struct policy_url_s {
    char    url[MAX_URL_LEN];
    size_t  len;

    int     all;

    UT_hash_handle hh;
} policy_url_t;

typedef struct policy_ip_s {
    uint32_t  address;

    UT_hash_handle hh;
} policy_ip_t;


policy_url_t *urls = NULL;
policy_ip_t  *ips  = NULL;

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

int policy_add_url(const char *url)
{
    policy_url_t  *u;

    if (!url || strlen(url) >= MAX_URL_LEN) return 0;

    pthread_rwlock_wrlock(&rwlock);

    HASH_FIND_STR(urls, url, u);
    if (u) {
        pthread_rwlock_unlock(&rwlock);
        return 0;
    }

    u = (policy_url_t *)calloc(1, sizeof(policy_url_t));

    strncpy(u->url, url, MAX_URL_LEN - 1);
    u->len = strlen(u->url);

    if (u->url[u->len - 1] == URL_SPLIT) {
        u->all = 1;
    }

    HASH_ADD_STR(urls, url, u);

    pthread_rwlock_unlock(&rwlock);

    return 1;
}

int policy_url_meet(const char *url)
{
    char    tmp[MAX_URL_LEN];
    char   *start, *end, *pos;
    size_t  ul;

    policy_url_t  *u;

    if (!url) {
        return 0;
    }
    
    ul = strlen(url); 
    if (ul >= MAX_URL_LEN) {
        return 0;
    }

    memset(tmp, 0x00, sizeof(tmp));

    pos   = tmp;
    start = (char *)url;

    pthread_rwlock_rdlock(&rwlock);

    HASH_FIND_STR(urls, url, u);
    if (u) {
        pthread_rwlock_unlock(&rwlock);
        return 1;
    }

    end = strchr(start, URL_SPLIT);
    for (; end; end = strchr(start, URL_SPLIT)) {
        memcpy(pos, start, end - start + 1);

        HASH_FIND_STR(urls, tmp, u);
        if (u && u->all) {
            pthread_rwlock_unlock(&rwlock);
            return 1;
        }

        pos += (end - start + 1);
        start = end + 1;
    }

    pthread_rwlock_unlock(&rwlock);

    return 0;
}

int policy_del_url(const char *url)
{
    policy_url_t  *u;

    if (!url || strlen(url) >= MAX_URL_LEN) {
        return 0;
    }

    pthread_rwlock_wrlock(&rwlock);
    
    HASH_FIND_STR(urls, url, u);
    if (u) {
        HASH_DEL(urls, u);
        pthread_rwlock_unlock(&rwlock);
        return 1;
    }

    pthread_rwlock_unlock(&rwlock);

    return 0;
}


int policy_add_ip(const char *ip)
{
    struct in_addr  in;
    policy_ip_t    *p;

    if (!ip) {
        return 1;
    }
    
    if (inet_pton(AF_INET, ip, &in) != 1) {
        return 1;
    }

    pthread_rwlock_wrlock(&rwlock);

    HASH_FIND(hh, ips, &in.s_addr, sizeof(in.s_addr), p);
    if (p) {
        pthread_rwlock_unlock(&rwlock);
        return 0;
    }

    p = (policy_ip_t *)calloc(1, sizeof(policy_ip_t));
    p->address = in.s_addr;

    HASH_ADD(hh, ips, address, sizeof(uint32_t), p);

    pthread_rwlock_unlock(&rwlock);

    return 0;
}

int policy_del_ip(const char *ip)
{
    struct in_addr  in;
    policy_ip_t    *p;

    if (!ip) {
        return 1;
    }

    if (inet_pton(AF_INET, ip, &in) != 1) {
        return 1;
    }        

    pthread_rwlock_wrlock(&rwlock);

    HASH_FIND(hh, ips, &in.s_addr, sizeof(in.s_addr), p);
    if (!p) {
        pthread_rwlock_unlock(&rwlock);
        return 0;
    }

    HASH_DEL(ips, p);
    free(p);

    pthread_rwlock_unlock(&rwlock);

    return 0;
}

int policy_ip_meet(uint32_t ip)
{
    policy_ip_t    *p;

    pthread_rwlock_rdlock(&rwlock);

    HASH_FIND(hh, ips, &ip, sizeof(ip), p);
    if (p) {
        pthread_rwlock_unlock(&rwlock);
        return 1;
    }

    pthread_rwlock_unlock(&rwlock);  
    return 0;
}



