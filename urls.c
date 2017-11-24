#include "urls.h"
#include "uthash.h"
#include <pthread.h>

typedef struct {
    char    url[MAX_URL_LEN];
    size_t  len;

    int     all;

    UT_hash_handle hh;
} url_t;


url_t *urls = NULL;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;


int add_url(const char *url)
{
    url_t  *u;

    if (!url || strlen(url) >= MAX_URL_LEN) return 0;

    pthread_rwlock_wrlock(&rwlock);

    HASH_FIND_STR(urls, url, u);
    if (u) {
        pthread_rwlock_unlock(&rwlock);
        return 0;
    }

    u = (url_t *)calloc(1, sizeof(url_t));

    strncpy(u->url, url, MAX_URL_LEN - 1);
    u->len = strlen(u->url);

    if (u->url[u->len - 1] == URL_SPLIT) {
        //u->url[u->len - 1] = 0;
        u->all = 1;
    }

    HASH_ADD_STR(urls, url, u);

    pthread_rwlock_unlock(&rwlock);

    return 1;
}

int has_url(const char *url)
{
    char    tmp[MAX_URL_LEN];
    char   *start, *end, *pos;
    size_t  ul;
    url_t  *u;

    if (!url) {
        return 0;
    }
    
    ul = strlen(url); 
    if (ul >= MAX_URL_LEN) {
        return 0;
    }

    memset(tmp, 0x00, sizeof(tmp));

    pos = tmp;
    if (!strncmp(url, "http://", 7)) {
        start = (char *)url + 7;
        memcpy(tmp, url, 7);
        pos += 7;
    } else if (!strncmp(url, "https://", 8)) {
        start = (char *)url + 8;
        memcpy(tmp, url, 8);
        pos += 8;
    } else {
        start = (char *)url;
    }

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

int del_url(const char *url)
{
    url_t  *u;

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



