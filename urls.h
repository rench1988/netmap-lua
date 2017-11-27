#ifndef __urls_h__
#define __urls_h__

#define MAX_URL_LEN  4098

#define URL_SPLIT  '/'

int add_url(const char *url);
int del_url(const char *url);
int has_url(const char *url);

#endif

