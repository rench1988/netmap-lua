#ifndef __https_h__
#define __https_h__

#include <stddef.h>


int parse_tls_header(const char *data, size_t data_len, char *hostname, size_t hlen);



#endif

