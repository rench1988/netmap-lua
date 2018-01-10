#include "https.h"
#include <string.h>

#define SERVER_NAME_LEN                  256
#define TLS_HEADER_LEN                   5
#define TLS_HANDSHAKE_CONTENT_TYPE       0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO  0x01


#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static int 
parse_extensions(const char *data, size_t data_len, char *hostname, size_t hlen);
static int
parse_server_name_extension(const char *data, size_t data_len, char *hostname, size_t hlen);


int 
parse_tls_header(const char *data, size_t data_len, char *hostname, size_t hlen)
{
    char   tls_content_type;
    char   tls_version_major;
    char   tls_version_minor;

    size_t pos = TLS_HEADER_LEN;
    size_t len;  

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return -1;    

    /* 
    * SSL 2.0 compatible Client Hello
    * High bit of first byte (length) and content type is Client Hello
    * See RFC5246 Appendix E.2
    */
    if (data[0] & 0x80 && data[2] == 1) {
        //"Received SSL 2.0 Client Hello which can not support SNI.");
        return -1;
    }

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        //"Request did not begin with TLS handshake.");
        return -1;
    }
    
    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        //"Received SSL %d.%d handshake which can not support SNI.", tls_version_major, tls_version_minor);
        return -1;
    }
    
    /* TLS record length */
    len = ((unsigned char)data[3] << 8) +
        (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);    

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;
    
    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return -1;
    }    
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        //"Not a client hello");
        return -1;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;    

    /* Session ID */
    if (pos + 1 > data_len)
        return -1;    
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return -1;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return -1;    
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        //"Received SSL 3.0 handshake without extensions");
        return -1;
    }
    
    /* Extensions */
    if (pos + 2 > data_len)
        return -1;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2; 
    
    if (pos + len > data_len)
        return -1;
    
    return parse_extensions(data + pos, len, hostname, hlen);
}

static int 
parse_extensions(const char *data, size_t data_len, char *hostname, size_t hlen) 
{
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((unsigned char)data[pos + 2] << 8) +
            (unsigned char)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return -1;
            return parse_server_name_extension(data + pos + 4, len, hostname, hlen);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -1;

    return -1;
}

static int
parse_server_name_extension(const char *data, size_t data_len, char *hostname, size_t hlen) 
{
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((unsigned char)data[pos + 1] << 8) +
            (unsigned char)data[pos + 2];

        if (pos + 3 + len > data_len)
            return -1;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                if (len >= hlen) {
                    return -1;
                }
    
                strncpy(hostname, data + pos + 3, len);

                hostname[len] = 0;

                return len;
            default:
                //("Unknown server name extension name type: %d", data[pos]);
                break;
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -1;

    return -1;
}
