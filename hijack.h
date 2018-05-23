#ifndef __hijack_h__
#define __hijack_h__


#include <net/ethernet.h>

#define MAX_PIPE_BODY  (4098 + 2)

#define MAX_IFNAMELEN 64

typedef struct {
    pid_t  pid;
    int    fd[2];
    int    core;

    int    status;
} hjk_process_t;


typedef struct {
    int   affinity;
    int   burst;

    char  *laddr;
    int    lport;

    char  iether[MAX_IFNAMELEN];
    char  oether[MAX_IFNAMELEN];

    char  *nmr;
    const char  *http_302_str;

    struct ether_addr src_mac;
    struct ether_addr dst_mac;
} hjk_conf_t;

#endif

