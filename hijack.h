#ifndef __hijack_h__
#define __hijack_h__


#include <net/ethernet.h>

#define MAX_PIPE_BODY  (4098 + 2)

typedef struct hjk_process_s {
    pid_t  pid;
    int    fd[2];
    int    core;

    int    status;
} hjk_process_t;


typedef struct hjk_cycle_s {
    int    affinity;
    int    threads;

    char  *laddr;
    int    lport;

    const char  *iether;
    const char  *nmr;

    hjk_process_t  proc;
} hjk_cycle_t;

#endif

