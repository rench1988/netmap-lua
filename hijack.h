#ifndef __hijack_h__
#define __hijack_h__

#include <sys/types.h>

#define HJK_MAX_PROCESSES  1024

#define version   "1.0.0"

#define MAX_PIPE_BODY  (4098 + 2)

typedef struct {
    pid_t  pid;
    int    fd[2];
    int    core;

    int    status;

    int    index;
} hjk_process_t;

#endif

