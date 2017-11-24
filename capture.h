#ifndef __capture_h__
#define __capture_h__

typedef struct {
    int    state;
    pid_t  pid;
} cap_process_t;


void *cap_service(void *arg);

#endif

