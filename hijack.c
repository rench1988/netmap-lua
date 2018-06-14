/**
 * @author [rench]
 * @create date 2017-11-21 09:53:44
 * @modify date 2017-11-21 09:53:44
 * @desc [net-hiject]
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <netinet/ether.h>
#include "log.h"
#include "hijack.h"
#include "util.h"
#include "capture.h"
#include "conf.h"

#define HIJACK_LOG_FILE  "hjk.log"

#define MAX_PIPE_BUF_SIZE  4089

static const u_char  version[]   = "1.0.0";
static const u_char  buildTime[] = __DATE__ " " __TIME__;

static const u_char  program[] = "hjk";
static const u_char  master_process[] = "master process";
static const u_char  worker_process[] = "worker process";

void helper(void)
{
    printf("netmap-cap version: %s built at %s\n", version, buildTime);
    printf("Usage: netmap-cap [-?haiClpdt]\n"
            "Options:\n" 
            "  -?,-h            : this help\n"
            "  -a cpu id	    : use setaffinity\n"
            "  -i interface     : set capture interface\n"
            "  -C netmap opt    : set netmap desc option\n"
            "  -l address       : rpc listen address\n"
            "  -p port          : rpc listen port\n"
            "  -t threads       : worker threads\n"
            "  -d debug         : debug mode\n");
}

void hjk_log_init(int debug)
{
    FILE *fp;

    fp = fopen(HIJACK_LOG_FILE, "w");
    if (!fp) {
        printf("failed create log file[%s], exit\n", strerror(errno));
        exit(-1);
    }

    log_set_fp(fp);
    log_set_level(debug ? LOG_DEBUG : LOG_INFO);
    log_set_quiet(1);
}

#if 0
int hjk_worker_process_pipe_msg(char *buf, int n)
{
    static const char sp = '\n';

    int   tn = n;
    char *start, *end;
    char  tmp[MAX_PIPE_BUF_SIZE];
    
    for (start = buf; (end = memchr(start, sp, n)) != NULL; start = end + 1) {
        if (end - start - 1 <= 0 || end - start - 1 >= MAX_PIPE_BUF_SIZE) {
            continue;
        }

        memcpy(tmp, start + 1, end - start - 1);
        *(tmp + (end - start - 1)) = 0;

        switch (*start - '0') {
            case uadd:
                log_info("process %d receive url[%s] add cmd", hjk_pid, tmp);
                policy_add_url(tmp);
                break;
            case udel:
                log_info("process %d receive url[%s] del cmd", hjk_pid, tmp);
                policy_del_url(tmp);
                break;
            case iadd:
                log_info("process %d receive ip[%s] add cmd", hjk_pid, tmp);
                policy_add_ip(tmp);
                break;
            case idel:
                log_info("process %d receive ip[%s] del cmd", hjk_pid, tmp);
                policy_del_ip(tmp);
                break;
            default:
                break;
        }
            
        tn = tn - (end - start + 1);
        if (tn <= 0) {
            return n;
        }
    }

    return start - buf;
}

void *hjk_worker_listen_pipe(void *arg)
{
    uintptr_t   fd = (uintptr_t)arg;

    int      parserd;
    ssize_t  n;
    char     buf[MAX_PIPE_BUF_SIZE];
    int      wpos = 0;

    while (1) {
        n = read(fd, buf + wpos, MAX_PIPE_BUF_SIZE - wpos);
        if (n <= 0) {
            log_fatal("worker process pipe broken[%s], exit", strerror(errno));
            exit(-1);
        }

        parserd = hjk_worker_process_pipe_msg(buf, n);
        if (parserd != n) {
            wpos = n - parserd;
            memmove(buf, buf + parserd, n - parserd);
        } else {
            wpos = 0;
        }
    }

    return NULL;
}
#endif

void hjk_worker_process_cycle(hjk_cycle_t *cycle)
{
   // pthread_t  t_pipe;

    setproctitle((char *)program, (char *)worker_process);

    log_info("worker process[%d] start to running...", cycle->proc.pid);

    close(cycle->proc.fd[1]);

    //pthread_create(&t_pipe, NULL, hjk_worker_listen_pipe, (void *)(uintptr_t)hjk_process.fd[0]);
    //pthread_detach(t_pipe);

    cap_service(cycle);
}

pid_t hjk_spawn_process(hjk_cycle_t *cycle)
{
    pid_t pid;

    if (pipe(cycle->proc.fd)) {
        goto failed;
    }

    pid = fork();

    cycle->proc.pid = pid;

    switch (pid) {
        case -1: 
            goto failed;
        case 0: 
            hjk_worker_process_cycle(cycle);
            break;
        default:
            break;
    }   
    
    return pid;

failed:
    log_error("failed spawn worker process[%s]", strerror(errno));
    exit(-1);
} 

void hjk_master_process_cycle(hjk_cycle_t *cycle)
{
    int        status;
    pid_t      pid;
    //pthread_t  tid;

    setproctitle((char *)program, (char *)master_process);

    pid = hjk_spawn_process(cycle);
        
    close(cycle->proc.fd[0]);

    cycle->proc.pid = pid;

    //pthread_create(&tid, NULL, rpc_service, cycle);
    //pthread_detach(tid);
    waitpid(pid, &status, -1);
}

int main(int argc, const char *argv[])
{
    int             opt;
    int             status;
    pid_t           pid;
    hjk_cycle_t     cycle;
    char           *file;

    bzero(&cycle, sizeof(cycle));

    while ((opt = getopt(argc, (char * const*)argv, "c:h")) != -1) {
        switch (opt) {
            case 'c':
                file = optarg;
                break;
            case 'h':
            case '?':
                helper();
                break;
            default:
                printf("unknown option %c\n", opt);
                break;
        }
    }

    if (parse_conf(file, &cycle)) {
        return -1;
    }

    hjk_log_init(cycle.debug);

    printf("program start...\n");

    initproctitle(argc, (char **)argv);

    daemonize();

    setrlimit_core();

    hjk_master_process_cycle(&cycle);

    while ((pid = waitpid(-1, &status, 0)) != -1) {
        log_error("worker process[%d] shutdown[%s]", pid, WIFEXITED(status) ? "exited" : "unexpected");
    }

    log_error("program unexpected exit");

    return 0;
}


