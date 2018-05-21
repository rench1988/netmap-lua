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
#include "conf.h"
#include "log.h"
#include "hijack.h"
#include "util.h"
#include "rpc.h"
#include "capture.h"
#include "policy.h"

#define DEFAULT_LOG_FILE  "hijack.log"
#define DEFAULT_LOG_LEVEL "INFO"

#define MAX_PIPE_BUF_SIZE  4089

const char build_time[] = __DATE__ " " __TIME__;

static u_char  program[] = "hjk";
static u_char  master_process[] = "master process";
static u_char  worker_process[] = "worker process";

pid_t   hjk_pid;

int            hjk_process_num;
int            hik_process_slot;
hjk_process_t  hjk_processes[HJK_MAX_PROCESSES];

void helper(void)
{
    printf("net-hijack version: %s built at %s" LINEFEED, version, build_time);
    printf("Usage: net-hijack [-?hc] [-c filename]" LINEFEED 
            LINEFEED
            "Options:" LINEFEED 
            "  -?,-h         : this help" LINEFEED
            "  -c filename   : set configuration file" LINEFEED);
}

void hjk_log_init(hjk_conf_t *conf)
{
    int   ret;
    FILE *fp;

    ret = mkpath(conf->log_file, S_IRWXU);
    if (ret) {
        printf("failed create log directory[%s], exit" LINEFEED, strerror(errno));
        exit(-1);
    }

    fp = fopen(conf->log_file == NULL ? DEFAULT_LOG_FILE : conf->log_file, "a");
    if (!fp) {
        printf("failed create log file[%s], exit" LINEFEED, strerror(errno));
        exit(-1);
    }

    log_set_fp(fp);
    log_set_str_level(conf->log_level == NULL ? DEFAULT_LOG_LEVEL : conf->log_level);
    log_set_quiet(1);
}

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
                log_debug("process %d receive url[%s] add cmd", hjk_pid, tmp);
                policy_add_url(tmp);
                break;
            case udel:
                log_debug("process %d receive url[%s] del cmd", hjk_pid, tmp);
                policy_del_url(tmp);
                break;
            case iadd:
                log_debug("process %d receive ip[%s] add cmd", hjk_pid, tmp);
                policy_add_ip(tmp);
                break;
            case idel:
                log_debug("process %d receive ip[%s] del cmd", hjk_pid, tmp);
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

void hjk_worker_process_cycle(hjk_conf_t *conf, int i)
{
    pthread_t  t_pipe;

    setproctitle((char *)program, (char *)worker_process);

    hik_process_slot = i;

    hjk_pid = getpid();

    log_info("worker process[%d] for %s start to running...", hjk_pid, conf->cap_conf[i].filter);

    close(hjk_processes[hik_process_slot].fd[1]);

    pthread_create(&t_pipe, NULL, hjk_worker_listen_pipe, (void *)(uintptr_t)hjk_processes[hik_process_slot].fd[0]);
    pthread_detach(t_pipe);

    cap_service(&conf->cap_conf[i], conf->cap_dev, conf->net_dev, conf->net_mtu, conf->net_url, conf->net_mac);
}

pid_t hjk_spawn_process(hjk_conf_t *conf, int i)
{
    pid_t pid;

    if (pipe(hjk_processes[i].fd)) {
        goto failed;
    }

    pid = fork();

    switch (pid) {
        case -1: 
            goto failed;
        case 0: 
            hjk_worker_process_cycle(conf, i);
        default:
            break;
    }   
    
    return pid;

failed:
    log_error("failed spawn worker process[%s]", strerror(errno));
    exit(-1);
} 

void hjk_master_process_cycle(hjk_conf_t *conf)
{
    int        i;
    pid_t      pid;
    pthread_t  tid;

    setproctitle((char *)program, (char *)master_process);

    hjk_process_num = conf->cap_num;

    for (i = 0; i < conf->cap_num; i++) {
        pid = hjk_spawn_process(conf, i);
        
        close(hjk_processes[i].fd[0]);

        hjk_processes[i].pid   = pid;
        hjk_processes[i].index = i;
    }

    pthread_create(&tid, NULL, rpc_service, conf);
    pthread_detach(tid);
}

int main(int argc, const char *argv[])
{
    int             opt;
    int             status;
    int             debug;
    pid_t           pid;
    char           *conf_file;
    hjk_conf_t     *conf;

    debug = 0;
    conf_file = NULL;

    while ((opt = getopt(argc, (char * const*)argv, "c:hd")) != -1) {
        switch (opt) {
            case 'c':
                conf_file = strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'h':
            case '?':
                helper();
                break;
            default:
                break;
        }
    }

    if (conf_file == NULL) {
        printf("must assign configuration file" LINEFEED);
        exit(0);
    }

    conf = parse_hijack_conf(conf_file);
    if (!conf) {
        exit(-1);
    }

    print_all_conf(conf);

    hjk_log_init(conf);

    printf("program start..." LINEFEED);

    initproctitle(argc, (char **)argv);

    if (!debug) daemonize();

    turn_on_core();

    hjk_master_process_cycle(conf);

    while ((pid = waitpid(-1, &status, 0)) != -1) {
        log_error("worker process[%d] shutdown[%s]", pid, WIFEXITED(status) ? "exited" : "unexpected");
    }

    log_error("program unexpected exit!!! all worker process Core");

    return 0;
}


