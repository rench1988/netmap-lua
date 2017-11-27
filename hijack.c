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
#include <errno.h>
#include "conf.h"
#include "log.h"
#include "hijack.h"
#include "util.h"
#include "rpc.h"
#include "capture.h"

#define DEFAULT_LOG_FILE  "hijack.log"
#define DEFAULT_LOG_LEVEL "INFO"

//hijack_cycle_t *cycle;

const char build_time[] = __DATE__ " " __TIME__;

void helper(void)
{
    printf("net-hijack version: %s built at %s" LINEFEED, version, build_time);
    printf("Usage: net-hijack [-?hc] [-c filename]" LINEFEED 
            LINEFEED
            "Options:" LINEFEED 
            "  -?,-h         : this help" LINEFEED
            "  -c filename   : set configuration file" LINEFEED);
}

void hijack_log_init(hijack_conf_t *conf)
{
    int   ret;
    FILE *fp;

    ret = mkpath(conf->log_file, S_IRWXU);
    if (ret) {
        printf("failed create log directory[%s], exit" LINEFEED, strerror(errno));
        exit(-1);
    }

    fp = fopen(conf->log_file == NULL ? DEFAULT_LOG_FILE : conf->log_file, "w");
    if (!fp) {
        printf("failed create log file[%s], exit" LINEFEED, strerror(errno));
        exit(-1);
    }

    log_set_fp(fp);
    log_set_str_level(conf->log_level == NULL ? DEFAULT_LOG_LEVEL : conf->log_level);
    log_set_quiet(1);
}

int main(int argc, const char *argv[])
{
    int             opt;
    int             debug;
    char           *conf_file;
    pthread_t       rpc_tid, cap_tid;
    hijack_conf_t  *hijack_conf;

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

    hijack_conf = parse_hijack_conf(conf_file);
    if (!hijack_conf) {
        exit(-1);
    }

    print_all_conf(hijack_conf);

    hijack_log_init(hijack_conf);

    printf("program start..." LINEFEED);

    if (!debug) daemonize();

    turn_on_core();

    pthread_create(&rpc_tid, NULL, rpc_service, hijack_conf);
    pthread_create(&cap_tid, NULL, cap_service, hijack_conf);



    pthread_join(rpc_tid, NULL);
    pthread_join(cap_tid, NULL);

    log_error("---------------program unexpected exit!!!---------------");

    return 0;
}


