#ifndef __conf_h__
#define __conf_h__


typedef struct {
    char  *laddr;
    int    lport;

    char  *net_pcap;
    char  *net_send;

    char  *log_file;
    char  *log_level;

    char  *pushaddr; //http://113.18.253.249/push

    char  *sendmac;

    char  *cap_filter;

    int    cap_thread_core;
    int   *proc_thread_core;
    int    proc_thread_num;
} hijack_conf_t;


hijack_conf_t *parse_hijack_conf(const char *filename);
void print_all_conf(hijack_conf_t *conf);

#endif

