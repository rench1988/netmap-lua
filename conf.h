#ifndef __conf_h__
#define __conf_h__

typedef struct {
    int    core;
    char  *filter;
} cap_conf_t;

typedef struct {
    char  *laddr;
    int    lport;

    char        *cap_dev;
    cap_conf_t  *cap_conf;
    int          cap_num;

    char  *net_dev;
    char  *net_mac;
    char  *net_url;

    char  *log_file;
    char  *log_level;
} hjk_conf_t;


hjk_conf_t *parse_hijack_conf(const char *filename);
void print_all_conf(hjk_conf_t *conf);

#endif

