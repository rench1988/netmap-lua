#include "conf.h"
#include <libconfig.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define config_compel_string(option, ptr) \
    do { \
        ret = config_lookup_string(&config, option, ptr); \
        if (ret == CONFIG_FALSE) { \
            printf("No '%s' setting in configuration file.\n", option); \
            return -1; \
        } \
    } while (0) 

#define config_compel_int(option, ptr) \
    do { \
        ret = config_lookup_int(&config, option, ptr); \
        if (ret == CONFIG_FALSE) { \
            printf("No '%s' setting in configuration file.\n", option); \
            return -1; \
        } \
    } while (0)

static void parse_error(const char *filename, config_t *config) {
    config_error_t type;

    type = config_error_type(config);
    
    switch (type) {
        case CONFIG_ERR_FILE_IO:
            printf("failed parse file %s: %s\n", filename, strerror(errno));
            break;
        case CONFIG_ERR_PARSE:
            printf("failed parse file %s on line %d's text: %s\n", config_error_file(config),
                        config_error_line(config), config_error_text(config));
            break;
        default:
            break;
    }

    return;
}

int parse_conf(const char *filename, hjk_cycle_t *cycle) {
    int      ret;
    config_t config;

    config_init(&config);

    ret = config_read_file(&config, filename);
    if (ret == CONFIG_FALSE) {
        parse_error(filename, &config);
        return -1;
    }

    config_lookup_bool(&config, "debug", &cycle->debug);
    config_lookup_int(&config, "affinity", &cycle->affinity);

    config_compel_string("cap.ether", &cycle->iether);

    config_compel_string("rpc.address", &cycle->laddr);
    config_compel_int("rpc.port", &cycle->lport);

    config_compel_string("redis.address", &cycle->raddr);
    config_compel_int("redis.port", &cycle->rport);

    config_compel_string("script", &cycle->script);

    return 0;
}
