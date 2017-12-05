#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "conf.h"
#include "cJSON.h"
#include "util.h"

#define TOKEN_RPC           "rpc"
#define TOKEN_RPC_HOST      "host"
#define TOKEN_RPC_PORT      "port"

#define TOKEN_CAPTURE               "capture"
#define TOKEN_CAPTURE_DEV           "dev"
#define TOKEN_CAPTURE_PROCS         "procs"
#define TOKEN_CAPTURE_PROCS_CORE    "cpu"
#define TOKEN_CAPTURE_PROCS_FILTER  "filter"

#define TOKEN_INJECT        "inject"
#define TOKEN_INJECT_DEV    "dev"
#define TOKEN_INJECT_URL    "pushurl"
#define TOKEN_INJECT_MAC    "mac"

#define TOKEN_LOG           "log"
#define TOKEN_LOG_FILE      "file"
#define TOKEN_LOG_LEVEL     "level"   //"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"

static int parse_hijack_value(cJSON *root, const char *token, int type, char **result, int *num);

int parse_hijack_unit(cJSON *root, const char *otoken, const char *itoken, int type, char **result, int *num)
{
    cJSON *outer, *inner;

    outer = cJSON_GetObjectItemCaseSensitive(root, otoken);
    if (!outer) {
        printf("%s configuration cant be null" LINEFEED, otoken);
        return -1;
    }

    inner = cJSON_GetObjectItemCaseSensitive(outer, itoken);
    if (!inner || inner->type != type) {
        printf("%s configuration in %s cant be null or illegal format" LINEFEED, itoken, otoken);
        return -1;
    }
    
    if (inner->type == cJSON_String) {
        *result = strdup(inner->valuestring);
    }
    if (inner->type == cJSON_Number) {
        *num = inner->valuedouble;
    }

    return 0;
}

int parse_hijack_cap_proc_array(cJSON *root, const char *otoken, const char *itoken, cap_conf_t **confs, int *num)
{
    int    i, size;
    cJSON *outer, *inner;

    outer = cJSON_GetObjectItemCaseSensitive(root, otoken);
    if (!outer) {
        printf("%s configuration cant be null" LINEFEED, otoken);
        return -1;
    }  
    
    inner = cJSON_GetObjectItemCaseSensitive(outer, itoken);
    if (!inner || inner->type != cJSON_Array) {
        goto failed;
    }

    size = cJSON_GetArraySize(inner);
    if (size == 0) {
        goto failed;
    }

    *num = size;

    *confs = (cap_conf_t *)calloc(size, sizeof(cap_conf_t));
    
    for (i = 0; i < size; i++) {
        cJSON *subitem = cJSON_GetArrayItem(inner, i);
        if (subitem->type != cJSON_Object) {
            goto failed;
        }

        if (parse_hijack_value(subitem, TOKEN_CAPTURE_PROCS_CORE, cJSON_Number, NULL, &((*confs)[i].core))) {
            return -1;
        }

        if (parse_hijack_value(subitem, TOKEN_CAPTURE_PROCS_FILTER, cJSON_String, &((*confs)[i].filter),NULL)) {
            return -1;
        }
    }

    return 0;

failed:
    printf("%s configuration in %s cant be null or illegal format" LINEFEED, itoken, otoken);
    return -1;
}

static int parse_hijack_value(cJSON *root, const char *token, int type, char **result, int *num)
{
    cJSON *node;

    node = cJSON_GetObjectItemCaseSensitive(root, token);
    if (!node) {
        printf("%s configuration cant be null" LINEFEED, token);
        return -1;
    }

    if (node->type != type) {
        printf("%s configuretion is illegal format" LINEFEED, token);
        return -1;
    }

    if (node->type == cJSON_String) {
        *result = strdup(node->valuestring);
    }
    if (node->type == cJSON_Number) {
        *num = node->valuedouble;
    }

    return 0;    
}

hjk_conf_t *parse_hijack_conf(const char *filename)
{
    char           *fstr;
    cJSON          *root;
    hjk_conf_t     *conf;

    fstr = NULL;
    root = NULL;
    conf = (hjk_conf_t *)calloc(1, sizeof(hjk_conf_t));

    fstr = load_file(filename);
    if (!fstr) {
        goto failed;
    }

    root = cJSON_Parse(fstr);
    if (!root) {
        goto failed;
    }

    if (parse_hijack_unit(root, TOKEN_RPC, TOKEN_RPC_HOST, cJSON_String, &conf->laddr, NULL) ||
        parse_hijack_unit(root, TOKEN_RPC, TOKEN_RPC_PORT, cJSON_Number, NULL, &conf->lport) ||
        parse_hijack_unit(root, TOKEN_LOG, TOKEN_LOG_FILE, cJSON_String, &conf->log_file, NULL) ||
        parse_hijack_unit(root, TOKEN_LOG, TOKEN_LOG_LEVEL, cJSON_String, &conf->log_level, NULL) ||
        parse_hijack_unit(root, TOKEN_INJECT, TOKEN_INJECT_DEV, cJSON_String, &conf->net_dev, NULL) ||
        parse_hijack_unit(root, TOKEN_INJECT, TOKEN_INJECT_URL, cJSON_String, &conf->net_url, NULL) ||
        parse_hijack_unit(root, TOKEN_INJECT, TOKEN_INJECT_MAC, cJSON_String, &conf->net_mac, NULL) ||
        parse_hijack_unit(root, TOKEN_CAPTURE, TOKEN_CAPTURE_DEV, cJSON_String, &conf->cap_dev, NULL) ||
        parse_hijack_cap_proc_array(root, TOKEN_CAPTURE, TOKEN_CAPTURE_PROCS, &conf->cap_conf, &conf->cap_num)) {
        goto failed;
    }

    cJSON_Delete(root);
    free(fstr);

    return conf;


failed:
    if (root) cJSON_Delete(root);
    if (fstr) free(fstr);

    return NULL;
}

void print_all_conf(hjk_conf_t *conf)
{
    int i;

    printf("configuration:" LINEFEED 
            "rpc listen on: %s:%d" LINEFEED 
            "inject card: %s" LINEFEED
            "inject push url: %s" LINEFEED
            "inject push mac: %s" LINEFEED
            "log file: %s" LINEFEED 
            "log level: %s" LINEFEED,
            conf->laddr, conf->lport, conf->net_dev, conf->net_url, conf->net_mac, 
            conf->log_file, conf->log_level);
    
    printf("capture dev: %s" LINEFEED, conf->cap_dev);

    printf("capture procs: " LINEFEED);
    for (i = 0; i < conf->cap_num; i++) {
        printf("[num.%d] core capture [%s]" LINEFEED, conf->cap_conf[i].core, conf->cap_conf[i].filter);
    }
}
