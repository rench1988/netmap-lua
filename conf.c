#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "conf.h"
#include "cJSON.h"
#include "util.h"

#define TOKEN_RPC           "rpc"
#define TOKEN_RPC_HOST      "host"
#define TOKEN_RPC_PORT      "port"
#define TOKEN_DEVICES       "devices"
#define TOKEN_DEVICES_PCAP  "pcap"
#define TOKEN_DEVICES_SEND  "send"
#define TOKEN_LOG           "log"
#define TOKEN_LOG_FILE      "file"
#define TOKEN_LOG_LEVEL     "level"   //"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
#define TOKEN_PUSHADDR      "pushaddr"
#define TOKEN_SENDMAC       "sendmac"
#define TOKEN_FILTER        "filter"
#define TOKEN_THREADS       "threads"

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

int parse_hijack_value(cJSON *root, const char *token, int type, char **result, int *num)
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

hijack_conf_t *parse_hijack_conf(const char *filename)
{
    char           *fstr;
    cJSON          *root;
    hijack_conf_t  *hijack_conf;

    fstr = NULL;
    root = NULL;
    hijack_conf = (hijack_conf_t *)calloc(1, sizeof(hijack_conf_t));

    fstr = load_file(filename);
    if (!fstr) {
        goto failed;
    }

    root = cJSON_Parse(fstr);
    if (!root) {
        goto failed;
    }

    if (parse_hijack_unit(root, TOKEN_RPC, TOKEN_RPC_HOST, cJSON_String, &hijack_conf->laddr, NULL) ||
        parse_hijack_unit(root, TOKEN_RPC, TOKEN_RPC_PORT, cJSON_Number, NULL, &hijack_conf->lport) ||
        parse_hijack_unit(root, TOKEN_DEVICES, TOKEN_DEVICES_PCAP, cJSON_String, &hijack_conf->net_pcap, NULL) ||
        parse_hijack_unit(root, TOKEN_DEVICES, TOKEN_DEVICES_SEND, cJSON_String, &hijack_conf->net_send, NULL) ||
        parse_hijack_unit(root, TOKEN_LOG, TOKEN_LOG_FILE, cJSON_String, &hijack_conf->log_file, NULL) ||
        parse_hijack_unit(root, TOKEN_LOG, TOKEN_LOG_LEVEL, cJSON_String, &hijack_conf->log_level, NULL) ||
        parse_hijack_value(root, TOKEN_PUSHADDR, cJSON_String, &hijack_conf->pushaddr, NULL) ||
        parse_hijack_value(root, TOKEN_SENDMAC, cJSON_String, &hijack_conf->sendmac, NULL) ||
        parse_hijack_value(root, TOKEN_FILTER, cJSON_String, &hijack_conf->cap_filter, NULL) ||
        parse_hijack_value(root, TOKEN_THREADS, cJSON_Number, NULL, &hijack_conf->cap_thread)) {
        goto failed;
    }

    cJSON_Delete(root);
    free(fstr);

    return hijack_conf;


failed:
    if (root) cJSON_Delete(root);
    if (fstr) free(fstr);

    return NULL;
}

void print_all_conf(hijack_conf_t *conf)
{
    printf("configuration:" LINEFEED "listen on: %s:%d" LINEFEED "capture card: %s" LINEFEED "inject card: %s" LINEFEED
            "log file: %s" LINEFEED "log level: %s" LINEFEED "pushaddr: %s" LINEFEED "inject mac: %s" LINEFEED
            "capture filter: %s" LINEFEED "capture thread num: %d" LINEFEED,
            conf->laddr, conf->lport, conf->net_pcap, conf->net_send, conf->log_file, conf->log_level,
            conf->pushaddr, conf->sendmac, conf->cap_filter, conf->cap_thread);
}
