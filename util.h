#ifndef __util_h__
#define __util_h__

#include <sys/types.h>
#include <stdint.h>

#define  LINEFEED    "\n"

char *load_file(const char *filename);
int mkpath(char* file_path, mode_t mode);
int daemonize(void);
int turn_on_core(void);
int set_pthread_affinity(int core);
int nic_mac(char *ethname, uint8_t *srcmac);
void initproctitle(int argc, char **argv);
void setproctitle(const char *prog, const char *txt);
char *cpystrn(char *dst, char *src, size_t n);
#endif

