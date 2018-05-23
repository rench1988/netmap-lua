#ifndef __util_h__
#define __util_h__

#include <sys/types.h>
#include <stdint.h>
#include <net/ethernet.h>

#define  LINEFEED    "\n"

int mkpath(char* file_path, mode_t mode);
int daemonize(void);

int setrlimit_core(void);
int setaffinity(pthread_t me, int i);

int hwaddr_mac(const char *ifname, struct ether_addr *buf);

void initproctitle(int argc, char **argv);
void setproctitle(const char *prog, const char *txt);
char *cpystrn(char *dst, char *src, size_t n);
#endif

