#ifndef __util_h__
#define __util_h__

#include <sys/types.h>
#include <stdint.h>

#define  LINEFEED    "\n"

char *load_file(const char *filename);
int mkpath(char* file_path, mode_t mode);
int daemonize(void);
int turn_on_core(void);
int stick_thread_to_core(int core_id);
int get_net_mac(char *ethname, uint8_t *srcmac);

#endif

