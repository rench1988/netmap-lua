#ifndef __util_h__
#define __util_h__

#define  LINEFEED    "\n"

char *load_file(const char *filename);
int mkpath(char* file_path, mode_t mode);
int daemonize(void);
int turn_on_core(void);

#endif

