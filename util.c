#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include "util.h"

#define path_split  '/'

char *load_file(const char *filename)
{
    char  *buffer = NULL;
    long   length;
    FILE  *f = fopen(filename, "rb");
    
    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = calloc(1, length);
        if (buffer) {
            fread(buffer, 1, length, f);
        }
        fclose(f);
    }

    return buffer;
}

int mkpath(char* file_path, mode_t mode) 
{
    char* p;
    
    for (p = strchr(file_path + 1, path_split); p; p = strchr(p + 1, path_split)) {
        *p = 0;
        if (mkdir(file_path, mode) == -1) {
            if (errno != EEXIST) { *p = path_split; return -1; }
        }
        *p = path_split;
    }

    return 0;
}

int daemonize(void)
{
    int  fd;

    switch (fork()) {
    case -1:
        printf("fork() failed, %s" LINEFEED, strerror(errno));
        return -1;
    case 0:
        break;
    default:
        exit(0);
    }

    if (setsid() == -1) {
        printf("setsid() failed, %s" LINEFEED, strerror(errno));
        return -1;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        printf("open(\"/dev/null\") failed, %s" LINEFEED, strerror(errno));
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        printf("dup2(STDIN) failed, %s" LINEFEED, strerror(errno));
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        printf("dup2(STDOUT) failed, %s" LINEFEED, strerror(errno));
        return -1;
    }

    if (dup2(fd, STDERR_FILENO) == -1) {
        printf("dup2(STDOUT) failed, %s" LINEFEED, strerror(errno));
        return -1;
    }    

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            printf("close() failed, %s" LINEFEED, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int turn_on_core(void)
{
    struct rlimit core_limit;
    
    core_limit.rlim_cur = RLIM_INFINITY;
    core_limit.rlim_max = RLIM_INFINITY;
    
    return setrlimit(RLIMIT_CORE, &core_limit);
}

