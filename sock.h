/**
 * @author [rench]
 * @create date 2017-10-28 02:38:22
 * @modify date 2017-10-28 02:38:34
 * @desc [net]
*/

#ifndef __net_h__
#define __net_h__

#define RECVBUF  8192

typedef enum {
    OK,
    ERROR,
    RETRY
} status;

status sock_listen(const char *ip, int port, int *listenfd);
//status sock_connect(const char *ip, int port);
status sock_close(int fd);
status sock_read(int fd, char *buf, size_t len, size_t *n);
status sock_write(int fd, char *buf, size_t len, size_t *n);
size_t sock_readable(int fd);
status sock_accept(int fd, int *newfd, char *addr, size_t addr_len);
status sock_nonblocking(int sockfd);


#endif 
