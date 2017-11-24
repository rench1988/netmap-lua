#include <sys/types.h>  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "sock.h"

#define LISTEN_BACKLOG  511

status sock_read(int fd, char *buf, size_t len, size_t *n)
{
    ssize_t r = read(fd, buf, len);
    *n = (size_t) r;
    return r > 0 ? OK : (errno == EAGAIN ? RETRY : ERROR);    
}

status sock_write(int fd, char *buf, size_t len, size_t *n) {
    ssize_t r;

    r = write(fd, buf, len);
    if (r == -1) {
        return errno == EAGAIN ? RETRY : ERROR;
    }

    *n = r;

    return OK;
}

/*
status sock_connect(const char *host, int port) {
    int                fd;
    int                ret;
    struct sockaddr_in server;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return ERROR;
    }

    bzero(&server, sizeof(server));
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    
    if (connect(fd , (struct sockaddr *)&server , sizeof(server)) < 0) goto error;

    return OK;

error:
    if (*ret) free(*ret);
    return ERROR;
}
*/

status sock_listen(const char *ip, int port, int *listenfd)
{
    int fd;
    int ret;
    struct sockaddr_in saddress;

    bzero(&saddress, sizeof(saddress));
    saddress.sin_family = AF_INET; 
    saddress.sin_port = htons(port);
    inet_pton(AF_INET, ip, &saddress.sin_addr);  

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return ERROR;
    }

    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    
    ret = bind(fd, (struct sockaddr*)&saddress, sizeof(saddress)); 
    if (ret) {
        return ERROR;
    }

    ret = listen(fd, LISTEN_BACKLOG);
    if (ret) {
        return ERROR;
    }

    *listenfd = fd;

    return OK;
}

status sock_nonblocking(int sockfd)
{
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

    return OK;
}

status sock_accept(int fd, int *newfd, char *addr, size_t addr_len)
{
    int                clientfd;
    socklen_t          clientlen;
    struct sockaddr_in clientaddr;

    clientlen = sizeof(struct sockaddr_in);
    clientfd = accept(fd, (struct sockaddr *) &clientaddr, &clientlen);
    if (clientfd < 0) {
        return errno == EAGAIN ? RETRY : ERROR;
    }

    snprintf(addr, addr_len, "%s:%d", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

    *newfd = clientfd;

    return OK;
}

size_t sock_readable(int fd) {
    int n, rc;
    rc = ioctl(fd, FIONREAD, &n);
    return rc == -1 ? 0 : n;
}

