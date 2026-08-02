#include "common.h"
#include "net_utils.h"

int connect_with_timeout(const char *ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        fcntl(sock, F_SETFL, flags);
        return sock;
    }
    if (errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    rc = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
        close(sock); /* timeout or error */
        return -1;
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        close(sock);
        return -1;
    }

    fcntl(sock, F_SETFL, flags);
    return sock;
}

int recv_with_timeout(int sock, char *buf, size_t buflen, int timeout_sec) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int rc = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) return -1;

    int n = recv(sock, buf, buflen - 1, 0);
    if (n > 0) buf[n] = '\0';
    return n;
}
