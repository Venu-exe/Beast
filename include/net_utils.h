#ifndef RECON_NET_UTILS_H
#define RECON_NET_UTILS_H

#include <stddef.h>

/* Non-blocking TCP connect with a timeout. Returns connected socket fd,
 * or -1 on failure/timeout. */
int connect_with_timeout(const char *ip, int port, int timeout_sec);

/* recv() bounded by a timeout (in seconds). Returns bytes read, -1 on
 * timeout/error. Null-terminates buf on success. */
int recv_with_timeout(int sock, char *buf, size_t buflen, int timeout_sec);

#endif /* RECON_NET_UTILS_H */
