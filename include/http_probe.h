#ifndef RECON_HTTP_PROBE_H
#define RECON_HTTP_PROBE_H

#include "common.h"

/* Returns 1 if the port is conventionally a web/HTTP(S) port. */
int is_web_port(int port);

/* Sends a simple GET / over an already-connected socket and fills in
 * res->banner with any Server header / <title> found. */
void http_probe(int sock, const char *host, PortResult *res);

#endif /* RECON_HTTP_PROBE_H */
