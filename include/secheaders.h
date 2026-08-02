#ifndef RECON_SECHEADERS_H
#define RECON_SECHEADERS_H

/* Fetches "/" from host:port and grades the response on presence of the
 * standard browser security headers (HSTS, X-Frame-Options, CSP, etc).
 * Prints a report block and (if enabled) adds a JSON section.
 * Returns 0 on success (request completed, headers examined), -1 if the
 * request itself failed (connection refused/timeout/etc). */
int run_security_header_audit(const char *host, int port);

#endif /* RECON_SECHEADERS_H */
