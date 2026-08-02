#ifndef RECON_TLS_PROBE_H
#define RECON_TLS_PROBE_H

/* Connects to host:port over TLS, retrieves the peer certificate, and
 * reports subject CN, issuer CN, validity window, days remaining until
 * expiry (warns if expired or expiring soon), and Subject Alternative
 * Names (useful for discovering more hostnames). Also feeds the JSON
 * report if enabled. Returns 0 on success, -1 if the TLS handshake or
 * certificate retrieval failed. */
int tls_probe(const char *host, int port);

#endif /* RECON_TLS_PROBE_H */
