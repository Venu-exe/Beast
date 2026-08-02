#ifndef RECON_DNS_UTILS_H
#define RECON_DNS_UTILS_H

#include <stddef.h>

/* Resolves host to an IP string (prefers IPv4), printing all A/AAAA
 * records via report(). Returns 0 on success, -1 on failure. */
int resolve_host(const char *host, char *ip_out, size_t ip_out_len);

/* Performs a reverse DNS (PTR) lookup on an IPv4 address and reports it. */
void reverse_dns(const char *ip);

/* Silent resolution used by subdomain enum: resolves `host` to its first
 * IPv4 address and canonical (post-CNAME-chain) name. Returns 0 on
 * success, -1 if the name doesn't resolve. */
int resolve_with_canonical(const char *host, char *ip_out, size_t ip_out_len,
                            char *canon_out, size_t canon_out_len);

#endif /* RECON_DNS_UTILS_H */
