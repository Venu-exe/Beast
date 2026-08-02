#ifndef RECON_SUBDOMAIN_H
#define RECON_SUBDOMAIN_H

/* Built-in fallback subdomain list, NULL-terminated. */
extern const char *default_subs[];

/* Multi-threaded subdomain enumeration of `domain`.
 * wordlist_path == "default" (or NULL) uses the built-in list; otherwise
 * reads one candidate per line from the given file. Prints hits via
 * report_color() and records them in the JSON report if enabled. Flags
 * entries whose CNAME points at a known third-party service as worth a
 * manual dangling-CNAME / takeover review. */
void run_subdomain_enum(const char *domain, const char *wordlist_path, int threads);

#endif /* RECON_SUBDOMAIN_H */
