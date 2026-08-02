#ifndef RECON_HTTP_PATHS_H
#define RECON_HTTP_PATHS_H

/* Built-in list of common paths worth checking (robots.txt, .git/config,
 * admin panels, etc.), NULL-terminated. */
extern const char *default_paths[];

/* Multi-threaded HTTP path discovery against host:port. wordlist_path ==
 * "default" (or NULL) uses the built-in list; otherwise one path per
 * line from the given file (leading "/" optional). Reports status code +
 * content-length for each response and records interesting ones (2xx,
 * 3xx, 401, 403) into the JSON report if enabled. */
void run_path_discovery(const char *host, int port, const char *wordlist_path, int threads);

#endif /* RECON_HTTP_PATHS_H */
