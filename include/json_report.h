#ifndef RECON_JSON_REPORT_H
#define RECON_JSON_REPORT_H

/* All functions are no-ops if g_json_mode is 0, so callers can invoke them
 * unconditionally throughout the pipeline. Not thread-safe by design across
 * *different* sections, but individual add_* calls take a lock internally,
 * so it is safe to call from within the scan/subdomain worker threads. */

void json_start(void);                          /* call once at startup */
void json_start_target(const char *target);      /* call once per target */

void json_add_dns_ip(const char *family, const char *ip);
void json_add_dns_ip6(const char *ip);
void json_set_reverse_dns(const char *ptr);

void json_add_subdomain(const char *fqdn, const char *ip, const char *canonical, int flagged);

void json_add_port(int port, const char *banner);

void json_add_path(const char *path, int status_code, long content_length);

void json_add_tls(const char *subject_cn, const char *issuer_cn,
                   const char *not_before, const char *not_after,
                   int days_remaining, const char *sans_csv);

void json_add_secheaders(int score, char grade, const char *missing_csv);

void json_end_target(void);                      /* call once per target */
void json_finish_and_write(const char *path);     /* call once at the end */

#endif /* RECON_JSON_REPORT_H */
