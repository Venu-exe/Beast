#ifndef RECON_CSV_REPORT_H
#define RECON_CSV_REPORT_H

/* All functions are no-ops if g_csv_mode is 0, so callers can invoke them
 * unconditionally throughout the pipeline, same convention as json_report.
 * Thread-safe: each add_* call takes an internal lock. One flat table with
 * a "type" column, so heterogeneous findings (subdomains/ports/paths) can
 * share a single CSV that's easy to filter/pivot in a spreadsheet. */

void csv_start(void);   /* call once at startup */

void csv_add_subdomain(const char *target, const char *fqdn, const char *ip,
                        const char *canonical, int flagged);
void csv_add_port(const char *target, int port, const char *banner);
void csv_add_path(const char *target, const char *path, int status_code, long content_length);

void csv_finish_and_write(const char *path);   /* call once at the end */

#endif /* RECON_CSV_REPORT_H */
