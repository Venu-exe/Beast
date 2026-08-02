#include "common.h"
#include "csv_report.h"

static char *s_buf = NULL;
static size_t s_len = 0;
static size_t s_cap = 0;
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;

static void ensure_cap(size_t extra) {
    if (s_len + extra + 1 <= s_cap) return;
    size_t new_cap = s_cap == 0 ? 4096 : s_cap * 2;
    while (new_cap < s_len + extra + 1) new_cap *= 2;
    s_buf = realloc(s_buf, new_cap);
    s_cap = new_cap;
}

static void raw_append(const char *s) {
    size_t l = strlen(s);
    ensure_cap(l);
    memcpy(s_buf + s_len, s, l);
    s_len += l;
    s_buf[s_len] = '\0';
}

/* RFC 4180-ish: wrap in quotes and double up any embedded quotes. Always
 * quotes (even when not strictly required) so mixed content -- hostnames,
 * banners with commas/newlines from raw server responses, etc -- is always
 * safe to round-trip through Excel/Sheets/pandas. */
static void append_csv_field(const char *s) {
    raw_append("\"");
    if (s) {
        for (const char *p = s; *p; p++) {
            if (*p == '"') raw_append("\"\"");
            else if (*p == '\n' || *p == '\r') raw_append(" ");
            else {
                char tmp[2] = { *p, '\0' };
                raw_append(tmp);
            }
        }
    }
    raw_append("\"");
}

void csv_start(void) {
    if (!g_csv_mode) return;
    pthread_mutex_lock(&s_lock);
    s_len = 0;
    ensure_cap(4096);
    raw_append("type,target,name,ip_or_status,detail,flagged\n");
    pthread_mutex_unlock(&s_lock);
}

void csv_add_subdomain(const char *target, const char *fqdn, const char *ip,
                        const char *canonical, int flagged) {
    if (!g_csv_mode) return;
    pthread_mutex_lock(&s_lock);
    append_csv_field("subdomain");
    raw_append(",");
    append_csv_field(target);
    raw_append(",");
    append_csv_field(fqdn);
    raw_append(",");
    append_csv_field(ip);
    raw_append(",");
    append_csv_field(canonical);
    raw_append(",");
    append_csv_field(flagged ? "true" : "false");
    raw_append("\n");
    pthread_mutex_unlock(&s_lock);
}

void csv_add_port(const char *target, int port, const char *banner) {
    if (!g_csv_mode) return;
    pthread_mutex_lock(&s_lock);
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    append_csv_field("port");
    raw_append(",");
    append_csv_field(target);
    raw_append(",");
    append_csv_field(portbuf);
    raw_append(",");
    append_csv_field("open");
    raw_append(",");
    append_csv_field(banner);
    raw_append(",");
    append_csv_field("false");
    raw_append("\n");
    pthread_mutex_unlock(&s_lock);
}

void csv_add_path(const char *target, const char *path, int status_code, long content_length) {
    if (!g_csv_mode) return;
    pthread_mutex_lock(&s_lock);
    char statusbuf[16], detailbuf[64];
    snprintf(statusbuf, sizeof(statusbuf), "%d", status_code);
    snprintf(detailbuf, sizeof(detailbuf), "%ld bytes", content_length);
    append_csv_field("path");
    raw_append(",");
    append_csv_field(target);
    raw_append(",");
    append_csv_field(path);
    raw_append(",");
    append_csv_field(statusbuf);
    raw_append(",");
    append_csv_field(detailbuf);
    raw_append(",");
    append_csv_field("false");
    raw_append("\n");
    pthread_mutex_unlock(&s_lock);
}

void csv_finish_and_write(const char *path) {
    if (!g_csv_mode) return;
    pthread_mutex_lock(&s_lock);
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(s_buf ? s_buf : "", f);
        fclose(f);
    } else {
        fprintf(stderr, "[-] Could not write CSV report to %s\n", path);
    }
    pthread_mutex_unlock(&s_lock);
}
