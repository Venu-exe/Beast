#include "common.h"
#include "json_report.h"

static char *s_buf = NULL;
static size_t s_len = 0;
static size_t s_cap = 0;
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;

static int s_first_target = 1;

static int s_dns_open     = 0;
static int s_first_ipv4   = 1;
static int s_reverse_done = 0;

static int s_subs_open  = 0;
static int s_first_sub  = 1;
static int s_ports_open = 0;
static int s_first_port = 1;
static int s_paths_open = 0;
static int s_first_path = 1;

/* tracks which array-type section was most recently written to, so we
 * know exactly when to close it: the moment a *different* section
 * starts writing (or the target ends). This makes section order and
 * omission (e.g. no subdomains found, or paths skipped) irrelevant. */
enum { SEC_NONE, SEC_SUBS, SEC_PORTS, SEC_TLS, SEC_PATHS, SEC_SECHEADERS };
static int s_last_section = SEC_NONE;

#define MAX_IPV6 32
static char s_ipv6_list[MAX_IPV6][INET6_ADDRSTRLEN];
static int  s_ipv6_count = 0;

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

static void append_jstr(const char *s) {
    if (!s) { raw_append("null"); return; }
    raw_append("\"");
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':  raw_append("\\\""); break;
            case '\\': raw_append("\\\\"); break;
            case '\n': raw_append("\\n");  break;
            case '\r': raw_append("\\r");  break;
            case '\t': raw_append("\\t");  break;
            default:
                if (*p < 0x20) {
                    char tmp[8];
                    snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
                    raw_append(tmp);
                } else {
                    char tmp[2] = { (char)*p, '\0' };
                    raw_append(tmp);
                }
        }
    }
    raw_append("\"");
}

/* must hold s_lock. Closes the array bracket for whichever array-type
 * section was last active, if `new_section` is different. */
static void switch_section_locked(int new_section) {
    if (s_last_section == new_section) return;

    if (s_last_section == SEC_SUBS && s_subs_open)   raw_append("\n      ]");
    if (s_last_section == SEC_PORTS && s_ports_open) raw_append("\n      ]");
    if (s_last_section == SEC_PATHS && s_paths_open) raw_append("\n      ]");

    s_last_section = new_section;
}

void json_start(void) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    s_len = 0;
    ensure_cap(4096);

    time_t now = time(NULL);
    char timebuf[64];
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", &tmv);

    raw_append("{\n  \"recon_version\": \"" RECON_VERSION "\",\n  \"generated\": ");
    append_jstr(timebuf);
    raw_append(",\n  \"targets\": [\n");
    s_first_target = 1;
    pthread_mutex_unlock(&s_lock);
}

void json_start_target(const char *target) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    if (!s_first_target) raw_append(",\n");
    s_first_target = 0;

    raw_append("    {\n      \"target\": ");
    append_jstr(target);
    raw_append(",\n      \"dns\": { \"ipv4\": [");

    s_dns_open = 1;
    s_first_ipv4 = 1;
    s_reverse_done = 0;
    s_subs_open = 0;
    s_first_sub = 1;
    s_ports_open = 0;
    s_first_port = 1;
    s_paths_open = 0;
    s_first_path = 1;
    s_ipv6_count = 0;
    s_last_section = SEC_NONE;
    pthread_mutex_unlock(&s_lock);
}

void json_add_dns_ip(const char *family, const char *ip) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    if (strcmp(family, "IPv4") == 0) {
        if (!s_first_ipv4) raw_append(", ");
        append_jstr(ip);
        s_first_ipv4 = 0;
    }
    pthread_mutex_unlock(&s_lock);
}

void json_add_dns_ip6(const char *ip) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    if (s_ipv6_count < MAX_IPV6) {
        strncpy(s_ipv6_list[s_ipv6_count], ip, INET6_ADDRSTRLEN - 1);
        s_ipv6_list[s_ipv6_count][INET6_ADDRSTRLEN - 1] = '\0';
        s_ipv6_count++;
    }
    pthread_mutex_unlock(&s_lock);
}

/* must hold s_lock */
static void close_dns_block_locked(void) {
    if (!s_dns_open) return;
    raw_append("], \"ipv6\": [");
    for (int i = 0; i < s_ipv6_count; i++) {
        if (i > 0) raw_append(", ");
        append_jstr(s_ipv6_list[i]);
    }
    raw_append("] }");
    s_dns_open = 0;
}

void json_set_reverse_dns(const char *ptr) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    close_dns_block_locked();
    raw_append(",\n      \"reverse_dns\": ");
    append_jstr(ptr);
    s_reverse_done = 1;
    pthread_mutex_unlock(&s_lock);
}

/* must hold s_lock */
static void ensure_reverse_closed_locked(void) {
    close_dns_block_locked();
    if (!s_reverse_done) {
        raw_append(",\n      \"reverse_dns\": null");
        s_reverse_done = 1;
    }
}

void json_add_subdomain(const char *fqdn, const char *ip, const char *canonical, int flagged) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    ensure_reverse_closed_locked();
    switch_section_locked(SEC_SUBS);

    if (!s_subs_open) {
        raw_append(",\n      \"subdomains\": [\n");
        s_subs_open = 1;
    } else if (!s_first_sub) {
        raw_append(",\n");
    }
    raw_append("        { \"fqdn\": ");
    append_jstr(fqdn);
    raw_append(", \"ip\": ");
    append_jstr(ip);
    raw_append(", \"canonical\": ");
    append_jstr(canonical);
    raw_append(flagged ? ", \"flagged_for_review\": true }" : ", \"flagged_for_review\": false }");
    s_first_sub = 0;
    pthread_mutex_unlock(&s_lock);
}

void json_add_port(int port, const char *banner) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    ensure_reverse_closed_locked();
    switch_section_locked(SEC_PORTS);

    if (!s_ports_open) {
        raw_append(",\n      \"open_ports\": [\n");
        s_ports_open = 1;
    } else if (!s_first_port) {
        raw_append(",\n");
    }
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    raw_append("        { \"port\": ");
    raw_append(portbuf);
    raw_append(", \"banner\": ");
    append_jstr(banner);
    raw_append(" }");
    s_first_port = 0;
    pthread_mutex_unlock(&s_lock);
}

void json_add_path(const char *path, int status_code, long content_length) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    ensure_reverse_closed_locked();
    switch_section_locked(SEC_PATHS);

    if (!s_paths_open) {
        raw_append(",\n      \"paths\": [\n");
        s_paths_open = 1;
    } else if (!s_first_path) {
        raw_append(",\n");
    }
    char numbuf[32];
    raw_append("        { \"path\": ");
    append_jstr(path);
    snprintf(numbuf, sizeof(numbuf), "%d", status_code);
    raw_append(", \"status\": ");
    raw_append(numbuf);
    snprintf(numbuf, sizeof(numbuf), "%ld", content_length);
    raw_append(", \"content_length\": ");
    raw_append(numbuf);
    raw_append(" }");
    s_first_path = 0;
    pthread_mutex_unlock(&s_lock);
}

void json_add_tls(const char *subject_cn, const char *issuer_cn,
                   const char *not_before, const char *not_after,
                   int days_remaining, const char *sans_csv) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    ensure_reverse_closed_locked();
    switch_section_locked(SEC_TLS);

    raw_append(",\n      \"tls\": {\n        \"subject_cn\": ");
    append_jstr(subject_cn);
    raw_append(",\n        \"issuer_cn\": ");
    append_jstr(issuer_cn);
    raw_append(",\n        \"not_before\": ");
    append_jstr(not_before);
    raw_append(",\n        \"not_after\": ");
    append_jstr(not_after);
    char numbuf[16];
    snprintf(numbuf, sizeof(numbuf), "%d", days_remaining);
    raw_append(",\n        \"days_remaining\": ");
    raw_append(numbuf);
    raw_append(",\n        \"sans\": ");
    append_jstr(sans_csv);
    raw_append("\n      }");
    pthread_mutex_unlock(&s_lock);
}

void json_add_secheaders(int score, char grade, const char *missing_csv) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    ensure_reverse_closed_locked();
    switch_section_locked(SEC_SECHEADERS);

    char gradebuf[2] = { grade, '\0' };
    char scorebuf[16];
    snprintf(scorebuf, sizeof(scorebuf), "%d", score);

    raw_append(",\n      \"security_headers\": {\n        \"score\": ");
    raw_append(scorebuf);
    raw_append(",\n        \"grade\": ");
    append_jstr(gradebuf);
    raw_append(",\n        \"missing\": ");
    append_jstr(missing_csv);
    raw_append("\n      }");
    pthread_mutex_unlock(&s_lock);
}

void json_end_target(void) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    ensure_reverse_closed_locked();
    switch_section_locked(SEC_NONE); /* closes whatever array was last open */
    raw_append("\n    }");
    pthread_mutex_unlock(&s_lock);
}

void json_finish_and_write(const char *path) {
    if (!g_json_mode) return;
    pthread_mutex_lock(&s_lock);
    raw_append("\n  ]\n}\n");

    FILE *f = fopen(path, "w");
    if (f) {
        fputs(s_buf, f);
        fclose(f);
    } else {
        fprintf(stderr, "[-] Could not write JSON report to %s\n", path);
    }
    pthread_mutex_unlock(&s_lock);
}
