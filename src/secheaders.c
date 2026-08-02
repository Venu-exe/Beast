#include "common.h"
#include "secheaders.h"
#include "net_utils.h"
#include "json_report.h"

/* Each entry: header name to look for, human-readable note shown when it's
 * missing, and how many grading points it's worth. Points loosely follow
 * the weighting used by Mozilla Observatory / securityheaders.com, scaled
 * down to keep the math simple. */
typedef struct {
    const char *name;
    const char *missing_note;
    int         points;
} SecHeaderCheck;

static const SecHeaderCheck checks[] = {
    { "Strict-Transport-Security", "HSTS not set -- HTTPS downgrade / SSL-stripping risk", 20 },
    { "Content-Security-Policy",   "no CSP -- reduces defense-in-depth against XSS",        20 },
    { "X-Content-Type-Options",    "MIME-sniffing not disabled",                            15 },
    { "X-Frame-Options",           "no clickjacking protection (consider frame-ancestors)", 15 },
    { "Referrer-Policy",           "referrer policy not set -- may leak URLs cross-origin", 10 },
    { "Permissions-Policy",        "no Permissions-Policy -- browser features not scoped",  10 },
    { "Cross-Origin-Opener-Policy","no COOP -- reduced isolation from cross-origin windows", 5 },
    { "Cross-Origin-Resource-Policy","no CORP set",                                          5 },
};
static const int checks_count = sizeof(checks) / sizeof(checks[0]);

static char grade_for_score(int score) {
    if (score >= 95) return 'A';
    if (score >= 80) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
}

/* returns 1 if `name: ` appears as a header line in the raw response buf */
static int header_present(const char *buf, const char *name) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\n%s:", name);
    if (strcasestr(buf, needle)) return 1;
    /* also match if it's the very first header right after the status line
     * (no leading \n visible because we searched from offset 0 above) */
    if (strncasecmp(buf, name, strlen(name)) == 0) return 1;
    return 0;
}

int run_security_header_audit(const char *host, int port) {
    report("\n[*] HTTP security header audit for %s:%d\n", host, port);

    int sock = connect_with_timeout(g_target_ip, port, g_timeout);
    if (sock < 0) {
        report("[-] Security header audit: could not connect to %s:%d\n", host, port);
        return -1;
    }

    char request[512];
    snprintf(request, sizeof(request),
             "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: recon-tool/%s\r\nConnection: close\r\n\r\n",
             host, RECON_VERSION);
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        report("[-] Security header audit: request failed on %s:%d\n", host, port);
        return -1;
    }

    char buf[MAX_BANNER];
    int n = recv_with_timeout(sock, buf, sizeof(buf), g_timeout);
    close(sock);
    if (n <= 0) {
        report("[-] Security header audit: no response from %s:%d\n", host, port);
        return -1;
    }
    buf[n] = '\0';

    int score = 0;
    int max_score = 0;
    char missing_csv[1024];
    missing_csv[0] = '\0';
    int first_missing = 1;

    for (int i = 0; i < checks_count; i++) {
        max_score += checks[i].points;
        if (header_present(buf, checks[i].name)) {
            score += checks[i].points;
            report_color(COLOR_GREEN, "    [x] %s\n", checks[i].name);
        } else {
            report_color(COLOR_YELLOW, "    [ ] %s -- %s\n", checks[i].name, checks[i].missing_note);
            if (!first_missing) strncat(missing_csv, ", ", sizeof(missing_csv) - strlen(missing_csv) - 1);
            strncat(missing_csv, checks[i].name, sizeof(missing_csv) - strlen(missing_csv) - 1);
            first_missing = 0;
        }
    }

    /* normalize to a 0-100 scale in case the point table above changes */
    int pct = max_score > 0 ? (score * 100) / max_score : 0;
    char grade = grade_for_score(pct);

    const char *grade_color = COLOR_GREEN;
    if (grade == 'D' || grade == 'F') grade_color = COLOR_RED;
    else if (grade == 'C') grade_color = COLOR_YELLOW;

    report_color(grade_color, "    Grade      : %c  (%d/100)\n", grade, pct);
    if (strlen(missing_csv) > 0) {
        report("    Bug bounty use: missing headers above are commonly reported as low/info-severity\n"
               "                     findings on programs that accept them; combine with an actual\n"
               "                     XSS/clickjacking PoC for anything above informational.\n");
    }

    json_add_secheaders(pct, grade, missing_csv);

    return 0;
}
