#include "common.h"
#include "http_paths.h"
#include "net_utils.h"
#include "json_report.h"
#include "csv_report.h"

const char *default_paths[] = {
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local",
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/api", "/api/", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/actuator/health", "/actuator/env", "/actuator", "/metrics",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/config.php", "/config.json", "/.htaccess", "/.DS_Store",
    "/backup.zip", "/backup.sql", "/dump.sql", "/database.sql",
    "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa",
    "/debug", "/test", "/staging", "/dev", "/console",
    "/.well-known/openid-configuration", "/crossdomain.xml",
    "/web.config", "/WEB-INF/web.xml", "/composer.json",
    "/package.json", "/README.md", "/CHANGELOG.md",
    NULL
};

typedef struct {
    char host[MAX_HOSTLEN];
    int  port;
} PathTarget;

static char **s_paths = NULL;
static int s_path_count = 0;
static int s_next_index = 0;
static PathTarget s_target;
static pthread_mutex_t s_index_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_found_count = 0;
static pthread_mutex_t s_found_lock = PTHREAD_MUTEX_INITIALIZER;

/* performs one GET request for `path` against s_target, returns status
 * code (0 if the request failed outright) and fills content_length (-1
 * if no Content-Length header was present). */
static int fetch_path(const char *path, long *content_length) {
    *content_length = -1;
    int sock = connect_with_timeout(g_target_ip, s_target.port, g_timeout);
    if (sock < 0) return 0;

    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: recon-tool/%s\r\nConnection: close\r\n\r\n",
             path, s_target.host, RECON_VERSION);
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        return 0;
    }

    char buf[MAX_BANNER];
    int n = recv_with_timeout(sock, buf, sizeof(buf), g_timeout);
    close(sock);
    if (n <= 0) return 0;

    int status = 0;
    if (strncmp(buf, "HTTP/", 5) == 0) {
        char *sp = strchr(buf, ' ');
        if (sp) status = atoi(sp + 1);
    }

    char *cl = strcasestr(buf, "Content-Length:");
    if (cl) {
        /* "Content-Length:" is 15 chars; atol() itself skips any
         * following whitespace, so start right after the colon.
         * The old "+16" skipped one extra byte and truncated the
         * length whenever the header had no space after the colon. */
        *content_length = atol(cl + 15);
    }

    return status;
}

static void *path_worker(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&s_index_lock);
        int idx = s_next_index;
        if (idx >= s_path_count) {
            pthread_mutex_unlock(&s_index_lock);
            break;
        }
        s_next_index++;
        pthread_mutex_unlock(&s_index_lock);

        const char *path = s_paths[idx];
        long content_length;
        int status = fetch_path(path, &content_length);

        if (status >= 200 && status < 300) {
            report_color(COLOR_GREEN, "    [%d] %s%s (%ld bytes)\n",
                         status, s_target.host, path, content_length);
            json_add_path(path, status, content_length);
            csv_add_path(s_target.host, path, status, content_length);
            pthread_mutex_lock(&s_found_lock); s_found_count++; pthread_mutex_unlock(&s_found_lock);
        } else if (status == 401 || status == 403) {
            report_color(COLOR_YELLOW, "    [%d] %s%s (protected)\n", status, s_target.host, path);
            json_add_path(path, status, content_length);
            csv_add_path(s_target.host, path, status, content_length);
            pthread_mutex_lock(&s_found_lock); s_found_count++; pthread_mutex_unlock(&s_found_lock);
        } else if (status >= 300 && status < 400) {
            report_color(COLOR_CYAN, "    [%d] %s%s (redirect)\n", status, s_target.host, path);
            json_add_path(path, status, content_length);
            csv_add_path(s_target.host, path, status, content_length);
            pthread_mutex_lock(&s_found_lock); s_found_count++; pthread_mutex_unlock(&s_found_lock);
        }
        /* 404s and failed connections are silently skipped */

        rate_limit_delay();
    }
    return NULL;
}

void run_path_discovery(const char *host, int port, const char *wordlist_path, int threads) {
    report("\n[*] Starting HTTP path discovery on %s:%d\n", host, port);

    strncpy(s_target.host, host, sizeof(s_target.host) - 1);
    s_target.host[sizeof(s_target.host) - 1] = '\0';
    s_target.port = port;

    char **paths = NULL;
    int count = 0, cap = 128;
    paths = malloc(sizeof(char *) * cap);

    FILE *f = NULL;
    if (wordlist_path && strcasecmp(wordlist_path, "default") != 0) {
        f = fopen(wordlist_path, "r");
        if (!f) {
            report("[-] Could not open path wordlist %s, falling back to default list\n", wordlist_path);
        }
    }

    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strlen(line) == 0) continue;
            char normalized[300];
            if (line[0] != '/') snprintf(normalized, sizeof(normalized), "/%s", line);
            else snprintf(normalized, sizeof(normalized), "%s", line);
            if (count >= cap) { cap *= 2; paths = realloc(paths, sizeof(char *) * cap); }
            paths[count++] = strdup(normalized);
        }
        fclose(f);
    } else {
        for (int i = 0; default_paths[i] != NULL; i++) {
            if (count >= cap) { cap *= 2; paths = realloc(paths, sizeof(char *) * cap); }
            paths[count++] = strdup(default_paths[i]);
        }
    }

    s_paths = paths;
    s_path_count = count;
    s_next_index = 0;
    s_found_count = 0;

    int nthreads = threads;
    if (nthreads > MAX_THREADS) nthreads = MAX_THREADS;
    if (nthreads > count) nthreads = count;
    if (nthreads < 1) nthreads = 1;

    pthread_t tids[MAX_THREADS];
    for (int i = 0; i < nthreads; i++) pthread_create(&tids[i], NULL, path_worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);

    report("[*] Path discovery complete: %d interesting responses (checked %d paths)\n",
           s_found_count, count);

    for (int i = 0; i < count; i++) free(paths[i]);
    free(paths);
}
