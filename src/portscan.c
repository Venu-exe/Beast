#include "common.h"
#include "portscan.h"
#include "net_utils.h"
#include "http_probe.h"
#include "json_report.h"
#include "csv_report.h"

int top_ports[] = {
    21,22,23,25,53,80,81,110,111,113,135,139,143,161,179,199,
    389,443,445,465,514,515,548,587,631,993,995,1025,1080,1433,1521,1723,
    2049,2082,2083,2181,25565,3000,3128,3306,3389,3690,
    5000,5432,5601,5900,5985,6379,6443,7001,7077,8000,
    8008,8080,8081,8088,8443,8888,9000,9042,9090,9200,9300,
    11211,15672,27017,27018,50000
};
int top_ports_count = sizeof(top_ports)/sizeof(top_ports[0]);

static PortResult *s_results = NULL;
static int *s_portlist = NULL;
static int s_portcount = 0;
static int s_next_index = 0;
static pthread_mutex_t s_index_lock = PTHREAD_MUTEX_INITIALIZER;

int parse_ports(const char *spec, int **out_list) {
    if (strcasecmp(spec, "top") == 0) {
        *out_list = malloc(sizeof(int) * top_ports_count);
        memcpy(*out_list, top_ports, sizeof(top_ports));
        return top_ports_count;
    }

    int a, b;
    if (sscanf(spec, "%d-%d", &a, &b) == 2) {
        if (a < 1) a = 1;
        if (b > 65535) b = 65535;
        if (b < a) { int t = a; a = b; b = t; }
        int count = b - a + 1;
        *out_list = malloc(sizeof(int) * count);
        for (int i = 0; i < count; i++) (*out_list)[i] = a + i;
        return count;
    }

    int cap = 256, count = 0;
    int *list = malloc(sizeof(int) * cap);
    char *copy = strdup(spec);
    char *tok = strtok(copy, ",");
    while (tok) {
        int p = atoi(tok);
        if (p > 0 && p <= 65535) {
            if (count >= cap) { cap *= 2; list = realloc(list, sizeof(int) * cap); }
            list[count++] = p;
        }
        tok = strtok(NULL, ",");
    }
    free(copy);
    *out_list = list;
    return count;
}

static void *scan_worker(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&s_index_lock);
        int idx = s_next_index;
        if (idx >= s_portcount) {
            pthread_mutex_unlock(&s_index_lock);
            break;
        }
        s_next_index++;
        pthread_mutex_unlock(&s_index_lock);

        int port = s_portlist[idx];
        PortResult *res = &s_results[idx];
        res->port = port;
        res->is_open = 0;
        res->banner[0] = '\0';

        int sock = connect_with_timeout(g_target_ip, port, g_timeout);
        if (sock < 0) continue;

        res->is_open = 1;

        if (is_web_port(port)) {
            http_probe(sock, g_target, res);
        } else {
            char buf[MAX_BANNER];
            int n = recv_with_timeout(sock, buf, sizeof(buf), 1);
            if (n > 0) {
                for (int i = 0; i < n; i++) {
                    if (!isprint((unsigned char)buf[i]) && buf[i] != '\n' && buf[i] != '\r')
                        buf[i] = '.';
                }
                snprintf(res->banner, sizeof(res->banner), "%.*s", n, buf);
            }
        }
        close(sock);
    }
    return NULL;
}

void run_port_scan(int *portlist, int portcount, int threads,
                    int **open_ports_out, int *open_count_out) {
    report("\n[*] Starting TCP connect scan on %s (%s) - %d ports, %d threads\n",
           g_target, g_target_ip, portcount, threads);

    s_portlist = portlist;
    s_portcount = portcount;
    s_next_index = 0;
    s_results = calloc(portcount, sizeof(PortResult));

    pthread_t tids[MAX_THREADS];
    int nthreads = threads > MAX_THREADS ? MAX_THREADS : threads;
    if (nthreads > portcount) nthreads = portcount;
    if (nthreads < 1) nthreads = 1;

    time_t start = time(NULL);
    for (int i = 0; i < nthreads; i++) pthread_create(&tids[i], NULL, scan_worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);
    time_t elapsed = time(NULL) - start;

    report("\n[*] Open ports:\n");
    int open_count = 0;
    int *open_ports = malloc(sizeof(int) * portcount);

    for (int i = 0; i < portcount; i++) {
        if (s_results[i].is_open) {
            open_ports[open_count++] = s_results[i].port;
            if (strlen(s_results[i].banner) > 0) {
                report_color(COLOR_GREEN, "    %-6d OPEN   %s\n", s_results[i].port, s_results[i].banner);
            } else {
                report_color(COLOR_GREEN, "    %-6d OPEN\n", s_results[i].port);
            }
            json_add_port(s_results[i].port, s_results[i].banner);
            csv_add_port(g_target, s_results[i].port, s_results[i].banner);
        }
    }
    if (open_count == 0) {
        report("    (none found)\n");
    }
    report("\n[*] Scan complete: %d/%d ports open (%lds elapsed)\n",
           open_count, portcount, (long)elapsed);

    if (open_ports_out) *open_ports_out = open_ports; else free(open_ports);
    if (open_count_out) *open_count_out = open_count;

    free(s_results);
    s_results = NULL;
}
