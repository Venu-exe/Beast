/*
 * recon v3.0 - Lightweight multi-threaded recon tool for authorized
 *              security testing / bug bounty engagements.
 *
 * New in v3.0:
 *   - Security header audit, graded A-F (HSTS/CSP/XFO/etc.)          --headers
 *   - CSV report output for spreadsheet-friendly findings             -c
 *
 * Carried over from v2.0:
 *   - TLS certificate inspection (subject/issuer/SANs/expiry)         --tls
 *   - Threaded subdomain enum with CNAME + takeover-candidate flags   -w
 *   - HTTP common-path / content discovery                            -x
 *   - JSON report output (alongside or instead of the text report)    -j
 *   - Multiple targets from a file, one pipeline run per target       -L
 *   - Colorized terminal output (auto-detected, can be disabled)      --no-color
 *   - Rate limiting for brute-force modules                           -d
 *
 * IMPORTANT: Only run this against hosts/domains you own or are explicitly
 * authorized to test (e.g. an in-scope bug bounty target). Unauthorized
 * scanning of systems you don't have permission to test is illegal in most
 * jurisdictions.
 */

#include <getopt.h>
#include "common.h"
#include "report.h"
#include "dns_utils.h"
#include "portscan.h"
#include "subdomain.h"
#include "http_paths.h"
#include "tls_probe.h"
#include "secheaders.h"
#include "json_report.h"
#include "csv_report.h"

/* ---- globals declared in common.h ---- */
char g_target[MAX_HOSTLEN];
char g_target_ip[INET6_ADDRSTRLEN];
int  g_timeout   = DEFAULT_TIMEOUT;
int  g_json_mode = 0;
int  g_csv_mode  = 0;

typedef struct {
    char port_spec[64];
    char wordlist[256];
    char paths_wordlist[256];
    int  do_paths;
    int  do_tls;
    int  do_headers;
    int  threads;
    int  skip_scan;
} RunConfig;

/* colorized ASCII banner, stdout only (kept out of -o/-j report files so
 * those stay clean/parseable). Suppressed by --no-banner or when a
 * non-TTY is detected together with --no-color. */
static void print_banner(void) {
    if (g_use_color) fputs(COLOR_CYAN COLOR_BOLD, stdout);
    printf(" ____   _____ ____ ___  _   _\n");
    printf("|  _ \\ | ____/ ___/ _ \\| \\ | |\n");
    printf("| |_) ||  _|| |  | | | |  \\| |\n");
    printf("|  _ < | |__| |__| |_| | |\\  |\n");
    printf("|_| \\_\\|_____\\____\\___/|_| \\_|\n");
    if (g_use_color) fputs(COLOR_RESET, stdout);
    printf("  DNS + ports + subdomains + TLS + paths   v%s\n\n", RECON_VERSION);
}

static void print_usage(const char *prog) {
    printf("recon v%s - authorized security testing / bug bounty recon\n\n", RECON_VERSION);
    printf("Usage: %s <target> [options]\n", prog);
    printf("       %s -L <targets_file> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p <ports>     \"1-1000\", \"22,80,443\", or \"top\" (default: top)\n");
    printf("  -w <wordlist>  subdomain wordlist file, or \"default\" for the built-in list\n");
    printf("  -x <wordlist>  enable HTTP path discovery; \"default\" or a wordlist file\n");
    printf("  --tls          probe TLS certificates on any TLS-looking open port\n");
    printf("  --headers      audit HTTP security headers (HSTS, CSP, X-Frame-Options, ...) and grade A-F\n");
    printf("  -T <threads>   worker threads for scan/brute-force modules (default %d, max %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  -t <seconds>   per-connection timeout (default %d)\n", DEFAULT_TIMEOUT);
    printf("  -d <ms>        delay between brute-force requests, for politeness/rate-limiting\n");
    printf("  -o <file>      write the text report to a file as well as stdout\n");
    printf("  -j <file>      also write a machine-readable JSON report to file\n");
    printf("  -c <file>      also write a CSV report (one row per subdomain/port/path finding) to file\n");
    printf("  -L <file>      run the full pipeline against every target listed in file (one per line)\n");
    printf("  -s             skip the port scan (DNS / subdomain / paths / tls only)\n");
    printf("  --no-color     disable ANSI colors in terminal output\n");
    printf("  --no-banner    suppress the startup banner (useful when piping/scripting)\n");
    printf("  -V, --version  print version and exit\n");
    printf("  -h, --help     show this help\n\n");
    printf("Examples:\n");
    printf("  %s example.com -w default -x default --tls -j report.json -o report.txt\n", prog);
    printf("  %s -L targets.txt -p top -T 100 -d 50\n\n", prog);
    printf("NOTE: Only scan targets you own or are explicitly authorized to test.\n");
}

/* runs the full recon pipeline against a single target */
static void run_recon_for_target(const char *target, const RunConfig *cfg) {
    strncpy(g_target, target, sizeof(g_target) - 1);
    g_target[sizeof(g_target) - 1] = '\0';

    time_t now = time(NULL);
    report("\n=====================================================\n");
    report(" Recon Report for: %s\n", g_target);
    report(" Generated: %s", ctime(&now));
    report("=====================================================\n");

    json_start_target(g_target);

    if (resolve_host(g_target, g_target_ip, sizeof(g_target_ip)) != 0) {
        report("[-] Cannot proceed without resolved IP address.\n");
        json_end_target();
        return;
    }

    reverse_dns(g_target_ip);

    if (strlen(cfg->wordlist) > 0) {
        run_subdomain_enum(g_target, cfg->wordlist, cfg->threads);
    }

    int *open_ports = NULL;
    int open_count = 0;

    if (!cfg->skip_scan) {
        int *portlist = NULL;
        int portcount = parse_ports(cfg->port_spec, &portlist);
        if (portcount <= 0) {
            report("[-] No valid ports parsed from spec '%s'\n", cfg->port_spec);
        } else {
            run_port_scan(portlist, portcount, cfg->threads, &open_ports, &open_count);
        }
        free(portlist);
    }

    /* TLS probe: any open port conventionally used for TLS */
    if (cfg->do_tls) {
        int tls_ports[] = {443, 8443, 465, 993, 995, 636, 989, 990, 5986, 6443};
        int probed_any = 0;
        for (int i = 0; i < open_count; i++) {
            for (size_t j = 0; j < sizeof(tls_ports)/sizeof(tls_ports[0]); j++) {
                if (open_ports[i] == tls_ports[j]) {
                    tls_probe(g_target, open_ports[i]);
                    probed_any = 1;
                }
            }
        }
        if (!probed_any) {
            /* still worth trying plain 443 even if the scan was skipped or missed it */
            if (tls_probe(g_target, 443) != 0) {
                report("[*] No TLS service found to inspect.\n");
            }
        }
    }

    /* HTTP security header audit: run against the first open web-ish port */
    if (cfg->do_headers) {
        int web_candidates[] = {80, 8080, 443, 8443, 8000, 8888, 3000, 5000};
        int probed = 0;
        for (size_t j = 0; j < sizeof(web_candidates)/sizeof(web_candidates[0]) && !probed; j++) {
            for (int i = 0; i < open_count; i++) {
                if (open_ports[i] == web_candidates[j]) {
                    run_security_header_audit(g_target, open_ports[i]);
                    probed = 1;
                    break;
                }
            }
        }
        if (!probed) {
            report("[*] No open web port found for security header audit (try without -s, or add 80/443 to -p).\n");
        }
    }

    /* HTTP path discovery: run against the first open web-ish port */
    if (cfg->do_paths) {
        int web_candidates[] = {80, 8080, 443, 8443, 8000, 8888, 3000, 5000};
        int probed = 0;
        for (size_t j = 0; j < sizeof(web_candidates)/sizeof(web_candidates[0]) && !probed; j++) {
            for (int i = 0; i < open_count; i++) {
                if (open_ports[i] == web_candidates[j]) {
                    run_path_discovery(g_target, open_ports[i], cfg->paths_wordlist, cfg->threads);
                    probed = 1;
                    break;
                }
            }
        }
        if (!probed) {
            report("[*] No open web port found for path discovery (try without -s, or add 80/443 to -p).\n");
        }
    }

    free(open_ports);

    report("\n[*] Recon complete for %s\n", g_target);
    json_end_target();
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    RunConfig cfg;
    strcpy(cfg.port_spec, "top");
    cfg.wordlist[0] = '\0';
    cfg.paths_wordlist[0] = '\0';
    cfg.do_paths = 0;
    cfg.do_tls = 0;
    cfg.do_headers = 0;
    cfg.threads = DEFAULT_THREADS;
    cfg.skip_scan = 0;

    char outfile_path[256] = "";
    char jsonfile_path[256] = "";
    char csvfile_path[256] = "";
    char targets_file[256] = "";
    int no_color = 0;

    static struct option long_opts[] = {
        {"tls",       no_argument,       0, 1000},
        {"no-color",  no_argument,       0, 1001},
        {"no-banner", no_argument,       0, 1002},
        {"headers",   no_argument,       0, 1003},
        {"version",   no_argument,       0, 'V'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int no_banner = 0;
    while ((opt = getopt_long(argc, argv, "p:w:x:T:t:o:j:c:d:L:sVh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': strncpy(cfg.port_spec, optarg, sizeof(cfg.port_spec)-1); break;
            case 'w': strncpy(cfg.wordlist, optarg, sizeof(cfg.wordlist)-1); break;
            case 'x': strncpy(cfg.paths_wordlist, optarg, sizeof(cfg.paths_wordlist)-1); cfg.do_paths = 1; break;
            case 'T': cfg.threads = atoi(optarg); break;
            case 't': g_timeout = atoi(optarg); break;
            case 'd': g_delay_ms = atoi(optarg); break;
            case 'o': strncpy(outfile_path, optarg, sizeof(outfile_path)-1); break;
            case 'j': strncpy(jsonfile_path, optarg, sizeof(jsonfile_path)-1); g_json_mode = 1; break;
            case 'c': strncpy(csvfile_path, optarg, sizeof(csvfile_path)-1); g_csv_mode = 1; break;
            case 'L': strncpy(targets_file, optarg, sizeof(targets_file)-1); break;
            case 's': cfg.skip_scan = 1; break;
            case 1000: cfg.do_tls = 1; break;
            case 1001: no_color = 1; break;
            case 1002: no_banner = 1; break;
            case 1003: cfg.do_headers = 1; break;
            case 'V': printf("recon v%s\n", RECON_VERSION); return 0;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    g_use_color = !no_color && isatty(fileno(stdout));
    if (!no_banner) print_banner();

    /* collect target list: either -L file, or the first positional arg */
    char **targets = NULL;
    int target_count = 0;

    if (strlen(targets_file) > 0) {
        FILE *f = fopen(targets_file, "r");
        if (!f) {
            fprintf(stderr, "[-] Could not open targets file %s\n", targets_file);
            return 1;
        }
        int cap = 16;
        targets = malloc(sizeof(char *) * cap);
        char line[MAX_HOSTLEN];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strlen(line) == 0) continue;
            if (target_count >= cap) { cap *= 2; targets = realloc(targets, sizeof(char *) * cap); }
            targets[target_count++] = strdup(line);
        }
        fclose(f);
    } else if (optind < argc) {
        targets = malloc(sizeof(char *));
        targets[0] = strdup(argv[optind]);
        target_count = 1;
    }

    if (target_count == 0) {
        fprintf(stderr, "[-] No target specified. Use `%s <target>` or `%s -L <file>`.\n", argv[0], argv[0]);
        print_usage(argv[0]);
        return 1;
    }

    report_open(outfile_path);
    json_start();
    csv_start();

    for (int i = 0; i < target_count; i++) {
        run_recon_for_target(targets[i], &cfg);
        free(targets[i]);
    }
    free(targets);

    if (strlen(jsonfile_path) > 0) {
        json_finish_and_write(jsonfile_path);
        printf("\n[*] JSON report written to %s\n", jsonfile_path);
    }
    if (strlen(csvfile_path) > 0) {
        csv_finish_and_write(csvfile_path);
        printf("[*] CSV report written to %s\n", csvfile_path);
    }
    if (strlen(outfile_path) > 0) {
        printf("[*] Text report written to %s\n", outfile_path);
    }
    report_close();

    return 0;
}
