#include "common.h"
#include "subdomain.h"
#include "dns_utils.h"
#include "json_report.h"
#include "csv_report.h"

const char *default_subs[] = {
    "www","mail","ftp","admin","api","dev","test","staging","stage",
    "blog","shop","portal","vpn","ns1","ns2","m","mobile","secure",
    "cpanel","webmail","remote","app","apps","beta","demo","docs",
    "git","gitlab","jenkins","jira","confluence","internal","intranet",
    "old","new","support","status","cdn","static","img","images",
    "media","download","downloads","forum","chat","mx","smtp","pop",
    "imap","autodiscover","auth","sso","login","dashboard","panel",
    "monitor","grafana","kibana","db","sql","mysql","redis","cache",
    NULL
};

/* Hostname fragments belonging to third-party services that are commonly
 * involved in "dangling CNAME" subdomain takeovers when the referenced
 * resource has been deleted/unclaimed. A match here is informational only
 * -- it means "this points at a service worth checking manually", not a
 * confirmed vulnerability. */
static const char *takeover_fingerprints[] = {
    ".github.io", ".herokuapp.com", ".s3.amazonaws.com", ".s3-website",
    ".cloudfront.net", ".azurewebsites.net", ".trafficmanager.net",
    ".cloudapp.net", ".bitbucket.io", ".surge.sh", ".netlify.app",
    ".zendesk.com", ".myshopify.com", ".fastly.net", ".wpengine.com",
    ".pantheonsite.io", ".ghost.io", ".helpscoutdocs.com",
    ".statuspage.io", ".readme.io", ".webflow.io", ".unbouncepages.com",
    ".tilda.ws", ".strikinglydns.com", ".firebaseapp.com",
    NULL
};

static int matches_takeover_fingerprint(const char *canonical) {
    for (int i = 0; takeover_fingerprints[i] != NULL; i++) {
        if (strcasestr(canonical, takeover_fingerprints[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* ---- shared worker-pool state ---- */
static char **s_words = NULL;
static int s_word_count = 0;
static int s_next_index = 0;
static char s_domain[MAX_HOSTLEN];
static pthread_mutex_t s_index_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_found_count = 0;
static pthread_mutex_t s_found_lock = PTHREAD_MUTEX_INITIALIZER;

static void *sub_worker(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&s_index_lock);
        int idx = s_next_index;
        if (idx >= s_word_count) {
            pthread_mutex_unlock(&s_index_lock);
            break;
        }
        s_next_index++;
        pthread_mutex_unlock(&s_index_lock);

        char fqdn[MAX_HOSTLEN];
        snprintf(fqdn, sizeof(fqdn), "%.200s.%.50s", s_words[idx], s_domain);

        char ip[INET6_ADDRSTRLEN];
        char canon[MAX_HOSTLEN];
        if (resolve_with_canonical(fqdn, ip, sizeof(ip), canon, sizeof(canon)) == 0) {
            int flagged = matches_takeover_fingerprint(canon) && strcasecmp(canon, fqdn) != 0;

            if (flagged) {
                report_color(COLOR_YELLOW, "    [+] %s -> %s  (CNAME: %s -- review for possible dangling CNAME)\n",
                              fqdn, ip, canon);
            } else if (strcasecmp(canon, fqdn) != 0) {
                report_color(COLOR_GREEN, "    [+] %s -> %s  (CNAME: %s)\n", fqdn, ip, canon);
            } else {
                report_color(COLOR_GREEN, "    [+] %s -> %s\n", fqdn, ip);
            }

            json_add_subdomain(fqdn, ip, canon, flagged);
            csv_add_subdomain(s_domain, fqdn, ip, canon, flagged);

            pthread_mutex_lock(&s_found_lock);
            s_found_count++;
            pthread_mutex_unlock(&s_found_lock);
        }

        rate_limit_delay();
    }
    return NULL;
}

void run_subdomain_enum(const char *domain, const char *wordlist_path, int threads) {
    report("\n[*] Starting subdomain enumeration for %s\n", domain);

    strncpy(s_domain, domain, sizeof(s_domain) - 1);
    s_domain[sizeof(s_domain) - 1] = '\0';

    /* load words either from the built-in list or a file, into s_words */
    char **words = NULL;
    int count = 0;
    int cap = 256;

    FILE *f = NULL;
    if (wordlist_path && strcasecmp(wordlist_path, "default") != 0) {
        f = fopen(wordlist_path, "r");
        if (!f) {
            report("[-] Could not open wordlist %s, falling back to default list\n", wordlist_path);
        }
    }

    words = malloc(sizeof(char *) * cap);
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strlen(line) == 0) continue;
            if (count >= cap) { cap *= 2; words = realloc(words, sizeof(char *) * cap); }
            words[count++] = strdup(line);
        }
        fclose(f);
    } else {
        for (int i = 0; default_subs[i] != NULL; i++) {
            if (count >= cap) { cap *= 2; words = realloc(words, sizeof(char *) * cap); }
            words[count++] = strdup(default_subs[i]);
        }
    }

    s_words = words;
    s_word_count = count;
    s_next_index = 0;
    s_found_count = 0;

    int nthreads = threads;
    if (nthreads > MAX_THREADS) nthreads = MAX_THREADS;
    if (nthreads > count) nthreads = count;
    if (nthreads < 1) nthreads = 1;

    pthread_t tids[MAX_THREADS];
    for (int i = 0; i < nthreads; i++) pthread_create(&tids[i], NULL, sub_worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);

    report("[*] Subdomain enumeration complete: %d found (checked %d candidates)\n",
           s_found_count, count);

    for (int i = 0; i < count; i++) free(words[i]);
    free(words);
}
