#ifndef RECON_COMMON_H
#define RECON_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define RECON_VERSION   "2.0"

#define MAX_BANNER      2048
#define MAX_HOSTLEN     256
#define DEFAULT_THREADS 50
#define MAX_THREADS     200
#define DEFAULT_TIMEOUT 2

/* ---- shared runtime config, defined in main.c ---- */
extern char g_target[MAX_HOSTLEN];
extern char g_target_ip[INET6_ADDRSTRLEN];
extern int  g_timeout;
extern int  g_delay_ms;     /* rate-limit delay between brute-force requests */
extern int  g_use_color;    /* 1 = colorize stdout (not the report file)     */
extern int  g_json_mode;    /* 1 = also collect a JSON report               */
extern int  g_csv_mode;     /* 1 = also collect a CSV report                */
extern FILE *g_outfile;
extern pthread_mutex_t g_print_lock;

/* single result of a port probe */
typedef struct {
    int  port;
    int  is_open;
    char banner[MAX_BANNER];
} PortResult;

/* thread-safe printf to stdout + optional plain-text report file */
void report(const char *fmt, ...);

/* same as report(), but the stdout copy is wrapped in an ANSI color code
 * (when g_use_color is set); the file copy is always left plain. */
void report_color(const char *color_code, const char *fmt, ...);

/* sleeps g_delay_ms milliseconds if it's set (used for polite rate limiting) */
void rate_limit_delay(void);

/* ---- ANSI color codes (only used through report_color) ---- */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_BOLD    "\x1b[1m"
#define COLOR_RESET   "\x1b[0m"

#endif /* RECON_COMMON_H */
