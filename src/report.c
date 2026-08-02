#include "common.h"
#include "report.h"

FILE *g_outfile = NULL;
pthread_mutex_t g_print_lock = PTHREAD_MUTEX_INITIALIZER;
int g_use_color = 0;
int g_delay_ms  = 0;

void report(const char *fmt, ...) {
    va_list args;
    pthread_mutex_lock(&g_print_lock);

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    if (g_outfile) {
        va_start(args, fmt);
        vfprintf(g_outfile, fmt, args);
        va_end(args);
    }
    pthread_mutex_unlock(&g_print_lock);
}

void report_color(const char *color_code, const char *fmt, ...) {
    char buf[4096];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    pthread_mutex_lock(&g_print_lock);
    if (g_use_color) {
        fputs(color_code, stdout);
        fputs(buf, stdout);
        fputs(COLOR_RESET, stdout);
    } else {
        fputs(buf, stdout);
    }
    if (g_outfile) {
        fputs(buf, g_outfile); /* report file always stays plain text */
    }
    pthread_mutex_unlock(&g_print_lock);
}

void rate_limit_delay(void) {
    if (g_delay_ms > 0) {
        usleep((useconds_t)g_delay_ms * 1000);
    }
}

int report_open(const char *path) {
    if (!path || strlen(path) == 0) return 0;
    g_outfile = fopen(path, "w");
    if (!g_outfile) {
        fprintf(stderr, "[-] Could not open output file %s\n", path);
        return -1;
    }
    return 0;
}

void report_close(void) {
    if (g_outfile) {
        fclose(g_outfile);
        g_outfile = NULL;
    }
}
