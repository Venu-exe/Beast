#include "common.h"
#include "http_probe.h"
#include "net_utils.h"

int is_web_port(int port) {
    int web_ports[] = {80,81,443,8000,8008,8080,8081,8088,8443,8888,3000,5000,9000,9090};
    for (size_t i = 0; i < sizeof(web_ports)/sizeof(web_ports[0]); i++) {
        if (web_ports[i] == port) return 1;
    }
    return 0;
}

void http_probe(int sock, const char *host, PortResult *res) {
    char request[512];
    snprintf(request, sizeof(request),
             "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: recon-tool/1.0\r\nConnection: close\r\n\r\n",
             host);
    if (send(sock, request, strlen(request), 0) < 0) return;

    char buf[MAX_BANNER];
    int n = recv_with_timeout(sock, buf, sizeof(buf), g_timeout);
    if (n <= 0) return;

    /* extract Server header */
    char *server = strcasestr(buf, "Server:");
    if (server) {
        server += 7;
        while (*server == ' ') server++;
        char *end = strstr(server, "\r\n");
        int len = end ? (int)(end - server) : (int)strlen(server);
        if (len > 100) len = 100;
        snprintf(res->banner + strlen(res->banner), sizeof(res->banner) - strlen(res->banner),
                 " | Server: %.*s", len, server);
    }

    /* extract <title> */
    char *title_start = strcasestr(buf, "<title>");
    if (title_start) {
        title_start += 7;
        char *title_end = strcasestr(title_start, "</title>");
        if (title_end && title_end > title_start) {
            int len = (int)(title_end - title_start);
            if (len > 80) len = 80;
            snprintf(res->banner + strlen(res->banner), sizeof(res->banner) - strlen(res->banner),
                     " | Title: %.*s", len, title_start);
        }
    }

    /* status line if nothing else captured */
    if (strlen(res->banner) == 0) {
        char *line_end = strstr(buf, "\r\n");
        int len = line_end ? (int)(line_end - buf) : (int)strlen(buf);
        if (len > 100) len = 100;
        snprintf(res->banner, sizeof(res->banner), "%.*s", len, buf);
    }
}
