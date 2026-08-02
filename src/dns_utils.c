#include "common.h"
#include "dns_utils.h"
#include "json_report.h"

int resolve_host(const char *host, char *ip_out, size_t ip_out_len) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        report("[-] DNS resolution failed for %s: %s\n", host, gai_strerror(rc));
        return -1;
    }

    report("[*] DNS resolution for %s:\n", host);
    int have_ip = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void *addr;
        const char *iptype;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            iptype = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            iptype = "IPv6";
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        report("      %-6s %s\n", iptype, ipstr);

        if (strcmp(iptype, "IPv4") == 0) {
            json_add_dns_ip("IPv4", ipstr);
        } else {
            json_add_dns_ip6(ipstr);
        }

        if (!have_ip && p->ai_family == AF_INET) {
            strncpy(ip_out, ipstr, ip_out_len - 1);
            ip_out[ip_out_len - 1] = '\0';
            have_ip = 1;
        }
    }

    if (!have_ip) {
        for (p = res; p != NULL; p = p->ai_next) {
            char ipstr[INET6_ADDRSTRLEN];
            void *addr = (p->ai_family == AF_INET)
                ? (void *)&(((struct sockaddr_in *)p->ai_addr)->sin_addr)
                : (void *)&(((struct sockaddr_in6 *)p->ai_addr)->sin6_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            strncpy(ip_out, ipstr, ip_out_len - 1);
            ip_out[ip_out_len - 1] = '\0';
            break;
        }
    }

    freeaddrinfo(res);
    return 0;
}

void reverse_dns(const char *ip) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        json_set_reverse_dns(NULL);
        return;
    }

    char host[NI_MAXHOST];
    int rc = getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD);
    if (rc == 0) {
        report("[*] Reverse DNS: %s -> %s\n", ip, host);
        json_set_reverse_dns(host);
    } else {
        report("[*] Reverse DNS: %s -> (no PTR record)\n", ip);
        json_set_reverse_dns(NULL);
    }
}

/* resolves a hostname to its first IPv4 + canonical (post-CNAME-chain)
 * name, without printing anything. Returns 0 on success, -1 on failure. */
int resolve_with_canonical(const char *host, char *ip_out, size_t ip_out_len,
                            char *canon_out, size_t canon_out_len) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_out, ip_out_len);

    if (res->ai_canonname) {
        strncpy(canon_out, res->ai_canonname, canon_out_len - 1);
        canon_out[canon_out_len - 1] = '\0';
    } else {
        strncpy(canon_out, host, canon_out_len - 1);
        canon_out[canon_out_len - 1] = '\0';
    }

    freeaddrinfo(res);
    return 0;
}
