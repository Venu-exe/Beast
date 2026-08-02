#include "common.h"
#include "tls_probe.h"
#include "net_utils.h"
#include "json_report.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

static void get_cn(X509_NAME *name, char *out, size_t out_len) {
    if (!name || X509_NAME_get_text_by_NID(name, NID_commonName, out, (int)out_len) < 0) {
        snprintf(out, out_len, "(none)");
    }
}

static void format_asn1_time(const ASN1_TIME *t, char *out, size_t out_len) {
    BIO *b = BIO_new(BIO_s_mem());
    if (!b) { snprintf(out, out_len, "(unknown)"); return; }
    ASN1_TIME_print(b, t);
    int n = BIO_read(b, out, (int)out_len - 1);
    out[n > 0 ? n : 0] = '\0';
    BIO_free(b);
}

static void collect_sans(X509 *cert, char *out, size_t out_len) {
    out[0] = '\0';
    GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!sans) return;

    int count = sk_GENERAL_NAME_num(sans);
    for (int i = 0; i < count; i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(sans, i);
        if (gen->type != GEN_DNS) continue;

        const unsigned char *dns_str = ASN1_STRING_get0_data(gen->d.dNSName);
        int len = ASN1_STRING_length(gen->d.dNSName);
        if (len <= 0) continue;

        size_t cur = strlen(out);
        if (cur > 0 && cur + 2 < out_len) { strcat(out, ", "); cur += 2; }
        if (cur + (size_t)len < out_len) {
            strncat(out, (const char *)dns_str, (size_t)len);
        }
    }
    GENERAL_NAMES_free(sans);
}

int tls_probe(const char *host, int port) {
    int sock = connect_with_timeout(g_target_ip, port, g_timeout);
    if (sock < 0) {
        report("[-] TLS probe: could not connect to %s:%d\n", host, port);
        return -1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        report("[-] TLS probe: failed to create SSL context\n");
        close(sock);
        return -1;
    }
    /* recon tool: we want the cert even if untrusted/self-signed, so we
     * don't fail the handshake on verification errors -- we just report
     * what we saw. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host); /* SNI */

    if (SSL_connect(ssl) != 1) {
        report("[-] TLS probe: handshake failed on %s:%d\n", host, port);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return -1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        report("[-] TLS probe: no certificate presented on %s:%d\n", host, port);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return -1;
    }

    char subject_cn[256], issuer_cn[256];
    get_cn(X509_get_subject_name(cert), subject_cn, sizeof(subject_cn));
    get_cn(X509_get_issuer_name(cert), issuer_cn, sizeof(issuer_cn));

    char not_before[128], not_after[128];
    format_asn1_time(X509_get0_notBefore(cert), not_before, sizeof(not_before));
    format_asn1_time(X509_get0_notAfter(cert), not_after, sizeof(not_after));

    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert));

    char sans[1024];
    collect_sans(cert, sans, sizeof(sans));

    report("\n[*] TLS certificate for %s:%d\n", host, port);
    report("    Subject CN : %s\n", subject_cn);
    report("    Issuer CN  : %s\n", issuer_cn);
    report("    Valid from : %s\n", not_before);
    report("    Valid to   : %s\n", not_after);

    if (days < 0) {
        report_color(COLOR_RED, "    Status     : EXPIRED (%d days ago)\n", -days);
    } else if (days < 30) {
        report_color(COLOR_YELLOW, "    Status     : expiring soon (%d days remaining)\n", days);
    } else {
        report("    Status     : valid (%d days remaining)\n", days);
    }

    if (strlen(sans) > 0) {
        report("    SANs       : %s\n", sans);
    }

    json_add_tls(subject_cn, issuer_cn, not_before, not_after, days, sans);

    X509_free(cert);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
