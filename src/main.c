/*
 * main.c — HTPPS Server (ZERO-COPY Edition)
 * ============================================================================
 * KEY DIFFERENCE: The JS engine and file server write DIRECTLY into the
 * send buffer. No intermediate file_buf. No memcpy between layers.
 *
 * Old path (6 copies):
 *   recv→buf → parse → disk→file_buf → JS→file_buf → file_buf→send_buf → send
 *
 * New path (4 copies):
 *   recv→buf → parse → disk→send_buf(body) OR JS→send_buf(body) → send
 *
 * The body lands directly where it will be sent from. Zero wasted copies.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "tcp.h"
#include "http.h"
#include "router.h"
#include "tls/tls.h"
#include "crypto/fast/fast_crypto.h"
#include "fast/fast_io.h"

/* Buffer sizes */
#define RECV_BUF_SIZE   (64 * 1024)
#define SEND_BUF_SIZE   (1024 * 1024)

/* Max reasonable header size — body starts after this */
#define MAX_HEADER_SIZE 512

/* Defaults */
#define DEFAULT_HTTP_PORT   8080
#define DEFAULT_HTTPS_PORT  4443
#define DEFAULT_WWW         "./www"
#define DEFAULT_CERT        "./certs/cert.pem"
#define DEFAULT_KEY         "./certs/key.pem"

/*
 * Pre-allocated buffers — allocated ONCE, reused for every request.
 * NOTE: No file_buf! The body goes directly into g_send_buf.
 */
static char g_recv_buf[RECV_BUF_SIZE];
static char g_send_buf[SEND_BUF_SIZE];

/*
 * MIME type lookup (duplicated from router.c for inlining)
 */
static const char *quick_mime(const char *path)
{
    if (!path) return "application/octet-stream";
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0)
        return "text/html; charset=utf-8";
    if (strcmp(dot, ".css") == 0)  return "text/css; charset=utf-8";
    if (strcmp(dot, ".js") == 0)   return "application/javascript; charset=utf-8";
    if (strcmp(dot, ".json") == 0) return "application/json; charset=utf-8";
    if (strcmp(dot, ".png") == 0)  return "image/png";
    if (strcmp(dot, ".jpg") == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(dot, ".svg") == 0)  return "image/svg+xml";
    if (strcmp(dot, ".ico") == 0)  return "image/x-icon";
    return "application/octet-stream";
}

#include "../jsengine/jsengine.h"

/*
 * handle_http_zerocopy — THE ZERO-COPY HTTP HANDLER
 *
 * Instead of: file → file_buf → send_buf → kernel
 * We do:      file → send_buf → kernel
 *
 * The body is written directly at g_send_buf + header_offset.
 * No intermediate buffer. No memcpy between layers.
 */
static void handle_http_zerocopy(int client_fd, const char *www_root)
{
    if (client_fd < 0 || !www_root) goto done;

    /*
     * SECURITY: Wipe buffers before each request.
     * Prevents previous client's data from leaking to the next client
     * if we accidentally send more bytes than the current response.
     */
    memset(g_recv_buf, 0, RECV_BUF_SIZE);
    memset(g_send_buf, 0, SEND_BUF_SIZE);

    /* Direct syscall recv — no libc */
    int64_t bytes_received = fast_recv(client_fd, g_recv_buf, RECV_BUF_SIZE - 1);
    if (bytes_received <= 0) goto done;
    g_recv_buf[bytes_received] = '\0';

    /* Parse request in-place (no copy — parser reads from recv_buf directly) */
    http_request_t req;
    if (http_parse_request(g_recv_buf, (size_t)bytes_received, &req) < 0) goto done;

    /* --- Determine what to serve --- */

    /* Security: block directory traversal */
    if (strstr(req.path, "..") != NULL) {
        const char *body = "<h1>403 Forbidden</h1>";
        size_t hdr_off = 0;
        if (http_build_headers_only(403, "Forbidden", "text/html",
                                    g_send_buf, SEND_BUF_SIZE, &hdr_off) < 0) goto done;
        size_t blen = strlen(body);
        if (hdr_off + blen > SEND_BUF_SIZE) goto done;  /* bounds check */
        memcpy(g_send_buf + hdr_off, body, blen);
        http_patch_content_length(g_send_buf, blen);
        fast_send(client_fd, g_send_buf, hdr_off + blen);
        goto done;
    }

    /* === API ROUTE: /api/* === */
    if (strncmp(req.path, "/api/", 5) == 0) {
        char js_path[2048];
        memset(js_path, 0, sizeof(js_path));
        snprintf(js_path, sizeof(js_path), "%s%s.js", www_root, req.path);

        char req_json[2048];
        memset(req_json, 0, sizeof(req_json));
        snprintf(req_json, sizeof(req_json),
            "{\"method\":\"%s\",\"path\":\"%s\"}", req.method, req.path);

        /* Build headers first — get offset where body goes */
        size_t hdr_off = 0;
        if (http_build_headers_only(200, "OK", "application/json; charset=utf-8",
                                    g_send_buf, SEND_BUF_SIZE, &hdr_off) < 0) goto done;

        /*
         * ZERO-COPY: JS engine writes DIRECTLY into g_send_buf + hdr_off.
         * No intermediate buffer. JS output lands exactly where send() reads.
         */
        int body_len = jsengine_run_file(js_path, req_json,
                                          g_send_buf + hdr_off,
                                          SEND_BUF_SIZE - hdr_off);

        if (body_len < 0) {
            /* Error — wipe buffer, rebuild with error body */
            memset(g_send_buf, 0, SEND_BUF_SIZE);
            const char *err = "{\"error\":\"JS execution failed\"}";
            size_t elen = strlen(err);
            if (http_build_headers_only(500, "Internal Server Error",
                                        "application/json",
                                        g_send_buf, SEND_BUF_SIZE, &hdr_off) < 0) goto done;
            if (hdr_off + elen > SEND_BUF_SIZE) goto done;
            memcpy(g_send_buf + hdr_off, err, elen);
            http_patch_content_length(g_send_buf, elen);
            fast_send(client_fd, g_send_buf, hdr_off + elen);
        } else {
            /* Patch content-length with actual body size, send */
            http_patch_content_length(g_send_buf, (size_t)body_len);
            fast_send(client_fd, g_send_buf, hdr_off + (size_t)body_len);
        }
        goto done;
    }

    /* === STATIC FILE ROUTE === */
    {
        char filepath[2048];
        memset(filepath, 0, sizeof(filepath));
        int path_len;
        if (strcmp(req.path, "/") == 0) {
            path_len = snprintf(filepath, sizeof(filepath), "%s/index.html", www_root);
        } else {
            path_len = snprintf(filepath, sizeof(filepath), "%s%s", www_root, req.path);
        }
        /* Check snprintf truncation — path too long */
        if (path_len < 0 || (size_t)path_len >= sizeof(filepath)) goto done;

        /* Build headers — body will go at hdr_off */
        size_t hdr_off = 0;
        if (http_build_headers_only(200, "OK", quick_mime(filepath),
                                    g_send_buf, SEND_BUF_SIZE, &hdr_off) < 0) goto done;

        /*
         * ZERO-COPY: fread() writes DIRECTLY into g_send_buf + hdr_off.
         * The file contents land exactly where send() will read them.
         * No file_buf. No memcpy.
         */
        FILE *fp = fopen(filepath, "rb");
        if (!fp) {
            memset(g_send_buf, 0, SEND_BUF_SIZE);  /* wipe stale headers */
            const char *body = "<h1>404 \xe2\x80\x94 Not Found</h1>";
            size_t blen = strlen(body);
            if (http_build_headers_only(404, "Not Found", "text/html",
                                        g_send_buf, SEND_BUF_SIZE, &hdr_off) < 0) goto done;
            if (hdr_off + blen > SEND_BUF_SIZE) goto done;
            memcpy(g_send_buf + hdr_off, body, blen);
            http_patch_content_length(g_send_buf, blen);
            fast_send(client_fd, g_send_buf, hdr_off + blen);
            goto done;
        }

        /* Read file directly into send buffer body region */
        size_t max_body = SEND_BUF_SIZE - hdr_off;
        size_t body_len = fread(g_send_buf + hdr_off, 1, max_body, fp);
        fclose(fp);
        fp = NULL;  /* NULL after close — prevent double-use */

        /* Patch content-length, send entire buffer in one syscall */
        http_patch_content_length(g_send_buf, body_len);
        fast_send(client_fd, g_send_buf, hdr_off + body_len);
    }

done:
    fast_close(client_fd);
}

/*
 * handle_https_client — HTTPS with TLS (unchanged for now)
 */
static void handle_https_client(int client_fd, const char *client_ip,
                                const char *www_root,
                                const char *cert_path, const char *key_path)
{
    if (client_fd < 0 || !www_root || !cert_path || !key_path) {
        if (client_fd >= 0) tcp_close(client_fd);
        return;
    }

    char *recv_buf = malloc(RECV_BUF_SIZE);
    char *send_buf = malloc(SEND_BUF_SIZE);
    char *file_buf = malloc(512 * 1024);
    if (!recv_buf || !send_buf || !file_buf) goto cleanup;

    /* Zero all buffers — no stale data from previous requests */
    memset(recv_buf, 0, RECV_BUF_SIZE);
    memset(send_buf, 0, SEND_BUF_SIZE);
    memset(file_buf, 0, 512 * 1024);

    tls_session sess;
    memset(&sess, 0, sizeof(sess));  /* zero TLS session struct */
    if (tls_session_init(&sess, client_fd, cert_path, key_path) < 0) {
        goto cleanup;
    }

    if (tls_handshake(&sess) < 0) {
        tls_session_cleanup(&sess);
        goto cleanup;
    }

    int bytes_received = tls_read(&sess, (uint8_t *)recv_buf, RECV_BUF_SIZE - 1);
    if (bytes_received <= 0) {
        tls_session_cleanup(&sess);
        goto cleanup;
    }
    recv_buf[bytes_received] = '\0';

    http_request_t req;
    memset(&req, 0, sizeof(req));
    if (http_parse_request(recv_buf, (size_t)bytes_received, &req) < 0) {
        tls_session_cleanup(&sess);
        goto cleanup;
    }

    http_response_t res;
    memset(&res, 0, sizeof(res));
    router_handle_request(www_root, &req, &res, file_buf, 512 * 1024);

    size_t response_len = 0;
    if (http_build_response(&res, send_buf, SEND_BUF_SIZE, &response_len) < 0) {
        tls_session_cleanup(&sess);
        goto cleanup;
    }

    tls_write(&sess, (const uint8_t *)send_buf, response_len);
    tls_session_cleanup(&sess);

cleanup:
    /*
     * SECURITY: Wipe buffers before freeing.
     * Prevents sensitive data (TLS keys, plaintext, session data)
     * from lingering in freed heap memory where it could be
     * recovered by a later allocation.
     */
    if (recv_buf) { memset(recv_buf, 0, RECV_BUF_SIZE); free(recv_buf); }
    if (send_buf) { memset(send_buf, 0, SEND_BUF_SIZE); free(send_buf); }
    if (file_buf) { memset(file_buf, 0, 512 * 1024);    free(file_buf); }
    recv_buf = NULL;
    send_buf = NULL;
    file_buf = NULL;
    tcp_close(client_fd);
}

int main(int argc, char *argv[])
{
    const char *www_root = DEFAULT_WWW;
    const char *cert_path = DEFAULT_CERT;
    const char *key_path = DEFAULT_KEY;
    uint16_t https_port = DEFAULT_HTTPS_PORT;
    uint16_t http_port = DEFAULT_HTTP_PORT;
    int mode = 2;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--http") == 0) {
            mode = 0;
        } else if (strcmp(argv[i], "--https") == 0) {
            mode = 1;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            https_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            http_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--www") == 0 && i + 1 < argc) {
            www_root = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_path = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            return 0;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    /* Detect and enable hardware crypto acceleration */
    crypto_fast_init();

    printf("╔═══════════════════════════════════════════╗\n");
    printf("║   ⚡ HTPPS Server (ZERO-COPY Edition)     ║\n");
    printf("║   No memcpy between JS ↔ HTTP ↔ send     ║\n");
    printf("╠═══════════════════════════════════════════╣\n");
    if (mode != 0) {
        printf("║   HTTPS: https://localhost:%-5u          ║\n", https_port);
    }
    if (mode != 1) {
        printf("║   HTTP:  http://localhost:%-5u           ║\n", http_port);
    }
    printf("║   Root:  %-33s║\n", www_root);
    printf("╚═══════════════════════════════════════════╝\n\n");

    if (mode == 0) {
        int server_fd = tcp_listen(http_port);
        if (server_fd < 0) return 1;

        while (1) {
            char client_ip[64] = {0};
            int client_fd = tcp_accept(server_fd, client_ip, sizeof(client_ip));
            if (client_fd < 0) continue;
            handle_http_zerocopy(client_fd, www_root);
        }
    } else {
        int https_fd = tcp_listen(https_port);
        if (https_fd < 0) return 1;

        printf("[INFO] Serving HTTPS on port %u (use --http for plain HTTP)\n\n", https_port);

        while (1) {
            char client_ip[64] = {0};
            int client_fd = tcp_accept(https_fd, client_ip, sizeof(client_ip));
            if (client_fd < 0) continue;
            handle_https_client(client_fd, client_ip, www_root, cert_path, key_path);
        }
    }

    return 0;
}
