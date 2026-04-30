/*
 * http.h — HTTP/1.1 Request Parser & Response Builder
 * ============================================================================
 * HTTP is formatted text over TCP. When your browser visits a URL, it sends:
 *
 *   GET / HTTP/1.1\r\n
 *   Host: localhost:8080\r\n
 *   \r\n
 *
 * And the server sends back:
 *
 *   HTTP/1.1 200 OK\r\n
 *   Content-Type: text/html\r\n
 *   Content-Length: 45\r\n
 *   \r\n
 *   <html>...</html>
 *
 * Our job: parse request text → struct, build response struct → text.
 * ============================================================================
 */

#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>

#define HTTP_MAX_METHOD      8
#define HTTP_MAX_PATH        1024
#define HTTP_MAX_VERSION     16
#define HTTP_MAX_HEADERS     32
#define HTTP_MAX_HEADER_KEY  128
#define HTTP_MAX_HEADER_VAL  512
#define HTTP_MAX_STATUS_TEXT 64

/* Parsed HTTP request */
typedef struct {
    char method[HTTP_MAX_METHOD];
    char path[HTTP_MAX_PATH];
    char version[HTTP_MAX_VERSION];

    struct {
        char key[HTTP_MAX_HEADER_KEY];
        char val[HTTP_MAX_HEADER_VAL];
    } headers[HTTP_MAX_HEADERS];
    int header_count;

    const char *body;
    int body_len;
} http_request_t;

/* HTTP response to build and send */
typedef struct {
    int status;
    char status_text[HTTP_MAX_STATUS_TEXT];

    struct {
        char key[HTTP_MAX_HEADER_KEY];
        char val[HTTP_MAX_HEADER_VAL];
    } headers[HTTP_MAX_HEADERS];
    int header_count;

    const char *body;
    int body_len;
} http_response_t;

/* Parse raw bytes into request struct. Returns 0 on success, -1 on error. */
int http_parse_request(const char *raw, size_t raw_len, http_request_t *req);

/* Serialize response struct into raw bytes. Returns 0 on success. */
int http_build_response(const http_response_t *res, char *out_buf,
                        size_t out_buf_size, size_t *out_len);

/* Add a header to a response */
void http_add_header(http_response_t *res, const char *key, const char *val);

/* Look up a header value by key (case-insensitive). Returns NULL if not found. */
const char *http_get_header(const http_request_t *req, const char *key);

/*
 * ZERO-COPY: Build headers only, return offset where body goes.
 * Body is written directly at out_buf + *header_end_offset.
 * Content-Length is a placeholder that gets patched after body is written.
 */
int http_build_headers_only(int status, const char *status_text,
                            const char *content_type,
                            char *out_buf, size_t out_buf_size,
                            size_t *header_end_offset);

/* Patch the Content-Length placeholder with actual body size */
void http_patch_content_length(char *out_buf, size_t body_len);

#endif /* HTTP_H */
