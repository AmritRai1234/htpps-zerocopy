/*
 * http.c — HTTP/1.1 Parser & Response Builder (ZERO-COPY edition)
 * ============================================================================
 * Added http_build_headers_inplace() — writes headers into a buffer and
 * returns the offset where the body starts. The caller writes the body
 * directly at that offset, eliminating the memcpy in http_build_response().
 * ============================================================================
 */

#include "http.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

static const char *find_in_buf(const char *buf, size_t buf_len, const char *needle)
{
    if (!buf || !needle) return NULL;
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > buf_len) return NULL;

    for (size_t i = 0; i <= buf_len - needle_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) {
            return buf + i;
        }
    }
    return NULL;
}

int http_parse_request(const char *raw, size_t raw_len, http_request_t *req)
{
    memset(req, 0, sizeof(*req));

    const char *line_end = find_in_buf(raw, raw_len, "\r\n");
    if (!line_end) return -1;

    size_t line_len = (size_t)(line_end - raw);
    if (line_len >= 2048) return -1;

    char line[2048];
    memcpy(line, raw, line_len);
    line[line_len] = '\0';

    if (sscanf(line, "%7s %1023s %15s", req->method, req->path, req->version) != 3) {
        return -1;
    }

    const char *pos = line_end + 2;
    size_t remaining = raw_len - (size_t)(pos - raw);

    while (remaining >= 2 && req->header_count < HTTP_MAX_HEADERS) {
        if (pos[0] == '\r' && pos[1] == '\n') {
            pos += 2;
            break;
        }

        const char *hdr_end = find_in_buf(pos, remaining, "\r\n");
        if (!hdr_end) break;

        size_t hdr_len = (size_t)(hdr_end - pos);

        const char *colon = memchr(pos, ':', hdr_len);
        if (colon) {
            size_t key_len = (size_t)(colon - pos);
            const char *val_start = colon + 1;

            while (val_start < hdr_end && *val_start == ' ') val_start++;

            size_t val_len = (size_t)(hdr_end - val_start);

            if (key_len < HTTP_MAX_HEADER_KEY && val_len < HTTP_MAX_HEADER_VAL) {
                memcpy(req->headers[req->header_count].key, pos, key_len);
                req->headers[req->header_count].key[key_len] = '\0';
                memcpy(req->headers[req->header_count].val, val_start, val_len);
                req->headers[req->header_count].val[val_len] = '\0';
                req->header_count++;
            }
        }

        pos = hdr_end + 2;
        remaining = raw_len - (size_t)(pos - raw);
    }

    remaining = raw_len - (size_t)(pos - raw);
    if (remaining > 0) {
        req->body = pos;
        req->body_len = (int)remaining;
    }

    return 0;
}

int http_build_response(const http_response_t *res, char *out_buf, size_t out_buf_size, size_t *out_len)
{
    int written = snprintf(out_buf, out_buf_size,
        "HTTP/1.1 %d %s\r\n", res->status, res->status_text);

    if (written < 0 || (size_t)written >= out_buf_size) return -1;

    size_t offset = (size_t)written;

    for (int i = 0; i < res->header_count; i++) {
        written = snprintf(out_buf + offset, out_buf_size - offset,
            "%s: %s\r\n", res->headers[i].key, res->headers[i].val);
        if (written < 0 || offset + (size_t)written >= out_buf_size) return -1;
        offset += (size_t)written;
    }

    if (offset + 2 >= out_buf_size) return -1;
    out_buf[offset++] = '\r';
    out_buf[offset++] = '\n';

    if (res->body && res->body_len > 0) {
        if (offset + (size_t)res->body_len > out_buf_size) return -1;
        memcpy(out_buf + offset, res->body, (size_t)res->body_len);
        offset += (size_t)res->body_len;
    }

    *out_len = offset;
    return 0;
}

/*
 * === ZERO-COPY RESPONSE BUILDER ===
 *
 * Writes ONLY the headers into out_buf, leaving space for the body.
 * Returns the byte offset where the body should be written.
 *
 * The caller writes the body directly at out_buf + returned_offset,
 * then calls http_finalize_zerocopy() to patch in Content-Length.
 *
 * This eliminates the memcpy of the body that http_build_response() does.
 */
int http_build_headers_only(int status, const char *status_text,
                            const char *content_type,
                            char *out_buf, size_t out_buf_size,
                            size_t *header_end_offset)
{
    if (!status_text || !content_type || !out_buf || !header_end_offset) return -1;
    if (out_buf_size < 128) return -1;  /* too small for any valid response */

    *header_end_offset = 0;  /* initialize output to safe value */
    /*
     * We leave Content-Length as a fixed-width field so we can patch it
     * later without shifting the buffer.
     * "Content-Length: 00000000\r\n" = 28 bytes, fits up to 99MB
     */
    int written = snprintf(out_buf, out_buf_size,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: 00000000\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text, content_type);

    if (written < 0 || (size_t)written >= out_buf_size) return -1;

    *header_end_offset = (size_t)written;
    return 0;
}

/*
 * Patch the Content-Length field in the pre-built headers.
 * Finds "Content-Length: 00000000" and overwrites the zeros.
 */
void http_patch_content_length(char *out_buf, size_t body_len)
{
    if (!out_buf) return;
    char *cl = strstr(out_buf, "Content-Length: 00000000");
    if (!cl) return;  /* placeholder not found — nothing to patch */

    /* Overwrite the 8-digit placeholder with actual length */
    char len_str[9];
    memset(len_str, 0, sizeof(len_str));
    snprintf(len_str, sizeof(len_str), "%8zu", body_len);
    memcpy(cl + 16, len_str, 8);  /* "Content-Length: " is 16 chars */
}

void http_add_header(http_response_t *res, const char *key, const char *val)
{
    if (res->header_count >= HTTP_MAX_HEADERS) return;

    strncpy(res->headers[res->header_count].key, key, HTTP_MAX_HEADER_KEY - 1);
    res->headers[res->header_count].key[HTTP_MAX_HEADER_KEY - 1] = '\0';
    strncpy(res->headers[res->header_count].val, val, HTTP_MAX_HEADER_VAL - 1);
    res->headers[res->header_count].val[HTTP_MAX_HEADER_VAL - 1] = '\0';
    res->header_count++;
}

const char *http_get_header(const http_request_t *req, const char *key)
{
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].key, key) == 0) {
            return req->headers[i].val;
        }
    }
    return NULL;
}
