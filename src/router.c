/*
 * router.c — Static File Server Implementation
 * ============================================================================
 * Serves files from a directory on disk. This is what nginx, Apache, and
 * every static file server does — map URL paths to filesystem paths.
 *
 * Security note: In a real server, you'd need to sanitize paths to prevent
 * directory traversal attacks (e.g., "/../../../etc/passwd"). We do a basic
 * check here, but this is a learning project, not production code.
 * ============================================================================
 */

#include "router.h"
#include <stdio.h>
#include <string.h>

/*
 * MIME type table.
 *
 * When a browser receives a response, it looks at Content-Type to decide
 * how to render it. If we send an HTML file with Content-Type: text/plain,
 * the browser will show the raw HTML tags instead of rendering the page.
 *
 * MIME = Multipurpose Internet Mail Extensions — originally designed for
 * email attachments, now used everywhere in HTTP.
 */
static const struct {
    const char *ext;
    const char *mime;
} mime_table[] = {
    { ".html", "text/html; charset=utf-8" },
    { ".htm",  "text/html; charset=utf-8" },
    { ".css",  "text/css; charset=utf-8" },
    { ".js",   "application/javascript; charset=utf-8" },
    { ".json", "application/json; charset=utf-8" },
    { ".txt",  "text/plain; charset=utf-8" },
    { ".png",  "image/png" },
    { ".jpg",  "image/jpeg" },
    { ".jpeg", "image/jpeg" },
    { ".gif",  "image/gif" },
    { ".svg",  "image/svg+xml" },
    { ".ico",  "image/x-icon" },
    { ".woff", "font/woff" },
    { ".woff2","font/woff2" },
    { ".pdf",  "application/pdf" },
    { NULL, NULL }
};

#include "../jsengine/jsengine.h"
#include <strings.h>

/* ... (rest of existing includes above) ... */

const char *mime_type_for_path(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    for (int i = 0; mime_table[i].ext != NULL; i++) {
        if (strcasecmp(dot, mime_table[i].ext) == 0)
            return mime_table[i].mime;
    }
    return "application/octet-stream";
}

void router_handle_request(const char *www_root,
                           const http_request_t *req,
                           http_response_t *res,
                           char *file_buf,
                           size_t file_buf_size)
{
    memset(res, 0, sizeof(*res));

    /* Security: block directory traversal */
    if (strstr(req->path, "..") != NULL) {
        res->status = 403;
        snprintf(res->status_text, sizeof(res->status_text), "Forbidden");
        const char *body = "<h1>403 Forbidden</h1>";
        res->body = body;
        res->body_len = (int)strlen(body);
        http_add_header(res, "Content-Type", "text/html");
        char cl[32]; snprintf(cl, sizeof(cl), "%d", res->body_len);
        http_add_header(res, "Content-Length", cl);
        return;
    }

    /*
     * === API ROUTE: /api/* ===
     * Maps /api/hello → www/api/hello.js
     * Runs JS file through our engine, returns output as HTTP response
     */
    if (strncmp(req->path, "/api/", 5) == 0) {
        char js_path[2048];
        snprintf(js_path, sizeof(js_path), "%s%s.js", www_root, req->path);

        /* Build request JSON to pass to JS */
        char req_json[2048];
        snprintf(req_json, sizeof(req_json),
            "{\"method\":\"%s\",\"path\":\"%s\"}",
            req->method, req->path);

        /* Run JS file, capture output */
        int len = jsengine_run_file(js_path, req_json, file_buf, file_buf_size);

        if (len >= 0) {
            res->status = 200;
            snprintf(res->status_text, sizeof(res->status_text), "OK");
            res->body = file_buf;
            res->body_len = len;
            http_add_header(res, "Content-Type", "application/json; charset=utf-8");
            http_add_header(res, "Access-Control-Allow-Origin", "*");
        } else {
            res->status = 500;
            snprintf(res->status_text, sizeof(res->status_text), "Internal Server Error");
            const char *err = "{\"error\":\"JS execution failed\"}";
            int elen = (int)strlen(err);
            memcpy(file_buf, err, (size_t)elen);
            res->body = file_buf;
            res->body_len = elen;
            http_add_header(res, "Content-Type", "application/json");
        }
        char cl[32]; snprintf(cl, sizeof(cl), "%d", res->body_len);
        http_add_header(res, "Content-Length", cl);
        http_add_header(res, "Connection", "close");
        return;
    }

    /*
     * === TEMPLATE ROUTE: .html files with JS ===
     * If an HTML file has a matching .js file, render as template
     */

    /* Map URL path to filesystem path */
    char filepath[2048];
    if (strcmp(req->path, "/") == 0) {
        snprintf(filepath, sizeof(filepath), "%s/index.html", www_root);
    } else {
        snprintf(filepath, sizeof(filepath), "%s%s", www_root, req->path);
    }

    /*
     * Read the file.
     *
     * fopen → fread → fclose. Classic C file I/O.
     * "rb" = read binary — important for images and other non-text files.
     */
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        /* File not found → 404 */
        res->status = 404;
        snprintf(res->status_text, sizeof(res->status_text), "Not Found");

        int len = snprintf(file_buf, file_buf_size,
            "<html><head><title>404</title></head>"
            "<body style=\"font-family:monospace;text-align:center;padding:50px;\">"
            "<h1>404 — Not Found</h1>"
            "<p>%s doesn't exist on this server.</p>"
            "</body></html>",
            req->path);

        res->body = file_buf;
        res->body_len = len;
        http_add_header(res, "Content-Type", "text/html; charset=utf-8");
        char cl[32];
        snprintf(cl, sizeof(cl), "%d", res->body_len);
        http_add_header(res, "Content-Length", cl);
        return;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < 0 || (size_t)file_size >= file_buf_size) {
        fclose(fp);
        res->status = 500;
        snprintf(res->status_text, sizeof(res->status_text), "Internal Server Error");
        const char *body = "<h1>500 — File too large</h1>";
        res->body = body;
        res->body_len = (int)strlen(body);
        http_add_header(res, "Content-Type", "text/html");
        char cl[32];
        snprintf(cl, sizeof(cl), "%d", res->body_len);
        http_add_header(res, "Content-Length", cl);
        return;
    }

    /* Read file contents into buffer */
    size_t bytes_read = fread(file_buf, 1, (size_t)file_size, fp);
    fclose(fp);

    /* Build 200 OK response */
    res->status = 200;
    snprintf(res->status_text, sizeof(res->status_text), "OK");
    res->body = file_buf;
    res->body_len = (int)bytes_read;

    http_add_header(res, "Content-Type", mime_type_for_path(filepath));
    char cl[32];
    snprintf(cl, sizeof(cl), "%d", res->body_len);
    http_add_header(res, "Content-Length", cl);
    http_add_header(res, "Connection", "close");
}
