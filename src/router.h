/*
 * router.h — Static File Server & Route Handler
 * ============================================================================
 * Maps HTTP request paths to files on disk and figures out the right
 * Content-Type header based on file extension.
 *
 * This is the "application logic" of our web server — given a request,
 * what do we send back?
 * ============================================================================
 */

#ifndef ROUTER_H
#define ROUTER_H

#include "http.h"

/*
 * router_handle_request — Process an HTTP request and build a response.
 *
 * This is the main entry point for request handling:
 *   1. Look at the request path (e.g., "/index.html")
 *   2. Map it to a file in the www/ directory
 *   3. Read the file and build a 200 response
 *   4. Or build a 404 if the file doesn't exist
 *
 * @param www_root: Path to the static files directory (e.g., "./www")
 * @param req:      Parsed HTTP request
 * @param res:      Response struct to fill in
 * @param file_buf: Buffer to store file contents (body points into this)
 * @param file_buf_size: Size of file_buf
 */
void router_handle_request(const char *www_root,
                           const http_request_t *req,
                           http_response_t *res,
                           char *file_buf,
                           size_t file_buf_size);

/*
 * mime_type_for_path — Get the MIME type for a file path.
 *
 * The Content-Type header tells the browser how to interpret the response body.
 * Without it, the browser has to guess (and often guesses wrong).
 *
 * Examples:
 *   "/index.html"  → "text/html"
 *   "/style.css"   → "text/css"
 *   "/app.js"      → "application/javascript"
 *   "/photo.png"   → "image/png"
 *   "/unknown.xyz" → "application/octet-stream" (binary blob)
 */
const char *mime_type_for_path(const char *path);

#endif /* ROUTER_H */
