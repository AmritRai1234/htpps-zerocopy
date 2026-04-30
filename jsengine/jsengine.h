/*
 * jsengine.h — JS Engine Public API (for embedding in the HTTPS server)
 * ============================================================================
 * This is the interface your HTTPS server uses to run JavaScript.
 *
 *   1. jsengine_init()         — set up the engine
 *   2. jsengine_run()          — execute JS code, get output
 *   3. jsengine_run_file()     — execute a .js file, get output
 *   4. jsengine_template()     — render HTML with {{expressions}}
 *   5. jsengine_cleanup()      — free all memory
 *
 * The engine captures console.log output into a buffer instead of
 * printing to stdout, so the server can send it as HTTP response.
 * ============================================================================
 */

#ifndef JSENGINE_H
#define JSENGINE_H

#include <stddef.h>

/* Initialize the JS engine. Call once at server startup. */
void jsengine_init(void);

/*
 * Run JS code and capture output.
 *
 * @param source     JavaScript source code
 * @param req_json   JSON string with request data (available as __request in JS)
 * @param output     Buffer to write captured console.log output
 * @param output_size Size of output buffer
 * @return           Number of bytes written to output, or -1 on error
 */
int jsengine_run(const char *source, const char *req_json,
                 char *output, size_t output_size);

/*
 * Run a .js file and capture output.
 */
int jsengine_run_file(const char *filepath, const char *req_json,
                      char *output, size_t output_size);

/*
 * Render an HTML template with {{expression}} placeholders.
 *
 * @param html_template  HTML with {{...}} markers
 * @param js_data        JS code to run first (sets up variables)
 * @param output         Buffer for rendered HTML
 * @param output_size    Size of output buffer
 * @return               Number of bytes written
 */
int jsengine_template(const char *html_template, const char *js_data,
                      char *output, size_t output_size);

/* Free all engine memory. Call at server shutdown. */
void jsengine_cleanup(void);

#endif /* JSENGINE_H */
