/*
 * main.c — JS Engine Entry Point (with proper memory cleanup)
 * ============================================================================
 * Memory lifecycle:
 *
 *   1. Tokenize  → tokens on STACK (TokenList is stack-allocated)
 *   2. Parse     → AST on HEAP (calloc per node)
 *   3. Evaluate  → strings on HEAP (tracked in string pool)
 *   4. Cleanup:
 *      → ast_free()        frees all AST nodes
 *      → env_free()        frees all environment entries
 *      → js_strings_free() frees all JS string values
 * ============================================================================
 */

#include "src/core/lexer.h"
#include "src/core/parser.h"
#include "src/core/eval.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_INPUT 4096

static void run(const char *source, Env *env, int show_result) {
    /* Step 1: Tokenize — tokens live on the STACK */
    TokenList tokens;
    if (js_tokenize(source, &tokens) < 0) {
        fprintf(stderr, "Tokenization failed\n");
        return;
    }

    /* Step 2: Parse → AST lives on the HEAP */
    AstNode *ast = js_parse(&tokens);
    if (!ast) {
        fprintf(stderr, "Parse failed\n");
        return;
    }

    /* Step 3: Evaluate — may create heap strings */
    JsValue result = js_eval(ast, env);

    /* Show result in REPL mode */
    if (show_result && !js_is_undef(result)) {
        printf("\033[90m→ %s\033[0m\n", js_to_string(result));
    }

    /* Step 4: Free AST — all nodes freed recursively */
    ast_free(ast);
    /* NOTE: we don't free strings here in REPL mode because
     * variables in env may still reference them.
     * Strings are freed when the env is freed or program exits. */
}

static void repl(void) {
    printf("\033[32m");
    printf("   ╦╔═╗  ╔═╗┌┐┌┌─┐┬┌┐┌┌─┐\n");
    printf("   ║╚═╗  ║╣ ││││ ┬││││├┤ \n");
    printf("  ╚╝╚═╝  ╚═╝┘└┘└─┘┴┘└┘└─┘\n");
    printf("\033[0m");
    printf("  \033[90mC + Assembly • Type JS, get results\033[0m\n");
    printf("  \033[90mType 'exit' to quit, 'ast' to show tree\033[0m\n\n");

    Env *global = env_new(NULL);
    char input[MAX_INPUT];  /* STACK allocated — no free needed */
    int show_ast = 0;

    while (1) {
        printf("\033[33mjs>\033[0m ");
        if (!fgets(input, sizeof(input), stdin)) break;

        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') input[len - 1] = '\0';
        if (input[0] == '\0') continue;

        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) break;
        if (strcmp(input, "ast") == 0) { show_ast = !show_ast; printf("AST display: %s\n", show_ast ? "ON" : "OFF"); continue; }
        if (strcmp(input, "mem") == 0) {
            printf("Tracked strings: %d\n", js_strings_count());
            continue;
        }

        if (show_ast) {
            TokenList tokens;
            js_tokenize(input, &tokens);
            AstNode *ast = js_parse(&tokens);
            ast_print(ast, 0);
            ast_free(ast);
        }

        run(input, global, 1);
    }

    /* === CLEANUP: Free everything === */
    env_free(global);       /* free all env entries + their name strings */
    js_strings_free();      /* free ALL tracked JS strings */
    printf("Bye! (freed %d strings)\n", js_strings_count());
}

static void run_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Cannot open: %s\n", path); return; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *source = malloc((size_t)size + 1);  /* HEAP — file content */
    if (!source) { fclose(f); return; }
    fread(source, 1, (size_t)size, f);
    source[size] = '\0';
    fclose(f);

    Env *global = env_new(NULL);

    run(source, global, 0);

    /* === CLEANUP: Free everything === */
    env_free(global);       /* free env entries */
    js_strings_free();      /* free ALL tracked strings */
    free(source);           /* free file content buffer */
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        run_file(argv[1]);
    } else {
        repl();
    }
    return 0;
}
