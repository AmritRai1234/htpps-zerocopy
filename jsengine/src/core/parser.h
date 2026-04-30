/*
 * parser.h — AST Builder (Memory-Optimized)
 * ============================================================================
 * Uses pointers + dynamic allocation instead of static arrays.
 * Each node only allocates what it actually needs.
 *
 * BEFORE: AstNode = 2072 bytes (static arrays, mostly empty)
 * AFTER:  AstNode = ~48 bytes (pointers to heap data)
 * ============================================================================
 */

#ifndef JS_PARSER_H
#define JS_PARSER_H

#include "lexer.h"
#include "value.h"

typedef enum {
    NODE_NUM,           /* literal number: 42 */
    NODE_STR,           /* literal string: "hello" */
    NODE_BOOL,          /* true / false */
    NODE_NULL,          /* null */
    NODE_UNDEF,         /* undefined */
    NODE_IDENT,         /* variable name: x */
    NODE_BINOP,         /* a + b, a * b, etc. */
    NODE_UNARY,         /* -x, !x */
    NODE_LET,           /* let x = expr */
    NODE_ASSIGN,        /* x = expr */
    NODE_CALL,          /* func(args) */
    NODE_BLOCK,         /* { statements } */
    NODE_IF,            /* if (cond) { ... } else { ... } */
    NODE_WHILE,         /* while (cond) { ... } */
    NODE_FOR,           /* for (init; cond; update) { ... } */
    NODE_FUNC,          /* function(params) { body } */
    NODE_RETURN,        /* return expr */
    NODE_ARROW,         /* (x) => expr */
    NODE_MEMBER,        /* obj.prop */
    NODE_ARRAY,         /* [1, 2, 3] */
    NODE_OBJECT,        /* { key: val } */
    NODE_PROGRAM,       /* top-level: list of statements */
} NodeType;

typedef struct AstNode {
    NodeType type;

    /* Data — only the relevant field is used per type */
    double          num_val;        /* NODE_NUM */
    char           *str_val;        /* NODE_STR, NODE_IDENT — heap allocated */
    TokenType       op;             /* NODE_BINOP, NODE_UNARY */
    int             bool_val;       /* NODE_BOOL */

    /* Children — dynamically allocated array */
    struct AstNode **children;      /* pointer to array of child pointers */
    int              num_children;
    int              cap_children;  /* allocated capacity */

    /* For functions — dynamically allocated param names */
    char           **params;        /* array of param name strings */
    int              num_params;
} AstNode;

/* Parse a token list into an AST. Returns the root node. */
AstNode *js_parse(TokenList *tokens);

/* Free an AST tree */
void ast_free(AstNode *node);

/* Print an AST for debugging */
void ast_print(AstNode *node, int indent);

#endif /* JS_PARSER_H */
