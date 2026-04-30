/*
 * parser.c — Recursive Descent Parser (Memory-Optimized)
 * ============================================================================
 * All arrays are dynamically grown. Strings are heap-allocated.
 * Null pointers used everywhere — no wasted bytes.
 * ============================================================================
 */

#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static Token *tokens;
static int pos;

static Token *peek(void) { return &tokens[pos]; }
static Token *advance(void) { return &tokens[pos++]; }
static int at(TokenType t) { return tokens[pos].type == t; }

static int expect(TokenType t) {
    if (!at(t)) {
        fprintf(stderr, "[Parser] Expected %s, got %s '%s' on line %d\n",
                tok_name(t), tok_name(peek()->type), peek()->text, peek()->line);
        return 0;
    }
    advance();
    return 1;
}

/* Allocate a node — only 48 bytes, everything else is NULL */
static AstNode *new_node(NodeType type) {
    AstNode *n = calloc(1, sizeof(AstNode));
    n->type = type;
    /* children, str_val, params all start as NULL — zero waste */
    return n;
}

/* Grow children array dynamically */
static void add_child(AstNode *parent, AstNode *child) {
    if (!child) return;
    if (parent->num_children >= parent->cap_children) {
        int new_cap = parent->cap_children == 0 ? 4 : parent->cap_children * 2;
        parent->children = realloc(parent->children, (size_t)new_cap * sizeof(AstNode *));
        parent->cap_children = new_cap;
    }
    parent->children[parent->num_children++] = child;
}

/* Set string value — heap allocated, exact size */
static void set_str(AstNode *n, const char *s) {
    n->str_val = strdup(s);
}

/* Forward declarations */
static AstNode *parse_expr(void);
static AstNode *parse_statement(void);

/* Primary: numbers, strings, booleans, identifiers, parens */
static AstNode *parse_primary(void) {
    Token *t = peek();

    if (t->type == TOK_NUM) {
        AstNode *n = new_node(NODE_NUM);
        n->num_val = t->num_val;
        advance();
        return n;
    }
    if (t->type == TOK_STR) {
        AstNode *n = new_node(NODE_STR);
        set_str(n, t->text);
        advance();
        return n;
    }
    if (t->type == TOK_TRUE || t->type == TOK_FALSE) {
        AstNode *n = new_node(NODE_BOOL);
        n->bool_val = (t->type == TOK_TRUE);
        advance();
        return n;
    }
    if (t->type == TOK_NULL) { advance(); return new_node(NODE_NULL); }
    if (t->type == TOK_UNDEFINED) { advance(); return new_node(NODE_UNDEF); }

    if (t->type == TOK_IDENT) {
        AstNode *n = new_node(NODE_IDENT);
        set_str(n, t->text);
        advance();

        /* Function call: ident(args) */
        if (at(TOK_LPAREN)) {
            AstNode *call = new_node(NODE_CALL);
            add_child(call, n);
            advance();
            while (!at(TOK_RPAREN) && !at(TOK_EOF)) {
                add_child(call, parse_expr());
                if (at(TOK_COMMA)) advance();
            }
            expect(TOK_RPAREN);
            return call;
        }

        /* Member access: ident.prop */
        while (at(TOK_DOT)) {
            advance();
            AstNode *member = new_node(NODE_MEMBER);
            add_child(member, n);
            AstNode *prop = new_node(NODE_STR);
            set_str(prop, peek()->text);
            advance();
            add_child(member, prop);
            n = member;

            if (at(TOK_LPAREN)) {
                AstNode *call = new_node(NODE_CALL);
                add_child(call, n);
                advance();
                while (!at(TOK_RPAREN) && !at(TOK_EOF)) {
                    add_child(call, parse_expr());
                    if (at(TOK_COMMA)) advance();
                }
                expect(TOK_RPAREN);
                n = call;
            }
        }

        /* Assignment: x = expr */
        if (at(TOK_EQ) && n->type == NODE_IDENT) {
            advance();
            AstNode *assign = new_node(NODE_ASSIGN);
            add_child(assign, n);
            add_child(assign, parse_expr());
            return assign;
        }

        return n;
    }

    if (t->type == TOK_LPAREN) {
        advance();
        AstNode *n = parse_expr();
        expect(TOK_RPAREN);
        return n;
    }

    /* function keyword */
    if (t->type == TOK_FUNCTION) {
        advance();
        AstNode *fn = new_node(NODE_FUNC);

        if (at(TOK_IDENT)) {
            set_str(fn, peek()->text);
            advance();
        }

        expect(TOK_LPAREN);
        /* Dynamically allocate params */
        while (!at(TOK_RPAREN) && !at(TOK_EOF)) {
            fn->params = realloc(fn->params, (size_t)(fn->num_params + 1) * sizeof(char *));
            fn->params[fn->num_params] = strdup(peek()->text);
            fn->num_params++;
            advance();
            if (at(TOK_COMMA)) advance();
        }
        expect(TOK_RPAREN);

        AstNode *body = new_node(NODE_BLOCK);
        expect(TOK_LBRACE);
        while (!at(TOK_RBRACE) && !at(TOK_EOF)) {
            add_child(body, parse_statement());
        }
        expect(TOK_RBRACE);
        add_child(fn, body);
        return fn;
    }

    /* Array literal */
    if (t->type == TOK_LBRACKET) {
        advance();
        AstNode *arr = new_node(NODE_ARRAY);
        while (!at(TOK_RBRACKET) && !at(TOK_EOF)) {
            add_child(arr, parse_expr());
            if (at(TOK_COMMA)) advance();
        }
        expect(TOK_RBRACKET);
        return arr;
    }

    /* Object literal: { key: value, key2: value2 } */
    if (t->type == TOK_LBRACE) {
        /* Peek ahead to distinguish object from block */
        /* If next is IDENT followed by COLON, it's an object */
        if (tokens[pos + 1].type == TOK_IDENT && tokens[pos + 2].type == TOK_COLON) {
            advance();  /* skip { */
            AstNode *obj = new_node(NODE_OBJECT);
            while (!at(TOK_RBRACE) && !at(TOK_EOF)) {
                /* Key */
                AstNode *key = new_node(NODE_STR);
                set_str(key, peek()->text);
                advance();
                expect(TOK_COLON);
                /* Value */
                AstNode *val = parse_expr();
                add_child(obj, key);
                add_child(obj, val);
                if (at(TOK_COMMA)) advance();
            }
            expect(TOK_RBRACE);
            return obj;
        }
        /* Also handle empty object {} */
        if (tokens[pos + 1].type == TOK_RBRACE) {
            advance(); advance();
            return new_node(NODE_OBJECT);
        }
    }

    fprintf(stderr, "[Parser] Unexpected token '%s' on line %d\n", t->text, t->line);
    advance();
    return new_node(NODE_UNDEF);
}

/* Unary: -x, !x */
static AstNode *parse_unary(void) {
    if (at(TOK_MINUS) || at(TOK_BANG)) {
        Token *op = advance();
        AstNode *n = new_node(NODE_UNARY);
        n->op = op->type;
        add_child(n, parse_unary());
        return n;
    }
    return parse_primary();
}

/* Binary operators with precedence */
static AstNode *parse_mul(void) {
    AstNode *left = parse_unary();
    while (at(TOK_STAR) || at(TOK_SLASH) || at(TOK_PERCENT)) {
        Token *op = advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = op->type;
        add_child(n, left);
        add_child(n, parse_unary());
        left = n;
    }
    return left;
}

static AstNode *parse_add(void) {
    AstNode *left = parse_mul();
    while (at(TOK_PLUS) || at(TOK_MINUS)) {
        Token *op = advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = op->type;
        add_child(n, left);
        add_child(n, parse_add());
        left = n;
    }
    return left;
}

static AstNode *parse_comparison(void) {
    AstNode *left = parse_add();
    while (at(TOK_LT) || at(TOK_GT) || at(TOK_LTE) || at(TOK_GTE)) {
        Token *op = advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = op->type;
        add_child(n, left);
        add_child(n, parse_add());
        left = n;
    }
    return left;
}

static AstNode *parse_equality(void) {
    AstNode *left = parse_comparison();
    while (at(TOK_EQEQ) || at(TOK_EQEQEQ) || at(TOK_NEQ) || at(TOK_NEQEQ)) {
        Token *op = advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = op->type;
        add_child(n, left);
        add_child(n, parse_comparison());
        left = n;
    }
    return left;
}

static AstNode *parse_bitwise(void) {
    AstNode *left = parse_equality();
    while (at(TOK_AMP) || at(TOK_PIPE) || at(TOK_CARET) || at(TOK_SHL) || at(TOK_SHR)) {
        Token *op = advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = op->type;
        add_child(n, left);
        add_child(n, parse_equality());
        left = n;
    }
    return left;
}

static AstNode *parse_logic_and(void) {
    AstNode *left = parse_bitwise();
    while (at(TOK_AND)) {
        advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = TOK_AND;
        add_child(n, left);
        add_child(n, parse_bitwise());
        left = n;
    }
    return left;
}

static AstNode *parse_expr(void) {
    AstNode *left = parse_logic_and();
    while (at(TOK_OR)) {
        advance();
        AstNode *n = new_node(NODE_BINOP);
        n->op = TOK_OR;
        add_child(n, left);
        add_child(n, parse_logic_and());
        left = n;
    }
    return left;
}

/* Statements */
static AstNode *parse_statement(void) {
    if (at(TOK_LET) || at(TOK_CONST) || at(TOK_VAR)) {
        advance();
        AstNode *decl = new_node(NODE_LET);
        set_str(decl, peek()->text);
        advance();
        if (at(TOK_EQ)) {
            advance();
            add_child(decl, parse_expr());
        } else {
            add_child(decl, new_node(NODE_UNDEF));
        }
        if (at(TOK_SEMI)) advance();
        return decl;
    }

    if (at(TOK_RETURN)) {
        advance();
        AstNode *ret = new_node(NODE_RETURN);
        if (!at(TOK_SEMI) && !at(TOK_RBRACE)) {
            add_child(ret, parse_expr());
        }
        if (at(TOK_SEMI)) advance();
        return ret;
    }

    if (at(TOK_IF)) {
        advance();
        AstNode *ifn = new_node(NODE_IF);
        expect(TOK_LPAREN);
        add_child(ifn, parse_expr());
        expect(TOK_RPAREN);

        AstNode *body = new_node(NODE_BLOCK);
        if (at(TOK_LBRACE)) {
            advance();
            while (!at(TOK_RBRACE) && !at(TOK_EOF))
                add_child(body, parse_statement());
            expect(TOK_RBRACE);
        } else {
            add_child(body, parse_statement());
        }
        add_child(ifn, body);

        if (at(TOK_ELSE)) {
            advance();
            AstNode *else_body = new_node(NODE_BLOCK);
            if (at(TOK_LBRACE)) {
                advance();
                while (!at(TOK_RBRACE) && !at(TOK_EOF))
                    add_child(else_body, parse_statement());
                expect(TOK_RBRACE);
            } else {
                add_child(else_body, parse_statement());
            }
            add_child(ifn, else_body);
        }
        return ifn;
    }

    if (at(TOK_WHILE)) {
        advance();
        AstNode *wh = new_node(NODE_WHILE);
        expect(TOK_LPAREN);
        add_child(wh, parse_expr());
        expect(TOK_RPAREN);

        AstNode *body = new_node(NODE_BLOCK);
        expect(TOK_LBRACE);
        while (!at(TOK_RBRACE) && !at(TOK_EOF))
            add_child(body, parse_statement());
        expect(TOK_RBRACE);
        add_child(wh, body);
        return wh;
    }

    if (at(TOK_FOR)) {
        advance();
        AstNode *f = new_node(NODE_FOR);
        expect(TOK_LPAREN);
        add_child(f, parse_statement());
        add_child(f, parse_expr());
        if (at(TOK_SEMI)) advance();
        add_child(f, parse_expr());
        expect(TOK_RPAREN);

        AstNode *body = new_node(NODE_BLOCK);
        expect(TOK_LBRACE);
        while (!at(TOK_RBRACE) && !at(TOK_EOF))
            add_child(body, parse_statement());
        expect(TOK_RBRACE);
        add_child(f, body);
        return f;
    }

    AstNode *expr = parse_expr();
    if (at(TOK_SEMI)) advance();
    return expr;
}

AstNode *js_parse(TokenList *tok_list) {
    tokens = tok_list->tokens;
    pos = 0;

    AstNode *program = new_node(NODE_PROGRAM);
    while (!at(TOK_EOF)) {
        add_child(program, parse_statement());
    }
    return program;
}

void ast_free(AstNode *node) {
    if (!node) return;
    for (int i = 0; i < node->num_children; i++)
        ast_free(node->children[i]);
    free(node->children);   /* free the children array */
    free(node->str_val);    /* free the string (NULL is safe to free) */
    if (node->params) {
        for (int i = 0; i < node->num_params; i++)
            free(node->params[i]);
        free(node->params);
    }
    free(node);
}

void ast_print(AstNode *node, int indent) {
    if (!node) return;
    for (int i = 0; i < indent; i++) printf("  ");

    switch (node->type) {
        case NODE_NUM:     printf("NUM(%g)\n", node->num_val); break;
        case NODE_STR:     printf("STR(\"%s\")\n", node->str_val ? node->str_val : ""); break;
        case NODE_BOOL:    printf("BOOL(%s)\n", node->bool_val ? "true" : "false"); break;
        case NODE_IDENT:   printf("IDENT(%s)\n", node->str_val ? node->str_val : "?"); break;
        case NODE_BINOP:   printf("BINOP(%s)\n", tok_name(node->op)); break;
        case NODE_UNARY:   printf("UNARY(%s)\n", tok_name(node->op)); break;
        case NODE_LET:     printf("LET(%s)\n", node->str_val ? node->str_val : "?"); break;
        case NODE_ASSIGN:  printf("ASSIGN\n"); break;
        case NODE_CALL:    printf("CALL\n"); break;
        case NODE_FUNC:    printf("FUNC(%s, %d params)\n", node->str_val ? node->str_val : "anon", node->num_params); break;
        case NODE_RETURN:  printf("RETURN\n"); break;
        case NODE_IF:      printf("IF\n"); break;
        case NODE_WHILE:   printf("WHILE\n"); break;
        case NODE_FOR:     printf("FOR\n"); break;
        case NODE_BLOCK:   printf("BLOCK\n"); break;
        case NODE_PROGRAM: printf("PROGRAM\n"); break;
        default:           printf("NODE(%d)\n", node->type); break;
    }

    for (int i = 0; i < node->num_children; i++)
        ast_print(node->children[i], indent + 1);
}
