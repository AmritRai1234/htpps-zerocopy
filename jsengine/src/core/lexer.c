/*
 * lexer.c — JavaScript Tokenizer Implementation
 * ============================================================================
 * Scans through source code character by character, producing tokens.
 * ============================================================================
 */

#include "lexer.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static const char *tok_names[] = {
    "NUM", "STR", "true", "false", "null", "undefined",
    "IDENT", "let", "const", "var", "function", "return",
    "if", "else", "while", "for",
    "+", "-", "*", "/", "%", "=", "==", "===",
    "!", "!=", "!==", "<", ">", "<=", ">=",
    "&&", "||", "&", "|", "^", "~", "<<", ">>",
    "++", "--", "=>", ".",
    "(", ")", "{", "}", "[", "]", ";", ",", ":",
    "EOF", "ERROR"
};

const char *tok_name(TokenType t) {
    if (t >= 0 && t <= TOK_ERROR) return tok_names[t];
    return "?";
}

/* Check if an identifier is a keyword */
static TokenType check_keyword(const char *word) {
    if (strcmp(word, "let") == 0)       return TOK_LET;
    if (strcmp(word, "const") == 0)     return TOK_CONST;
    if (strcmp(word, "var") == 0)       return TOK_VAR;
    if (strcmp(word, "function") == 0)  return TOK_FUNCTION;
    if (strcmp(word, "return") == 0)    return TOK_RETURN;
    if (strcmp(word, "if") == 0)        return TOK_IF;
    if (strcmp(word, "else") == 0)      return TOK_ELSE;
    if (strcmp(word, "while") == 0)     return TOK_WHILE;
    if (strcmp(word, "for") == 0)       return TOK_FOR;
    if (strcmp(word, "true") == 0)      return TOK_TRUE;
    if (strcmp(word, "false") == 0)     return TOK_FALSE;
    if (strcmp(word, "null") == 0)      return TOK_NULL;
    if (strcmp(word, "undefined") == 0) return TOK_UNDEFINED;
    return TOK_IDENT;
}

int js_tokenize(const char *src, TokenList *out) {
    out->count = 0;
    int line = 1;
    const char *p = src;

    while (*p) {
        /* Skip whitespace */
        while (*p && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
        if (*p == '\n') { line++; p++; continue; }
        if (*p == '\0') break;

        /* Skip single-line comments */
        if (p[0] == '/' && p[1] == '/') {
            while (*p && *p != '\n') p++;
            continue;
        }
        /* Skip multi-line comments */
        if (p[0] == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/')) {
                if (*p == '\n') line++;
                p++;
            }
            if (*p) p += 2;
            continue;
        }

        Token tok = { .line = line };
        if (out->count >= MAX_TOKENS) return -1;

        /* Numbers: 42, 3.14, .5 */
        if (isdigit(*p) || (*p == '.' && isdigit(p[1]))) {
            int len = 0;
            while (isdigit(p[len]) || p[len] == '.') len++;
            memcpy(tok.text, p, (size_t)len);
            tok.text[len] = '\0';
            tok.type = TOK_NUM;
            tok.num_val = strtod(p, NULL);
            p += len;
        }
        /* Strings: "hello" or 'world' */
        else if (*p == '"' || *p == '\'') {
            char quote = *p++;
            int len = 0;
            while (p[len] && p[len] != quote) {
                if (p[len] == '\\') len++; /* skip escape */
                len++;
            }
            memcpy(tok.text, p, (size_t)len);
            tok.text[len] = '\0';
            tok.type = TOK_STR;
            p += len;
            if (*p == quote) p++;
        }
        /* Identifiers and keywords */
        else if (isalpha(*p) || *p == '_' || *p == '$') {
            int len = 0;
            while (isalnum(p[len]) || p[len] == '_' || p[len] == '$') len++;
            memcpy(tok.text, p, (size_t)len);
            tok.text[len] = '\0';
            tok.type = check_keyword(tok.text);
            p += len;
        }
        /* Multi-char operators */
        else if (p[0] == '=' && p[1] == '=' && p[2] == '=') { tok.type = TOK_EQEQEQ; strcpy(tok.text, "==="); p += 3; }
        else if (p[0] == '!' && p[1] == '=' && p[2] == '=') { tok.type = TOK_NEQEQ; strcpy(tok.text, "!=="); p += 3; }
        else if (p[0] == '=' && p[1] == '=') { tok.type = TOK_EQEQ; strcpy(tok.text, "=="); p += 2; }
        else if (p[0] == '!' && p[1] == '=') { tok.type = TOK_NEQ; strcpy(tok.text, "!="); p += 2; }
        else if (p[0] == '=' && p[1] == '>') { tok.type = TOK_ARROW; strcpy(tok.text, "=>"); p += 2; }
        else if (p[0] == '&' && p[1] == '&') { tok.type = TOK_AND; strcpy(tok.text, "&&"); p += 2; }
        else if (p[0] == '|' && p[1] == '|') { tok.type = TOK_OR; strcpy(tok.text, "||"); p += 2; }
        else if (p[0] == '<' && p[1] == '=') { tok.type = TOK_LTE; strcpy(tok.text, "<="); p += 2; }
        else if (p[0] == '>' && p[1] == '=') { tok.type = TOK_GTE; strcpy(tok.text, ">="); p += 2; }
        else if (p[0] == '<' && p[1] == '<') { tok.type = TOK_SHL; strcpy(tok.text, "<<"); p += 2; }
        else if (p[0] == '>' && p[1] == '>') { tok.type = TOK_SHR; strcpy(tok.text, ">>"); p += 2; }
        else if (p[0] == '+' && p[1] == '+') { tok.type = TOK_PLUSPLUS; strcpy(tok.text, "++"); p += 2; }
        else if (p[0] == '-' && p[1] == '-') { tok.type = TOK_MINUSMINUS; strcpy(tok.text, "--"); p += 2; }
        /* Single-char operators */
        else {
            tok.text[0] = *p;
            tok.text[1] = '\0';
            switch (*p) {
                case '+': tok.type = TOK_PLUS; break;
                case '-': tok.type = TOK_MINUS; break;
                case '*': tok.type = TOK_STAR; break;
                case '/': tok.type = TOK_SLASH; break;
                case '%': tok.type = TOK_PERCENT; break;
                case '=': tok.type = TOK_EQ; break;
                case '!': tok.type = TOK_BANG; break;
                case '<': tok.type = TOK_LT; break;
                case '>': tok.type = TOK_GT; break;
                case '&': tok.type = TOK_AMP; break;
                case '|': tok.type = TOK_PIPE; break;
                case '^': tok.type = TOK_CARET; break;
                case '~': tok.type = TOK_TILDE; break;
                case '(': tok.type = TOK_LPAREN; break;
                case ')': tok.type = TOK_RPAREN; break;
                case '{': tok.type = TOK_LBRACE; break;
                case '}': tok.type = TOK_RBRACE; break;
                case '[': tok.type = TOK_LBRACKET; break;
                case ']': tok.type = TOK_RBRACKET; break;
                case ';': tok.type = TOK_SEMI; break;
                case ',': tok.type = TOK_COMMA; break;
                case ':': tok.type = TOK_COLON; break;
                case '.': tok.type = TOK_DOT; break;
                default:
                    fprintf(stderr, "[Lexer] Unknown char '%c' on line %d\n", *p, line);
                    tok.type = TOK_ERROR;
                    break;
            }
            p++;
        }

        out->tokens[out->count++] = tok;
    }

    /* Add EOF */
    Token eof = { .type = TOK_EOF, .text = "EOF", .line = line };
    out->tokens[out->count++] = eof;

    return out->count;
}
