/*
 * lexer.h — JavaScript Tokenizer
 * ============================================================================
 * The lexer is the FIRST step. It takes raw text and breaks it into tokens:
 *
 *   "let x = 5 + 3;"  →  [LET] [IDENT:x] [EQ] [NUM:5] [PLUS] [NUM:3] [SEMI]
 *
 * It doesn't understand MEANING — it just splits text into labeled chunks.
 * Like splitting a sentence into words without knowing the grammar.
 * ============================================================================
 */

#ifndef JS_LEXER_H
#define JS_LEXER_H

typedef enum {
    /* Literals */
    TOK_NUM,            /* 42, 3.14 */
    TOK_STR,            /* "hello", 'world' */
    TOK_TRUE,           /* true */
    TOK_FALSE,          /* false */
    TOK_NULL,           /* null */
    TOK_UNDEFINED,      /* undefined */

    /* Identifiers & Keywords */
    TOK_IDENT,          /* x, foo, myVar */
    TOK_LET,            /* let */
    TOK_CONST,          /* const */
    TOK_VAR,            /* var */
    TOK_FUNCTION,       /* function */
    TOK_RETURN,         /* return */
    TOK_IF,             /* if */
    TOK_ELSE,           /* else */
    TOK_WHILE,          /* while */
    TOK_FOR,            /* for */

    /* Operators */
    TOK_PLUS,           /* + */
    TOK_MINUS,          /* - */
    TOK_STAR,           /* * */
    TOK_SLASH,          /* / */
    TOK_PERCENT,        /* % */
    TOK_EQ,             /* = */
    TOK_EQEQ,          /* == */
    TOK_EQEQEQ,        /* === */
    TOK_BANG,           /* ! */
    TOK_NEQ,            /* != */
    TOK_NEQEQ,         /* !== */
    TOK_LT,             /* < */
    TOK_GT,             /* > */
    TOK_LTE,            /* <= */
    TOK_GTE,            /* >= */
    TOK_AND,            /* && */
    TOK_OR,             /* || */
    TOK_AMP,            /* & */
    TOK_PIPE,           /* | */
    TOK_CARET,          /* ^ */
    TOK_TILDE,          /* ~ */
    TOK_SHL,            /* << */
    TOK_SHR,            /* >> */
    TOK_PLUSPLUS,       /* ++ */
    TOK_MINUSMINUS,    /* -- */
    TOK_ARROW,          /* => */
    TOK_DOT,            /* . */

    /* Delimiters */
    TOK_LPAREN,         /* ( */
    TOK_RPAREN,         /* ) */
    TOK_LBRACE,         /* { */
    TOK_RBRACE,         /* } */
    TOK_LBRACKET,       /* [ */
    TOK_RBRACKET,       /* ] */
    TOK_SEMI,           /* ; */
    TOK_COMMA,          /* , */
    TOK_COLON,          /* : */

    /* Special */
    TOK_EOF,            /* end of input */
    TOK_ERROR,          /* bad token */
} TokenType;

typedef struct {
    TokenType type;
    char      text[256];   /* The actual text of the token */
    double    num_val;     /* Parsed number (if TOK_NUM) */
    int       line;        /* Line number for error messages */
} Token;

#define MAX_TOKENS 4096

typedef struct {
    Token tokens[MAX_TOKENS];
    int   count;
} TokenList;

/* Tokenize a JS source string. Returns number of tokens, or -1 on error. */
int js_tokenize(const char *source, TokenList *out);

/* Get token type name (for debugging) */
const char *tok_name(TokenType t);

#endif /* JS_LEXER_H */
