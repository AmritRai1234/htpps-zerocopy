/*
 * eval.h — Tree-Walking Interpreter
 * ============================================================================
 */

#ifndef JS_EVAL_H
#define JS_EVAL_H

#include "value.h"
#include "parser.h"
#include <stdint.h>

/* Environment is opaque — implementation in eval.c uses hash table */
typedef struct Env Env;

/* Create/destroy environments */
Env *env_new(Env *parent);
void env_free(Env *env);

/* Variable operations */
void    env_set(Env *env, const char *name, JsValue val);
JsValue env_get(Env *env, const char *name);

/* Evaluate an AST node and return its JS value */
JsValue js_eval(AstNode *node, Env *env);

#endif /* JS_EVAL_H */
