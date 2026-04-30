/*
 * eval.c — Optimized Tree-Walking Interpreter
 * ============================================================================
 * Optimizations:
 *   1. Hash-based variable lookup (O(1) instead of O(n) strcmp)
 *   2. Assembly math calls for ALL numeric operations
 *   3. Inline hot paths to avoid function call overhead
 *   4. Pre-computed string hashes for variable names
 * ============================================================================
 */

#include "eval.h"
#include "../fast/math_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../jit/jit.h"

/* Output capture — when set, console.log writes to buffer instead of stdout */
extern void jsengine_capture(const char *text) __attribute__((weak));
extern void jsengine_capture_char(char c) __attribute__((weak));

/* ===== Fast String Hashing (FNV-1a) ===== */

static inline uint32_t hash_str(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

/* ===== Environment with Hash Table ===== */

#define ENV_BUCKETS 64  /* power of 2 for fast masking */

typedef struct EnvEntry {
    char    *name;
    uint32_t hash;
    JsValue  value;
    struct EnvEntry *next;  /* chaining for collisions */
} EnvEntry;

struct Env {
    EnvEntry *buckets[ENV_BUCKETS];
    Env      *parent;
};

Env *env_new(Env *parent) {
    Env *e = calloc(1, sizeof(Env));
    e->parent = parent;
    return e;
}

void env_free(Env *env) {
    for (int i = 0; i < ENV_BUCKETS; i++) {
        EnvEntry *e = env->buckets[i];
        while (e) {
            EnvEntry *next = e->next;
            free(e->name);
            free(e);
            e = next;
        }
    }
    free(env);
}

/* O(1) average lookup instead of O(n) linear scan */
static EnvEntry *env_find(Env *env, const char *name, uint32_t h) {
    uint32_t idx = h & (ENV_BUCKETS - 1);
    EnvEntry *e = env->buckets[idx];
    while (e) {
        if (e->hash == h && strcmp(e->name, name) == 0) return e;
        e = e->next;
    }
    return NULL;
}

void env_set(Env *env, const char *name, JsValue val) {
    uint32_t h = hash_str(name);

    /* Search current + parent scopes for existing var */
    Env *scope = env;
    while (scope) {
        EnvEntry *e = env_find(scope, name, h);
        if (e) { e->value = val; return; }
        scope = scope->parent;
    }

    /* New variable — insert into current scope */
    uint32_t idx = h & (ENV_BUCKETS - 1);
    EnvEntry *entry = malloc(sizeof(EnvEntry));
    entry->name = strdup(name);
    entry->hash = h;
    entry->value = val;
    entry->next = env->buckets[idx];
    env->buckets[idx] = entry;
}

JsValue env_get(Env *env, const char *name) {
    uint32_t h = hash_str(name);
    Env *scope = env;
    while (scope) {
        EnvEntry *e = env_find(scope, name, h);
        if (e) return e->value;
        scope = scope->parent;
    }
    fprintf(stderr, "[Runtime] ReferenceError: %s is not defined\n", name);
    return js_undef();
}

/* ===== Stored functions (closures) ===== */

typedef struct {
    AstNode *node;
    Env     *scope;
} JsClosure;

#define MAX_CLOSURES 4096
static JsClosure closures[MAX_CLOSURES];
static int num_closures = 0;

/* ===== String concatenation ===== */

static JsValue str_concat(JsValue a, JsValue b) {
    const char *sa = js_to_string(a);
    char buf_a[512];
    strncpy(buf_a, sa, sizeof(buf_a) - 1);
    buf_a[sizeof(buf_a) - 1] = '\0';

    const char *sb = js_to_string(b);
    char result[1024];
    snprintf(result, sizeof(result), "%s%s", buf_a, sb);
    return js_str(result);
}

/* ===== The Evaluator — Hot Path Optimized ===== */

JsValue js_eval(AstNode *node, Env *env) {
    /* NULL check — critical for safety */
    if (__builtin_expect(!node, 0)) return js_undef();

    /* Use GCC's computed address for faster dispatch on hot types */
    switch (node->type) {

        /* === Literals — instant return, no work === */
        case NODE_NUM:   return js_num(node->num_val);
        case NODE_STR:   return js_str(node->str_val ? node->str_val : "");
        case NODE_BOOL:  return js_bool(node->bool_val);
        case NODE_NULL:  return js_null();
        case NODE_UNDEF: return js_undef();

        /* === Variable lookup — hash-based O(1) === */
        case NODE_IDENT:
            return env_get(env, node->str_val);

        /* === Declaration === */
        case NODE_LET: {
            JsValue val = js_eval(node->children[0], env);
            env_set(env, node->str_val, val);
            return val;
        }

        /* === Assignment === */
        case NODE_ASSIGN: {
            JsValue val = js_eval(node->children[1], env);
            env_set(env, node->children[0]->str_val, val);
            return val;
        }

        /* === Binary Operations — ASSEMBLY MATH === */
        case NODE_BINOP: {
            JsValue left = js_eval(node->children[0], env);

            /* Short-circuit logical ops BEFORE evaluating right */
            if (node->op == TOK_AND) {
                if (!js_is_truthy(left)) return js_bool(0);
                return js_bool(js_is_truthy(js_eval(node->children[1], env)));
            }
            if (node->op == TOK_OR) {
                if (js_is_truthy(left)) return js_bool(1);
                return js_bool(js_is_truthy(js_eval(node->children[1], env)));
            }

            JsValue right = js_eval(node->children[1], env);

            /* String concat fast path */
            if (__builtin_expect(node->op == TOK_PLUS && (js_is_str(left) || js_is_str(right)), 0)) {
                return str_concat(left, right);
            }

            /* Equality */
            if (node->op == TOK_EQEQ || node->op == TOK_EQEQEQ) {
                if (js_is_num(left) && js_is_num(right))
                    return js_bool(js_eq(js_as_num(left), js_as_num(right)));
                if (js_is_str(left) && js_is_str(right))
                    return js_bool(strcmp(js_as_str(left), js_as_str(right)) == 0);
                return js_bool(left == right);  /* same NaN-boxed bits = same value */
            }
            if (node->op == TOK_NEQ || node->op == TOK_NEQEQ) {
                if (js_is_num(left) && js_is_num(right))
                    return js_bool(!js_eq(js_as_num(left), js_as_num(right)));
                if (js_is_str(left) && js_is_str(right))
                    return js_bool(strcmp(js_as_str(left), js_as_str(right)) != 0);
                return js_bool(left != right);
            }

            /* ALL numeric math → ASSEMBLY CALLS */
            double a = js_is_num(left) ? js_as_num(left) : 0;
            double b = js_is_num(right) ? js_as_num(right) : 0;

            switch (node->op) {
                case TOK_PLUS:    return js_num(js_add(a, b));
                case TOK_MINUS:   return js_num(js_sub(a, b));
                case TOK_STAR:    return js_num(js_mul(a, b));
                case TOK_SLASH:   return js_num(js_div(a, b));
                case TOK_PERCENT: return js_num(js_mod(a, b));
                case TOK_LT:     return js_bool(js_lt(a, b));
                case TOK_GT:     return js_bool(js_gt(a, b));
                case TOK_LTE:    return js_bool(js_lte(a, b));
                case TOK_GTE:    return js_bool(js_gte(a, b));
                case TOK_AMP:    return js_num((double)js_bitand(a, b));
                case TOK_PIPE:   return js_num((double)js_bitor(a, b));
                case TOK_CARET:  return js_num((double)js_bitxor(a, b));
                case TOK_SHL:    return js_num((double)js_shl(a, b));
                case TOK_SHR:    return js_num((double)js_shr(a, b));
                default: break;
            }
            return js_undef();
        }

        /* === Unary === */
        case NODE_UNARY: {
            JsValue val = js_eval(node->children[0], env);
            if (node->op == TOK_MINUS && js_is_num(val))
                return js_num(js_neg(js_as_num(val)));
            if (node->op == TOK_BANG)
                return js_bool(!js_is_truthy(val));
            if (node->op == TOK_TILDE && js_is_num(val))
                return js_num((double)js_bitnot(js_as_num(val)));
            return js_undef();
        }

        /* === If/Else === */
        case NODE_IF: {
            JsValue cond = js_eval(node->children[0], env);
            if (js_is_truthy(cond))
                return js_eval(node->children[1], env);
            else if (node->num_children > 2)
                return js_eval(node->children[2], env);
            return js_undef();
        }

        /* === While loop — TRY JIT FIRST === */
        case NODE_WHILE: {
            /* Can this loop be JIT compiled to native code? */
            if (jit_can_compile(node, env)) {
                /* YES — compile to x86-64 and execute directly */
                jit_compile_and_run(node, env);
                return js_undef();
            }

            /* FALLBACK — interpret normally */
            AstNode *cond_node = node->children[0];
            AstNode *body_node = node->children[1];
            JsValue result = js_undef();
            while (js_is_truthy(js_eval(cond_node, env))) {
                result = js_eval(body_node, env);
            }
            return result;
        }

        /* === For loop === */
        case NODE_FOR: {
            Env *for_env = env_new(env);
            js_eval(node->children[0], for_env);
            JsValue result = js_undef();
            while (js_is_truthy(js_eval(node->children[1], for_env))) {
                result = js_eval(node->children[3], for_env);
                js_eval(node->children[2], for_env);
            }
            env_free(for_env);
            return result;
        }

        /* === Function definition === */
        case NODE_FUNC: {
            int idx = num_closures++;
            closures[idx].node = node;
            closures[idx].scope = env;
            JsValue fn = js_num((double)idx);
            if (node->str_val && node->str_val[0]) {
                env_set(env, node->str_val, fn);
            }
            return fn;
        }

        /* === Function call === */
        case NODE_CALL: {
            JsValue fn_ref = js_eval(node->children[0], env);

            /* Built-in: console.log, Math, JSON, method calls */
            if (node->children[0]->type == NODE_MEMBER) {
                AstNode *mem = node->children[0];
                AstNode *obj_node = mem->children[0];
                AstNode *prop_node = mem->children[1];

                /* Static builtins: console.log, Math.*, JSON.* */
                if (obj_node->type == NODE_IDENT && obj_node->str_val && prop_node->str_val) {
                    if (strcmp(obj_node->str_val, "console") == 0 && strcmp(prop_node->str_val, "log") == 0) {
                        for (int i = 1; i < node->num_children; i++) {
                            if (i > 1) {
                                if (jsengine_capture) jsengine_capture(" ");
                                else putchar(' ');
                            }
                            const char *s = js_to_string(js_eval(node->children[i], env));
                            if (jsengine_capture) jsengine_capture(s);
                            else printf("%s", s);
                        }
                        if (jsengine_capture) jsengine_capture("\n");
                        else putchar('\n');
                        return js_undef();
                    }
                    if (strcmp(obj_node->str_val, "Math") == 0) {
                        JsValue arg = (node->num_children > 1) ? js_eval(node->children[1], env) : js_num(0);
                        double n = js_is_num(arg) ? js_as_num(arg) : 0;
                        if (strcmp(prop_node->str_val, "floor") == 0) return js_num(floor(n));
                        if (strcmp(prop_node->str_val, "ceil") == 0)  return js_num(ceil(n));
                        if (strcmp(prop_node->str_val, "abs") == 0)   return js_num(fabs(n));
                        if (strcmp(prop_node->str_val, "sqrt") == 0)  return js_num(sqrt(n));
                        if (strcmp(prop_node->str_val, "round") == 0) return js_num(round(n));
                        if (strcmp(prop_node->str_val, "random") == 0) return js_num((double)rand() / RAND_MAX);
                    }
                    if (strcmp(obj_node->str_val, "JSON") == 0 && strcmp(prop_node->str_val, "stringify") == 0) {
                        JsValue arg = (node->num_children > 1) ? js_eval(node->children[1], env) : js_undef();
                        char json_buf[4096];
                        js_to_json(arg, json_buf, sizeof(json_buf));
                        return js_str(json_buf);
                    }
                }

                /* Method calls on values: arr.push(), arr.map(), obj.keys() */
                JsValue target = js_eval(obj_node, env);
                if (prop_node->str_val) {
                    /* Array methods */
                    if (js_is_arr(target)) {
                        if (strcmp(prop_node->str_val, "push") == 0) {
                            for (int i = 1; i < node->num_children; i++)
                                js_arr_push(target, js_eval(node->children[i], env));
                            return js_num((double)js_arr_len(target));
                        }
                        if (strcmp(prop_node->str_val, "pop") == 0) {
                            int len = js_arr_len(target);
                            if (len == 0) return js_undef();
                            JsValue last = js_arr_get(target, len - 1);
                            js_as_arr(target)->length--;
                            return last;
                        }
                        if (strcmp(prop_node->str_val, "length") == 0) {
                            return js_num((double)js_arr_len(target));
                        }
                    }
                    /* String methods */
                    if (js_is_str(target)) {
                        if (strcmp(prop_node->str_val, "toUpperCase") == 0) {
                            char *s = js_as_str(target);
                            char buf[1024];
                            int i = 0;
                            while (s[i] && i < 1023) {
                                buf[i] = (s[i] >= 'a' && s[i] <= 'z') ? s[i] - 32 : s[i];
                                i++;
                            }
                            buf[i] = '\0';
                            return js_str(buf);
                        }
                        if (strcmp(prop_node->str_val, "toLowerCase") == 0) {
                            char *s = js_as_str(target);
                            char buf[1024];
                            int i = 0;
                            while (s[i] && i < 1023) {
                                buf[i] = (s[i] >= 'A' && s[i] <= 'Z') ? s[i] + 32 : s[i];
                                i++;
                            }
                            buf[i] = '\0';
                            return js_str(buf);
                        }
                        if (strcmp(prop_node->str_val, "includes") == 0) {
                            if (node->num_children > 1) {
                                JsValue arg = js_eval(node->children[1], env);
                                if (js_is_str(arg))
                                    return js_bool(strstr(js_as_str(target), js_as_str(arg)) != NULL);
                            }
                            return js_bool(0);
                        }
                    }
                }
            }

            /* User function */
            if (js_is_num(fn_ref)) {
                int idx = (int)js_as_num(fn_ref);
                if (idx >= 0 && idx < num_closures) {
                    AstNode *fn = closures[idx].node;
                    Env *fn_env = env_new(closures[idx].scope);

                    for (int i = 0; i < fn->num_params && i + 1 < node->num_children; i++) {
                        JsValue arg = js_eval(node->children[i + 1], env);
                        env_set(fn_env, fn->params[i], arg);
                    }

                    JsValue result = js_eval(fn->children[0], fn_env);
                    env_free(fn_env);
                    return result;
                }
            }

            fprintf(stderr, "[Runtime] TypeError: not a function\n");
            return js_undef();
        }

        /* === Return === */
        case NODE_RETURN:
            return (node->num_children > 0) ? js_eval(node->children[0], env) : js_undef();

        /* === Block / Program === */
        case NODE_BLOCK:
        case NODE_PROGRAM: {
            JsValue result = js_undef();
            int n = node->num_children;
            for (int i = 0; i < n; i++) {
                result = js_eval(node->children[i], env);
                if (node->children[i]->type == NODE_RETURN)
                    return result;
            }
            return result;
        }

        /* === Object literal: { key: value } === */
        case NODE_OBJECT: {
            JsValue obj = js_obj_new();
            /* Children come in pairs: key, value, key, value... */
            for (int i = 0; i + 1 < node->num_children; i += 2) {
                const char *key = node->children[i]->str_val;
                JsValue val = js_eval(node->children[i + 1], env);
                if (key) js_obj_set(obj, key, val);
            }
            return obj;
        }

        /* === Array literal: [1, 2, 3] === */
        case NODE_ARRAY: {
            JsValue arr = js_arr_new();
            for (int i = 0; i < node->num_children; i++) {
                js_arr_push(arr, js_eval(node->children[i], env));
            }
            return arr;
        }

        /* === Member access: obj.prop === */
        case NODE_MEMBER: {
            JsValue obj = js_eval(node->children[0], env);
            const char *prop = node->children[1]->str_val;
            if (!prop) return js_undef();

            /* Array.length */
            if (js_is_arr(obj) && strcmp(prop, "length") == 0)
                return js_num((double)js_arr_len(obj));

            /* String.length */
            if (js_is_str(obj) && strcmp(prop, "length") == 0)
                return js_num((double)strlen(js_as_str(obj)));

            /* Object property */
            if (js_is_obj(obj))
                return js_obj_get(obj, prop);

            return js_undef();
        }

        default:
            return js_undef();
    }
}
