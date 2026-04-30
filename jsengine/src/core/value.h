/*
 * value.h — NaN-Boxed JavaScript Values (with Objects & Arrays)
 * ============================================================================
 * NaN-boxing layout (64 bits):
 *
 *   Regular double: the value IS the double (no tag)
 *   Tagged values use quiet NaN bits + type tag:
 *
 *   0x7FFC_xxxx = null
 *   0x7FFD_xxxx = undefined
 *   0x7FFE_xxxx = boolean (payload: 0 or 1)
 *   0x7FFF_xxxx = string pointer
 *   0xFFFC_xxxx = object pointer
 *   0xFFFD_xxxx = array pointer
 * ============================================================================
 */

#ifndef JS_VALUE_H
#define JS_VALUE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <math.h>

typedef uint64_t JsValue;

/* Tag constants */
#define QNAN      ((uint64_t)0x7FF8000000000000ULL)
#define TAG_NULL  ((uint64_t)0x7FFC000000000000ULL)
#define TAG_UNDEF ((uint64_t)0x7FFD000000000000ULL)
#define TAG_BOOL  ((uint64_t)0x7FFE000000000000ULL)
#define TAG_STR   ((uint64_t)0x7FFF000000000000ULL)
#define TAG_OBJ   ((uint64_t)0xFFFC000000000000ULL)
#define TAG_ARR   ((uint64_t)0xFFFD000000000000ULL)
#define PTR_MASK  ((uint64_t)0x0000FFFFFFFFFFFFULL)
#define TAG_MASK  ((uint64_t)0xFFFF000000000000ULL)

/* ===== Object System ===== */

#define OBJ_MAX_PROPS 64

typedef struct {
    char    *keys[OBJ_MAX_PROPS];   /* HEAP: property names */
    JsValue  vals[OBJ_MAX_PROPS];   /* property values */
    int      count;
} JsObject;

typedef struct {
    JsValue *items;     /* HEAP: dynamic array */
    int      length;
    int      capacity;
} JsArray;

/* ===== Constructors ===== */

static inline JsValue js_num(double n) {
    JsValue v;
    memcpy(&v, &n, 8);
    return v;
}

JsValue js_str(const char *s);
JsValue js_obj_new(void);
JsValue js_arr_new(void);

static inline JsValue js_bool(int b) {
    return TAG_BOOL | (uint64_t)(b ? 1 : 0);
}
static inline JsValue js_null(void)  { return TAG_NULL; }
static inline JsValue js_undef(void) { return TAG_UNDEF; }

/* ===== Type Checks ===== */

static inline int js_is_num(JsValue v)   { return (v & QNAN) != QNAN; }
static inline int js_is_str(JsValue v)   { return (v & TAG_MASK) == TAG_STR; }
static inline int js_is_bool(JsValue v)  { return (v & TAG_MASK) == TAG_BOOL; }
static inline int js_is_null(JsValue v)  { return v == TAG_NULL; }
static inline int js_is_undef(JsValue v) { return v == TAG_UNDEF; }
static inline int js_is_obj(JsValue v)   { return (v & TAG_MASK) == TAG_OBJ; }
static inline int js_is_arr(JsValue v)   { return (v & TAG_MASK) == TAG_ARR; }

/* ===== Extractors ===== */

static inline double js_as_num(JsValue v) {
    double d; memcpy(&d, &v, 8); return d;
}
static inline char *js_as_str(JsValue v) {
    return (char *)(uintptr_t)(v & PTR_MASK);
}
static inline int js_as_bool(JsValue v) {
    return (int)(v & 1);
}
static inline JsObject *js_as_obj(JsValue v) {
    return (JsObject *)(uintptr_t)(v & PTR_MASK);
}
static inline JsArray *js_as_arr(JsValue v) {
    return (JsArray *)(uintptr_t)(v & PTR_MASK);
}

/* ===== Object Operations ===== */

void    js_obj_set(JsValue obj, const char *key, JsValue val);
JsValue js_obj_get(JsValue obj, const char *key);
int     js_obj_has(JsValue obj, const char *key);

/* ===== Array Operations ===== */

void    js_arr_push(JsValue arr, JsValue val);
JsValue js_arr_get(JsValue arr, int index);
void    js_arr_set(JsValue arr, int index, JsValue val);
int     js_arr_len(JsValue arr);

/* ===== Truthiness ===== */

static inline int js_is_truthy(JsValue v) {
    if (js_is_num(v))  { double d = js_as_num(v); return d != 0 && !isnan(d); }
    if (js_is_str(v))  { char *s = js_as_str(v); return s && s[0] != '\0'; }
    if (js_is_bool(v)) return js_as_bool(v);
    if (js_is_obj(v))  return 1;  /* objects are always truthy */
    if (js_is_arr(v))  return 1;  /* arrays are always truthy */
    return 0;
}

/* ===== Printing & Conversion ===== */

const char *js_to_string(JsValue v);
void js_print(JsValue v);

/* JSON output */
int js_to_json(JsValue v, char *buf, int buf_size);

/* Memory management */
void js_strings_free(void);
int  js_strings_count(void);

#endif /* JS_VALUE_H */
