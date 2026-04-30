/*
 * value.c — NaN-Boxed Values with Objects, Arrays, and JSON
 * ============================================================================
 * HEAP tracking:
 *   - Strings: tracked in string_pool[]
 *   - Objects: tracked in obj_pool[]
 *   - Arrays:  tracked in arr_pool[]
 *   All freed by js_strings_free() at cleanup
 * ============================================================================
 */

#include "value.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ===== String Pool ===== */

#define POOL_INIT 1024

static char **string_pool = NULL;
static int    str_count = 0, str_cap = 0;

static void str_track(char *s) {
    if (str_count >= str_cap) {
        str_cap = str_cap == 0 ? POOL_INIT : str_cap * 2;
        string_pool = realloc(string_pool, (size_t)str_cap * sizeof(char *));
    }
    string_pool[str_count++] = s;
}

/* ===== Object Pool ===== */

static JsObject **obj_pool = NULL;
static int obj_count = 0, obj_cap = 0;

static void obj_track(JsObject *o) {
    if (obj_count >= obj_cap) {
        obj_cap = obj_cap == 0 ? 256 : obj_cap * 2;
        obj_pool = realloc(obj_pool, (size_t)obj_cap * sizeof(JsObject *));
    }
    obj_pool[obj_count++] = o;
}

/* ===== Array Pool ===== */

static JsArray **arr_pool = NULL;
static int arr_count = 0, arr_cap = 0;

static void arr_track(JsArray *a) {
    if (arr_count >= arr_cap) {
        arr_cap = arr_cap == 0 ? 256 : arr_cap * 2;
        arr_pool = realloc(arr_pool, (size_t)arr_cap * sizeof(JsArray *));
    }
    arr_pool[arr_count++] = a;
}

/* ===== Free ALL heap memory ===== */

void js_strings_free(void) {
    /* Free strings */
    for (int i = 0; i < str_count; i++) { free(string_pool[i]); }
    free(string_pool); string_pool = NULL; str_count = 0; str_cap = 0;

    /* Free objects */
    for (int i = 0; i < obj_count; i++) {
        JsObject *o = obj_pool[i];
        if (o) {
            for (int j = 0; j < o->count; j++) free(o->keys[j]);
            free(o);
        }
    }
    free(obj_pool); obj_pool = NULL; obj_count = 0; obj_cap = 0;

    /* Free arrays */
    for (int i = 0; i < arr_count; i++) {
        JsArray *a = arr_pool[i];
        if (a) { free(a->items); free(a); }
    }
    free(arr_pool); arr_pool = NULL; arr_count = 0; arr_cap = 0;
}

int js_strings_count(void) { return str_count + obj_count + arr_count; }

/* ===== Constructors ===== */

JsValue js_str(const char *s) {
    char *copy = strdup(s);
    str_track(copy);
    return TAG_STR | ((uint64_t)(uintptr_t)copy & PTR_MASK);
}

JsValue js_obj_new(void) {
    JsObject *o = calloc(1, sizeof(JsObject));
    obj_track(o);
    return TAG_OBJ | ((uint64_t)(uintptr_t)o & PTR_MASK);
}

JsValue js_arr_new(void) {
    JsArray *a = calloc(1, sizeof(JsArray));
    a->capacity = 8;
    a->items = calloc((size_t)a->capacity, sizeof(JsValue));
    arr_track(a);
    return TAG_ARR | ((uint64_t)(uintptr_t)a & PTR_MASK);
}

/* ===== Object Operations ===== */

void js_obj_set(JsValue obj_val, const char *key, JsValue val) {
    if (!js_is_obj(obj_val)) return;
    JsObject *o = js_as_obj(obj_val);

    /* Update existing key */
    for (int i = 0; i < o->count; i++) {
        if (strcmp(o->keys[i], key) == 0) {
            o->vals[i] = val;
            return;
        }
    }

    /* Add new key */
    if (o->count < OBJ_MAX_PROPS) {
        o->keys[o->count] = strdup(key);  /* freed in js_strings_free via obj_pool */
        o->vals[o->count] = val;
        o->count++;
    }
}

JsValue js_obj_get(JsValue obj_val, const char *key) {
    if (!js_is_obj(obj_val)) return js_undef();
    JsObject *o = js_as_obj(obj_val);

    for (int i = 0; i < o->count; i++) {
        if (strcmp(o->keys[i], key) == 0) return o->vals[i];
    }
    return js_undef();
}

int js_obj_has(JsValue obj_val, const char *key) {
    if (!js_is_obj(obj_val)) return 0;
    JsObject *o = js_as_obj(obj_val);
    for (int i = 0; i < o->count; i++) {
        if (strcmp(o->keys[i], key) == 0) return 1;
    }
    return 0;
}

/* ===== Array Operations ===== */

void js_arr_push(JsValue arr_val, JsValue val) {
    if (!js_is_arr(arr_val)) return;
    JsArray *a = js_as_arr(arr_val);
    if (a->length >= a->capacity) {
        a->capacity *= 2;
        a->items = realloc(a->items, (size_t)a->capacity * sizeof(JsValue));
    }
    a->items[a->length++] = val;
}

JsValue js_arr_get(JsValue arr_val, int index) {
    if (!js_is_arr(arr_val)) return js_undef();
    JsArray *a = js_as_arr(arr_val);
    if (index < 0 || index >= a->length) return js_undef();
    return a->items[index];
}

void js_arr_set(JsValue arr_val, int index, JsValue val) {
    if (!js_is_arr(arr_val)) return;
    JsArray *a = js_as_arr(arr_val);
    while (index >= a->capacity) {
        a->capacity *= 2;
        a->items = realloc(a->items, (size_t)a->capacity * sizeof(JsValue));
    }
    if (index >= a->length) a->length = index + 1;
    a->items[index] = val;
}

int js_arr_len(JsValue arr_val) {
    if (!js_is_arr(arr_val)) return 0;
    return js_as_arr(arr_val)->length;
}

/* ===== Printing ===== */

static char print_buf[256];

const char *js_to_string(JsValue v) {
    if (js_is_num(v)) {
        double d = js_as_num(v);
        if (isnan(d)) return "NaN";
        if (isinf(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == (long long)d && fabs(d) < 1e15)
            snprintf(print_buf, sizeof(print_buf), "%lld", (long long)d);
        else
            snprintf(print_buf, sizeof(print_buf), "%.10g", d);
        return print_buf;
    }
    if (js_is_str(v))   return js_as_str(v);
    if (js_is_bool(v))  return js_as_bool(v) ? "true" : "false";
    if (js_is_null(v))  return "null";
    if (js_is_undef(v)) return "undefined";
    if (js_is_obj(v))   return "[object Object]";
    if (js_is_arr(v)) {
        /* Simple array display */
        JsArray *a = js_as_arr(v);
        char *p = print_buf;
        int rem = (int)sizeof(print_buf);
        int n = snprintf(p, (size_t)rem, "[");
        p += n; rem -= n;
        for (int i = 0; i < a->length && rem > 10; i++) {
            if (i > 0) { n = snprintf(p, (size_t)rem, ","); p += n; rem -= n; }
            const char *s = js_to_string(a->items[i]);
            n = snprintf(p, (size_t)rem, "%s", s);
            p += n; rem -= n;
        }
        snprintf(p, (size_t)rem, "]");
        return print_buf;
    }
    return "unknown";
}

void js_print(JsValue v) { printf("%s", js_to_string(v)); }

/* ===== JSON Output ===== */

int js_to_json(JsValue v, char *buf, int buf_size) {
    if (js_is_num(v)) {
        double d = js_as_num(v);
        if (d == (long long)d && fabs(d) < 1e15)
            return snprintf(buf, (size_t)buf_size, "%lld", (long long)d);
        else
            return snprintf(buf, (size_t)buf_size, "%.10g", d);
    }
    if (js_is_str(v)) {
        return snprintf(buf, (size_t)buf_size, "\"%s\"", js_as_str(v));
    }
    if (js_is_bool(v)) {
        return snprintf(buf, (size_t)buf_size, "%s", js_as_bool(v) ? "true" : "false");
    }
    if (js_is_null(v) || js_is_undef(v)) {
        return snprintf(buf, (size_t)buf_size, "null");
    }
    if (js_is_arr(v)) {
        JsArray *a = js_as_arr(v);
        int pos = snprintf(buf, (size_t)buf_size, "[");
        for (int i = 0; i < a->length; i++) {
            if (i > 0) pos += snprintf(buf + pos, (size_t)(buf_size - pos), ",");
            pos += js_to_json(a->items[i], buf + pos, buf_size - pos);
        }
        pos += snprintf(buf + pos, (size_t)(buf_size - pos), "]");
        return pos;
    }
    if (js_is_obj(v)) {
        JsObject *o = js_as_obj(v);
        int pos = snprintf(buf, (size_t)buf_size, "{");
        for (int i = 0; i < o->count; i++) {
            if (i > 0) pos += snprintf(buf + pos, (size_t)(buf_size - pos), ",");
            pos += snprintf(buf + pos, (size_t)(buf_size - pos), "\"%s\":", o->keys[i]);
            pos += js_to_json(o->vals[i], buf + pos, buf_size - pos);
        }
        pos += snprintf(buf + pos, (size_t)(buf_size - pos), "}");
        return pos;
    }
    return snprintf(buf, (size_t)buf_size, "null");
}
