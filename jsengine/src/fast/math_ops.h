/*
 * math_ops.h — C headers for assembly math functions
 * ============================================================================
 * These are implemented in math_ops.asm (pure machine code).
 * This header lets C code call them like normal functions.
 * ============================================================================
 */

#ifndef JS_MATH_OPS_H
#define JS_MATH_OPS_H

#include <stdint.h>

/* Arithmetic — each one is a single CPU instruction */
extern double  js_add(double a, double b);
extern double  js_sub(double a, double b);
extern double  js_mul(double a, double b);
extern double  js_div(double a, double b);
extern double  js_mod(double a, double b);
extern double  js_neg(double a);

/* Comparisons — returns 0 or 1 */
extern int     js_lt(double a, double b);
extern int     js_gt(double a, double b);
extern int     js_lte(double a, double b);
extern int     js_gte(double a, double b);
extern int     js_eq(double a, double b);

/* Bitwise — converts to int32 first (per JS spec) */
extern int32_t js_bitor(double a, double b);
extern int32_t js_bitand(double a, double b);
extern int32_t js_bitxor(double a, double b);
extern int32_t js_shl(double a, double b);
extern int32_t js_shr(double a, double b);
extern int32_t js_bitnot(double a);

#endif /* JS_MATH_OPS_H */
