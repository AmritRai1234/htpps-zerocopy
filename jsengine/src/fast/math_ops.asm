; ============================================================================
; math_ops.asm — Fast Math Operations for JS Engine
; ============================================================================
; These run MILLIONS of times per second during JS execution.
; Each function is a single CPU instruction (or near it).
;
; Calling convention (System V AMD64):
;   doubles passed in xmm0, xmm1
;   ints passed in rdi, rsi
;   return in xmm0 (double) or rax (int)
; ============================================================================

section .text

; ===== Double Arithmetic =====

; double js_add(double a, double b)
global js_add
js_add:
    addsd xmm0, xmm1       ; ONE instruction: a + b
    ret

; double js_sub(double a, double b)
global js_sub
js_sub:
    subsd xmm0, xmm1       ; a - b
    ret

; double js_mul(double a, double b)
global js_mul
js_mul:
    mulsd xmm0, xmm1       ; a * b
    ret

; double js_div(double a, double b)
global js_div
js_div:
    divsd xmm0, xmm1       ; a / b (returns Infinity if b=0, per IEEE 754)
    ret

; double js_neg(double a)
global js_neg
js_neg:
    xorpd xmm1, xmm1       ; xmm1 = 0.0
    subsd xmm1, xmm0       ; xmm1 = 0 - a = -a
    movsd xmm0, xmm1       ; return -a
    ret

; double js_mod(double a, double b) — JS % operator
; x86 doesn't have a double modulo instruction, so we compute: a - floor(a/b) * b
global js_mod
js_mod:
    movsd xmm2, xmm0       ; save a
    divsd xmm0, xmm1       ; a / b
    roundsd xmm0, xmm0, 1  ; floor(a / b)  — round toward negative infinity
    mulsd xmm0, xmm1       ; floor(a/b) * b
    subsd xmm2, xmm0       ; a - floor(a/b) * b
    movsd xmm0, xmm2       ; return result
    ret

; ===== Comparisons =====

; int js_lt(double a, double b) — a < b
global js_lt
js_lt:
    xor eax, eax            ; result = 0
    ucomisd xmm0, xmm1     ; compare a vs b
    setb al                 ; set to 1 if a < b
    ret

; int js_gt(double a, double b) — a > b
global js_gt
js_gt:
    xor eax, eax
    ucomisd xmm0, xmm1
    seta al                 ; set to 1 if a > b
    ret

; int js_lte(double a, double b) — a <= b
global js_lte
js_lte:
    xor eax, eax
    ucomisd xmm0, xmm1
    setbe al
    ret

; int js_gte(double a, double b) — a >= b
global js_gte
js_gte:
    xor eax, eax
    ucomisd xmm0, xmm1
    setae al
    ret

; int js_eq(double a, double b) — a == b
global js_eq
js_eq:
    xor eax, eax
    ucomisd xmm0, xmm1
    sete al
    jp .nan                 ; if NaN, result is always false
    ret
.nan:
    xor eax, eax
    ret

; ===== Bitwise (convert to int32 first, like JS spec) =====

; int32_t js_bitor(double a, double b)
global js_bitor
js_bitor:
    cvttsd2si eax, xmm0    ; double → int32
    cvttsd2si ecx, xmm1
    or eax, ecx             ; a | b
    ret

; int32_t js_bitand(double a, double b)
global js_bitand
js_bitand:
    cvttsd2si eax, xmm0
    cvttsd2si ecx, xmm1
    and eax, ecx            ; a & b
    ret

; int32_t js_bitxor(double a, double b)
global js_bitxor
js_bitxor:
    cvttsd2si eax, xmm0
    cvttsd2si ecx, xmm1
    xor eax, ecx            ; a ^ b
    ret

; int32_t js_shl(double a, double b)
global js_shl
js_shl:
    cvttsd2si eax, xmm0
    cvttsd2si ecx, xmm1
    shl eax, cl             ; a << b
    ret

; int32_t js_shr(double a, double b)
global js_shr
js_shr:
    cvttsd2si eax, xmm0
    cvttsd2si ecx, xmm1
    sar eax, cl             ; a >> b (arithmetic shift, preserves sign)
    ret

; int32_t js_bitnot(double a)
global js_bitnot
js_bitnot:
    cvttsd2si eax, xmm0
    not eax                 ; ~a
    ret
