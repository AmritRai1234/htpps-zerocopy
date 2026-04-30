/*
 * jit.c — x86-64 JIT Compiler (Memory-Safe)
 * ============================================================================
 * MEMORY MAP:
 *
 *   STACK (automatic, no free needed):
 *     - JitCtx struct (local var in jit_compile_and_run)
 *     - vars[32] array (doubles passed to generated code)
 *     - All emit() calls write into mmap'd buffer, not stack
 *
 *   HEAP (must free):
 *     - j.code → mmap'd executable buffer → freed by munmap()
 *     - j.var_names[i] → strdup'd strings → freed individually, then NULLed
 *
 *   RULES:
 *     1. Every strdup() has a matching free()
 *     2. Every mmap() has a matching munmap()
 *     3. Every pointer is NULLed after free
 *     4. Every function that can fail cleans up before returning
 * ============================================================================
 */

#define _GNU_SOURCE
#include "jit.h"
#include "../core/value.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ===== Code Buffer ===== */

#define JIT_CODE_SIZE 4096

typedef struct {
    uint8_t *code;          /* HEAP: mmap'd executable memory */
    int      pos;           /* STACK: write position (value, not pointer) */
    int      capacity;      /* STACK: buffer size (value) */

    char    *var_names[32]; /* HEAP: strdup'd strings (must free each) */
    int      var_count;     /* STACK: count (value) */

    int      loop_start;   /* STACK: offset (value) */
} JitCtx;

/* Initialize — allocates executable memory on HEAP via mmap */
static void jit_init(JitCtx *j) {
    j->code = mmap(NULL, JIT_CODE_SIZE,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (j->code == MAP_FAILED) {
        j->code = NULL;
        j->capacity = 0;
    } else {
        j->capacity = JIT_CODE_SIZE;
    }
    j->pos = 0;
    j->var_count = 0;
    j->loop_start = 0;

    /* All var_names start as NULL */
    for (int i = 0; i < 32; i++)
        j->var_names[i] = NULL;
}

/* Destroy — free ALL heap memory, NULL all pointers */
static void jit_cleanup(JitCtx *j) {
    /* Free each strdup'd variable name */
    for (int i = 0; i < j->var_count; i++) {
        free(j->var_names[i]);
        j->var_names[i] = NULL;
    }

    /* Unmap executable memory */
    if (j->code) {
        munmap(j->code, (size_t)j->capacity);
        j->code = NULL;  /* NULL after free! */
    }

    j->pos = 0;
    j->capacity = 0;
    j->var_count = 0;
}

/* ===== Byte Emitters ===== */

static inline void emit(JitCtx *j, uint8_t byte) {
    if (j->code && j->pos < j->capacity)
        j->code[j->pos++] = byte;
}

static inline void emit32(JitCtx *j, int32_t val) {
    emit(j, (uint8_t)(val & 0xFF));
    emit(j, (uint8_t)((val >> 8) & 0xFF));
    emit(j, (uint8_t)((val >> 16) & 0xFF));
    emit(j, (uint8_t)((val >> 24) & 0xFF));
}

/* Get or create variable index. strdup's name onto HEAP. */
static int jit_var_index(JitCtx *j, const char *name) {
    /* Search existing (no new allocation) */
    for (int i = 0; i < j->var_count; i++) {
        if (j->var_names[i] && strcmp(j->var_names[i], name) == 0)
            return i;
    }
    /* New variable — HEAP allocation via strdup */
    if (j->var_count >= 32) return 0;  /* safety limit */
    j->var_names[j->var_count] = strdup(name);  /* HEAP: freed in jit_cleanup */
    return j->var_count++;
}

/* ===== x86-64 Instruction Emitters ===== */

/*
 * movsd xmmN, [rdi + offset]   — load double from vars array
 * All offsets are var_idx * 8 (each double = 8 bytes on STACK)
 */
static void emit_load_var(JitCtx *j, int xmm_reg, int var_idx) {
    int offset = var_idx * 8;
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x10);
    if (offset == 0) {
        emit(j, 0x07 | (uint8_t)(xmm_reg << 3));
    } else if (offset < 128) {
        emit(j, 0x47 | (uint8_t)(xmm_reg << 3));
        emit(j, (uint8_t)offset);
    } else {
        emit(j, 0x87 | (uint8_t)(xmm_reg << 3));
        emit32(j, offset);
    }
}

/* movsd [rdi + offset], xmmN   — store double to vars array */
static void emit_store_var(JitCtx *j, int var_idx, int xmm_reg) {
    int offset = var_idx * 8;
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x11);
    if (offset == 0) {
        emit(j, 0x07 | (uint8_t)(xmm_reg << 3));
    } else if (offset < 128) {
        emit(j, 0x47 | (uint8_t)(xmm_reg << 3));
        emit(j, (uint8_t)offset);
    } else {
        emit(j, 0x87 | (uint8_t)(xmm_reg << 3));
        emit32(j, offset);
    }
}

/* Load a constant double into XMM using the STACK as temp storage */
static void emit_load_const(JitCtx *j, int xmm_reg, double val) {
    uint64_t bits;
    memcpy(&bits, &val, 8);  /* type-pun double → uint64 */

    /* mov rax, imm64 */
    emit(j, 0x48); emit(j, 0xB8);
    for (int i = 0; i < 8; i++)
        emit(j, (uint8_t)((bits >> (i * 8)) & 0xFF));

    /* push rax              — put it on the STACK */
    emit(j, 0x50);

    /* movsd xmmN, [rsp]     — load from STACK into register */
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x10);
    emit(j, 0x04 | (uint8_t)(xmm_reg << 3));
    emit(j, 0x24);

    /* add rsp, 8            — restore STACK pointer */
    emit(j, 0x48); emit(j, 0x83); emit(j, 0xC4); emit(j, 0x08);
}

/* Arithmetic: one CPU instruction each */
static void emit_addsd(JitCtx *j, int dst, int src) {
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x58);
    emit(j, 0xC0 | (uint8_t)(dst << 3) | (uint8_t)src);
}
static void emit_subsd(JitCtx *j, int dst, int src) {
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x5C);
    emit(j, 0xC0 | (uint8_t)(dst << 3) | (uint8_t)src);
}
static void emit_mulsd(JitCtx *j, int dst, int src) {
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x59);
    emit(j, 0xC0 | (uint8_t)(dst << 3) | (uint8_t)src);
}
static void emit_divsd(JitCtx *j, int dst, int src) {
    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x5E);
    emit(j, 0xC0 | (uint8_t)(dst << 3) | (uint8_t)src);
}
static void emit_ucomisd(JitCtx *j, int a, int b) {
    emit(j, 0x66); emit(j, 0x0F); emit(j, 0x2E);
    emit(j, 0xC0 | (uint8_t)(a << 3) | (uint8_t)b);
}

/* ===== AST → Machine Code ===== */

static int compile_expr(JitCtx *j, AstNode *node, int xmm_dst) {
    if (!node) return 0;

    switch (node->type) {
        case NODE_NUM:
            emit_load_const(j, xmm_dst, node->num_val);
            return 1;

        case NODE_IDENT: {
            if (!node->str_val) return 0;  /* NULL check! */
            int idx = jit_var_index(j, node->str_val);
            emit_load_var(j, xmm_dst, idx);
            return 1;
        }

        case NODE_BINOP: {
            int tmp = xmm_dst + 1;
            if (tmp > 5) return 0;  /* reserve xmm6-7 for modulo */

            if (!compile_expr(j, node->children[0], xmm_dst)) return 0;
            if (!compile_expr(j, node->children[1], tmp)) return 0;

            switch (node->op) {
                case TOK_PLUS:  emit_addsd(j, xmm_dst, tmp); break;
                case TOK_MINUS: emit_subsd(j, xmm_dst, tmp); break;
                case TOK_STAR:  emit_mulsd(j, xmm_dst, tmp); break;
                case TOK_SLASH: emit_divsd(j, xmm_dst, tmp); break;
                case TOK_PERCENT:
                    /* a % b = a - floor(a/b) * b */
                    /* movsd xmm6, xmm_dst (save a) */
                    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x10);
                    emit(j, 0xC0 | (6 << 3) | (uint8_t)xmm_dst);

                    emit_divsd(j, xmm_dst, tmp);

                    /* roundsd xmm_dst, xmm_dst, 1 (floor) */
                    emit(j, 0x66); emit(j, 0x0F); emit(j, 0x3A); emit(j, 0x0B);
                    emit(j, 0xC0 | (uint8_t)(xmm_dst << 3) | (uint8_t)xmm_dst);
                    emit(j, 0x01);

                    emit_mulsd(j, xmm_dst, tmp);
                    emit_subsd(j, 6, xmm_dst);

                    /* movsd xmm_dst, xmm6 */
                    emit(j, 0xF2); emit(j, 0x0F); emit(j, 0x10);
                    emit(j, 0xC0 | (uint8_t)(xmm_dst << 3) | 6);
                    break;
                default:
                    return 0;
            }
            return 1;
        }

        default:
            return 0;
    }
}

static int compile_assign(JitCtx *j, AstNode *node) {
    if (!node) return 0;  /* NULL check! */

    if (node->type == NODE_ASSIGN) {
        if (!node->children[0] || !node->children[0]->str_val) return 0;
        int var_idx = jit_var_index(j, node->children[0]->str_val);
        if (!compile_expr(j, node->children[1], 0)) return 0;
        emit_store_var(j, var_idx, 0);
        return 1;
    }
    if (node->type == NODE_LET) {
        if (!node->str_val) return 0;  /* NULL check! */
        int var_idx = jit_var_index(j, node->str_val);
        if (!compile_expr(j, node->children[0], 0)) return 0;
        emit_store_var(j, var_idx, 0);
        return 1;
    }
    return 0;
}

/* ===== JIT-ability Check ===== */

static int is_numeric_expr(AstNode *node) {
    if (!node) return 0;
    switch (node->type) {
        case NODE_NUM: return 1;
        case NODE_IDENT: return node->str_val != NULL;  /* must have a name */
        case NODE_BINOP:
            if (!node->children[0] || !node->children[1]) return 0;
            if (node->op == TOK_PLUS || node->op == TOK_MINUS ||
                node->op == TOK_STAR || node->op == TOK_SLASH ||
                node->op == TOK_PERCENT ||
                node->op == TOK_LT || node->op == TOK_GT ||
                node->op == TOK_LTE || node->op == TOK_GTE) {
                return is_numeric_expr(node->children[0]) &&
                       is_numeric_expr(node->children[1]);
            }
            return 0;
        default: return 0;
    }
}

static int is_jitable_body(AstNode *body) {
    if (!body || body->type != NODE_BLOCK) return 0;
    if (!body->children) return 0;  /* NULL check! */

    for (int i = 0; i < body->num_children; i++) {
        AstNode *stmt = body->children[i];
        if (!stmt) return 0;  /* NULL check! */
        if (stmt->type == NODE_ASSIGN) {
            if (!stmt->children[0] || !stmt->children[1]) return 0;
            if (!is_numeric_expr(stmt->children[1])) return 0;
        } else if (stmt->type == NODE_LET) {
            if (stmt->num_children < 1 || !stmt->children[0]) return 0;
            if (!is_numeric_expr(stmt->children[0])) return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

int jit_can_compile(AstNode *while_node, Env *env) {
    (void)env;
    if (!while_node || while_node->type != NODE_WHILE) return 0;
    if (while_node->num_children < 2) return 0;
    if (!while_node->children) return 0;  /* NULL check! */

    AstNode *cond = while_node->children[0];
    AstNode *body = while_node->children[1];
    if (!cond || !body) return 0;  /* NULL check! */

    if (cond->type != NODE_BINOP) return 0;
    if (cond->op != TOK_LT && cond->op != TOK_GT &&
        cond->op != TOK_LTE && cond->op != TOK_GTE) return 0;
    if (!is_numeric_expr(cond)) return 0;

    return is_jitable_body(body);
}

/* ===== Compile & Execute ===== */

JsValue jit_compile_and_run(AstNode *while_node, Env *env) {
    JitCtx j;
    jit_init(&j);

    /* Check mmap succeeded */
    if (!j.code) return js_undef();

    AstNode *cond = while_node->children[0];
    AstNode *body = while_node->children[1];

    /* Function prologue */
    emit(&j, 0x53);                                    /* push rbx */
    emit(&j, 0x48); emit(&j, 0x89); emit(&j, 0xFB);  /* mov rbx, rdi */

    /* === LOOP TOP === */
    j.loop_start = j.pos;

    /* Compile condition */
    if (!compile_expr(&j, cond->children[0], 0) ||
        !compile_expr(&j, cond->children[1], 1)) {
        jit_cleanup(&j);  /* clean up on failure! */
        return js_undef();
    }

    emit_ucomisd(&j, 0, 1);

    /* Conditional exit jump (fixup later) */
    switch (cond->op) {
        case TOK_LT:  emit(&j, 0x0F); emit(&j, 0x83); break;
        case TOK_LTE: emit(&j, 0x0F); emit(&j, 0x87); break;
        case TOK_GT:  emit(&j, 0x0F); emit(&j, 0x86); break;
        case TOK_GTE: emit(&j, 0x0F); emit(&j, 0x82); break;
        default: jit_cleanup(&j); return js_undef();
    }
    int fixup_pos = j.pos;
    emit32(&j, 0);  /* placeholder */

    /* Compile body */
    for (int i = 0; i < body->num_children; i++) {
        if (!compile_assign(&j, body->children[i])) {
            jit_cleanup(&j);  /* clean up on failure! */
            return js_undef();
        }
    }

    /* Jump back to top */
    emit(&j, 0xE9);
    int32_t back_offset = j.loop_start - (j.pos + 4);
    emit32(&j, back_offset);

    /* Fixup exit jump */
    int32_t exit_offset = j.pos - (fixup_pos + 4);
    memcpy(&j.code[fixup_pos], &exit_offset, 4);

    /* Epilogue */
    emit(&j, 0x5B);  /* pop rbx */
    emit(&j, 0xC3);  /* ret */

    /* === Load variables from env into STACK array === */
    double vars[32] = {0};   /* STACK allocated — auto freed on return */
    for (int i = 0; i < j.var_count; i++) {
        if (j.var_names[i]) {  /* NULL check! */
            JsValue v = env_get(env, j.var_names[i]);
            vars[i] = js_is_num(v) ? js_as_num(v) : 0;
        }
    }

    /* === EXECUTE generated machine code === */
    typedef void (*JitFn)(double *);
    JitFn fn = (JitFn)j.code;
    fn(vars);    /* CPU runs our generated instructions */
    fn = NULL;   /* NULL after use — code is about to be munmap'd */

    /* === Write results back to env (HEAP hash table) === */
    for (int i = 0; i < j.var_count; i++) {
        if (j.var_names[i]) {  /* NULL check! */
            env_set(env, j.var_names[i], js_num(vars[i]));
        }
    }

    /* === Free ALL heap memory, NULL all pointers === */
    jit_cleanup(&j);

    return js_undef();
}
