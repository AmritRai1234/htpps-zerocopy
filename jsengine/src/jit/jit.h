/*
 * jit.h — Just-In-Time Compiler
 * ============================================================================
 * Takes an AST node (like a while loop) and compiles it to REAL x86-64
 * machine code. The generated code runs directly on the CPU — no interpreter,
 * no tree walking, no hash lookups. Just raw instructions.
 *
 * How it works:
 *   1. Detect a "hot" while loop (simple numeric loop)
 *   2. Emit x86-64 machine code bytes into an mmap'd buffer
 *   3. Cast the buffer to a function pointer and CALL it
 *   4. The CPU executes our generated code natively
 *
 * We use XMM registers to hold JS doubles:
 *   xmm0-xmm7 = local variables (mapped by index)
 *   Function signature: void jit_fn(double *vars)
 *     vars[] is an array of variable values passed in/out
 * ============================================================================
 */

#ifndef JS_JIT_H
#define JS_JIT_H

#include "../core/parser.h"
#include "../core/eval.h"

/* Can this while loop be JIT compiled? */
int jit_can_compile(AstNode *while_node, Env *env);

/*
 * JIT compile a while loop and execute it.
 * Returns the result, or js_undef() if JIT fails (falls back to interpreter).
 *
 * The JIT modifies variables in env directly.
 */
JsValue jit_compile_and_run(AstNode *while_node, Env *env);

#endif /* JS_JIT_H */
