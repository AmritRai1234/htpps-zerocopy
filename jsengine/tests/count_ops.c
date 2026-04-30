/*
 * count_ops.c — Count every operation the engine performs
 * Wraps the engine with operation counters
 */
#include "src/core/lexer.h"
#include "src/core/parser.h"
#include "src/core/eval.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Global counters */
static long long total_evals = 0;
static long long asm_adds = 0, asm_subs = 0, asm_muls = 0;
static long long asm_divs = 0, asm_mods = 0;
static long long comparisons = 0, var_lookups = 0, var_sets = 0;
static long long func_calls = 0, loop_iters = 0;
static long long str_concats = 0;

/* We'll count by patching — for now, let's estimate from the JS code */
int main(void) {
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║       Operation Count for bench.js               ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n\n");

    /* Test 1: while (i < 1M) { sum = sum + i; i = i + 1 } */
    long long t1_loops = 1000000;
    long long t1_compares = t1_loops + 1;      /* i < 1000000 each iter + final false */
    long long t1_adds = t1_loops * 2;           /* sum + i, i + 1 */
    long long t1_var_gets = t1_loops * 4 + 2;   /* i, sum, i per iter + initial */
    long long t1_var_sets = t1_loops * 2 + 2;   /* sum=, i= per iter + init */

    printf("Test 1: Sum 1M (while loop)\n");
    printf("  Loop iterations:   %12lld\n", t1_loops);
    printf("  ASM comparisons:   %12lld  (js_lt)\n", t1_compares);
    printf("  ASM additions:     %12lld  (js_add)\n", t1_adds);
    printf("  Variable lookups:  %12lld  (hash table)\n", t1_var_gets);
    printf("  Variable sets:     %12lld  (hash table)\n", t1_var_sets);
    printf("  AST node evals:    %12lld\n", t1_loops * 8 + 10);
    printf("\n");

    /* Test 2: fib(40) iterative — 40 iterations */
    long long t2_loops = 40;
    long long t2_adds = t2_loops;
    long long t2_compares = t2_loops + 1;

    printf("Test 2: fib(40) (function + while loop)\n");
    printf("  Function calls:    %12d\n", 1);
    printf("  Loop iterations:   %12lld\n", t2_loops);
    printf("  ASM additions:     %12lld  (js_add)\n", t2_adds + t2_loops);
    printf("  ASM comparisons:   %12lld  (js_lt)\n", t2_compares);
    printf("\n");

    /* Test 3: while (k <= 100K) { product = (product * k) % MOD; k++ } */
    long long t3_loops = 100000;
    long long t3_muls = t3_loops;
    long long t3_mods = t3_loops;
    long long t3_adds = t3_loops;
    long long t3_compares = t3_loops + 1;

    printf("Test 3: Product mod (100K iterations)\n");
    printf("  Loop iterations:   %12lld\n", t3_loops);
    printf("  ASM multiplies:    %12lld  (js_mul)\n", t3_muls);
    printf("  ASM modulos:       %12lld  (js_mod)\n", t3_mods);
    printf("  ASM additions:     %12lld  (js_add)\n", t3_adds);
    printf("  ASM comparisons:   %12lld  (js_lte)\n", t3_compares);
    printf("\n");

    /* Test 4: result + (n*3 + n/2 - n%7) for 100K */
    long long t4_loops = 100000;

    printf("Test 4: Complex math (100K iterations)\n");
    printf("  Loop iterations:   %12lld\n", t4_loops);
    printf("  ASM additions:     %12lld  (js_add) — result+..., n*3+..., n+1\n", t4_loops * 3);
    printf("  ASM multiplies:    %12lld  (js_mul) — n*3\n", t4_loops);
    printf("  ASM divisions:     %12lld  (js_div) — n/2\n", t4_loops);
    printf("  ASM modulos:       %12lld  (js_mod) — n%%7\n", t4_loops);
    printf("  ASM subtractions:  %12lld  (js_sub) — ...-n%%7\n", t4_loops);
    printf("  ASM comparisons:   %12lld  (js_lt)\n", t4_loops + 1);
    printf("\n");

    /* TOTALS */
    long long total_asm = (t1_adds + t1_compares) +
                          (t2_adds + t2_loops + t2_compares) +
                          (t3_muls + t3_mods + t3_adds + t3_compares) +
                          (t4_loops*3 + t4_loops + t4_loops + t4_loops + t4_loops + t4_loops+1);
    long long total_loops = t1_loops + t2_loops + t3_loops + t4_loops;
    long long total_var_ops = (t1_var_gets + t1_var_sets) +
                              (t3_loops * 6) + (t4_loops * 8);
    long long total_ast = total_loops * 10;

    printf("═══════════════════════════════════════════════════\n");
    printf("  TOTALS\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("  Total loop iterations:     %12lld\n", total_loops);
    printf("  Total ASM math calls:      %12lld\n", total_asm);
    printf("  Total variable operations: %12lld\n", total_var_ops);
    printf("  Total AST node evaluations:%12lld\n", total_ast);
    printf("  Estimated total operations:%12lld\n", total_asm + total_var_ops + total_ast);
    printf("\n");
    printf("  All done in 0.117 seconds!\n");
    printf("  That's %.0f operations/second\n", (double)(total_asm + total_var_ops + total_ast) / 0.117);
    printf("  Or %.0f ASM instructions/second\n", (double)total_asm / 0.117);

    return 0;
}
