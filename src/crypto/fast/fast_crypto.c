/*
 * fast_crypto.c — Hardware Crypto Dispatch Layer
 * ============================================================================
 * Probes CPUID at startup, prints capabilities, and exposes boolean
 * flags so the existing C crypto code can branch to the assembly path.
 * ============================================================================
 */

#include "fast_crypto.h"
#include <stdio.h>

static int g_use_aesni = 0;
static int g_use_shani = 0;

void crypto_fast_init(void)
{
    g_use_aesni = fast_has_aesni();
    g_use_shani = fast_has_shani() && fast_has_sse41();

    printf("[FAST] AES-NI: %s | SHA-NI: %s | 64-bit MUL: yes\n",
           g_use_aesni ? "\033[32mON\033[0m" : "\033[31moff\033[0m",
           g_use_shani ? "\033[32mON\033[0m" : "\033[31moff\033[0m");
}

int crypto_use_aesni(void)
{
    return g_use_aesni;
}

int crypto_use_shani(void)
{
    return g_use_shani;
}
