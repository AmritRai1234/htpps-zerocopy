/*
 * fast_crypto.h — Hardware-Accelerated Crypto Dispatch
 * ============================================================================
 * Runtime detection of AES-NI, SHA-NI, and 64-bit MUL acceleration.
 * Call crypto_fast_init() once at startup; then use crypto_use_aesni()
 * / crypto_use_shani() to decide which path to take.
 * ============================================================================
 */

#ifndef FAST_CRYPTO_H
#define FAST_CRYPTO_H

#include <stdint.h>

/* ---- Initialization (call once at startup) ---- */
void crypto_fast_init(void);

/* ---- Feature queries ---- */
int crypto_use_aesni(void);
int crypto_use_shani(void);

/* ---- CPUID probes (from cpuid.asm) ---- */
extern int fast_has_aesni(void);
extern int fast_has_shani(void);
extern int fast_has_sse41(void);

/* ---- AES-NI functions (from crypto_ops.asm) ---- */
extern void fast_aes128_key_expand(const uint8_t key[16],
                                   uint8_t round_keys[176]);
extern void fast_aes128_encrypt_block(const uint8_t in[16],
                                      uint8_t out[16],
                                      const uint8_t round_keys[176]);
extern void fast_aes128_decrypt_block(const uint8_t in[16],
                                      uint8_t out[16],
                                      const uint8_t round_keys[176]);

/* ---- SHA-NI functions (from crypto_ops.asm) ---- */
extern void fast_sha256_transform(uint32_t state[8],
                                  const uint8_t block[64]);

/* ---- BigNum 64-bit multiply (from crypto_ops.asm) ---- */
extern void fast_bn_mul_words(uint32_t *result,
                              const uint32_t *a, int a_len,
                              const uint32_t *b, int b_len);

#endif /* FAST_CRYPTO_H */
