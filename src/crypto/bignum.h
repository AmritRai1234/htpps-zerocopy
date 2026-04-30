/*
 * bignum.h — Big Integer Arithmetic
 * ============================================================================
 * RSA uses numbers that are 2048 bits (256 bytes) long. Your CPU's largest
 * native integer is 64 bits. So we need to implement arithmetic on numbers
 * made up of ARRAYS of 64-bit words — "bignums."
 *
 * Think of it like grade-school math, but instead of base-10 digits, we
 * use base-2^32 digits (32-bit words).
 *
 * Example: the number 0x1234567890ABCDEF is stored as:
 *   words[0] = 0x90ABCDEF  (low word)
 *   words[1] = 0x12345678  (high word)
 *   len = 2
 *
 * This is called "little-endian word order" — least significant word first.
 * (Even though each word is stored in native byte order.)
 *
 * The key operation for RSA is MODULAR EXPONENTIATION:
 *   result = base^exponent mod modulus
 *
 * For RSA-2048, this is a 2048-bit number raised to a 2048-bit power,
 * modulo another 2048-bit number. Naive exponentiation would produce a
 * number with 2^2048 digits — not feasible. We use "square-and-multiply"
 * to keep the intermediate results small by reducing mod at each step.
 * ============================================================================
 */

#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Max size: 2048-bit RSA = 64 x 32-bit words.
 * We add some headroom for intermediate calculations.
 */
#define BN_MAX_WORDS 128

typedef struct {
    uint32_t words[BN_MAX_WORDS];  /* Little-endian array of 32-bit words */
    int len;                        /* Number of significant words */
} bignum;

/* Initialize a bignum to zero */
void bn_zero(bignum *n);

/* Set a bignum from a small integer */
void bn_from_uint(bignum *n, uint32_t val);

/* Load a bignum from big-endian byte array (as found in RSA keys) */
void bn_from_bytes(bignum *n, const uint8_t *buf, size_t buf_len);

/* Export a bignum to big-endian byte array */
void bn_to_bytes(const bignum *n, uint8_t *buf, size_t buf_len);

/* Get the number of significant bits */
int bn_bit_length(const bignum *n);

/* Compare: returns -1 if a<b, 0 if a==b, 1 if a>b */
int bn_cmp(const bignum *a, const bignum *b);

/* c = a + b */
void bn_add(bignum *c, const bignum *a, const bignum *b);

/* c = a - b (assumes a >= b) */
void bn_sub(bignum *c, const bignum *a, const bignum *b);

/* c = a * b */
void bn_mul(bignum *c, const bignum *a, const bignum *b);

/* q = a / b, r = a % b */
void bn_divmod(bignum *q, bignum *r, const bignum *a, const bignum *b);

/* c = a mod b */
void bn_mod(bignum *c, const bignum *a, const bignum *b);

/*
 * result = base^exp mod mod
 *
 * This is THE critical operation for RSA.
 * Uses square-and-multiply algorithm.
 */
void bn_mod_exp(bignum *result, const bignum *base, const bignum *exp, const bignum *mod);

#endif /* BIGNUM_H */
