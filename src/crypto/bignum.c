/*
 * bignum.c — Big Integer Arithmetic Implementation
 * ============================================================================
 * Grade-school arithmetic at scale. Each operation works word-by-word,
 * propagating carries/borrows just like you do with pencil and paper.
 *
 * Performance note: This is a simple, readable implementation. Production
 * crypto uses Montgomery multiplication, Karatsuba, and assembly-optimized
 * routines. But for learning, clarity > speed.
 * ============================================================================
 */

#include "bignum.h"
#include "fast/fast_crypto.h"
#include <string.h>
#include <stdio.h>

void bn_zero(bignum *n)
{
    memset(n->words, 0, sizeof(n->words));
    n->len = 1;
}

void bn_from_uint(bignum *n, uint32_t val)
{
    bn_zero(n);
    n->words[0] = val;
    n->len = (val == 0) ? 1 : 1;
}

/* Trim leading zero words (keep at least 1 word) */
static void bn_trim(bignum *n)
{
    while (n->len > 1 && n->words[n->len - 1] == 0) {
        n->len--;
    }
}

void bn_from_bytes(bignum *n, const uint8_t *buf, size_t buf_len)
{
    /*
     * Convert big-endian byte array to little-endian word array.
     *
     * RSA keys store numbers in big-endian bytes: most significant byte first.
     * We need least significant word first.
     *
     * Example: bytes [0x12, 0x34, 0x56, 0x78] (big-endian)
     *   → words[0] = 0x12345678, len = 1
     */
    bn_zero(n);

    int word_idx = 0;
    int byte_in_word = 0;

    /* Process bytes from least significant (end) to most significant (start) */
    for (int i = (int)buf_len - 1; i >= 0; i--) {
        n->words[word_idx] |= ((uint32_t)buf[i]) << (byte_in_word * 8);
        byte_in_word++;
        if (byte_in_word == 4) {
            byte_in_word = 0;
            word_idx++;
        }
    }

    n->len = word_idx + 1;
    if (n->len > BN_MAX_WORDS) n->len = BN_MAX_WORDS;
    bn_trim(n);
}

void bn_to_bytes(const bignum *n, uint8_t *buf, size_t buf_len)
{
    /*
     * Convert little-endian word array to big-endian byte array.
     * Pads with leading zeros if buf_len > needed bytes.
     */
    memset(buf, 0, buf_len);

    for (int i = 0; i < n->len && i * 4 < (int)buf_len; i++) {
        uint32_t w = n->words[i];
        for (int j = 0; j < 4; j++) {
            int byte_pos = i * 4 + j;
            int buf_pos = (int)buf_len - 1 - byte_pos;
            if (buf_pos >= 0) {
                buf[buf_pos] = (uint8_t)(w & 0xFF);
            }
            w >>= 8;
        }
    }
}

int bn_bit_length(const bignum *n)
{
    if (n->len == 1 && n->words[0] == 0) return 0;

    int bits = (n->len - 1) * 32;
    uint32_t top = n->words[n->len - 1];
    while (top > 0) {
        bits++;
        top >>= 1;
    }
    return bits;
}

int bn_cmp(const bignum *a, const bignum *b)
{
    /* Compare from most significant word to least */
    int max_len = (a->len > b->len) ? a->len : b->len;

    for (int i = max_len - 1; i >= 0; i--) {
        uint32_t wa = (i < a->len) ? a->words[i] : 0;
        uint32_t wb = (i < b->len) ? b->words[i] : 0;
        if (wa > wb) return 1;
        if (wa < wb) return -1;
    }
    return 0;
}

void bn_add(bignum *c, const bignum *a, const bignum *b)
{
    /*
     * Addition: word by word with carry, just like adding digit by digit.
     *
     *   carry = 0
     *   for each word position i:
     *     sum = a[i] + b[i] + carry
     *     c[i] = low 32 bits of sum
     *     carry = high bit(s) of sum
     */
    int max_len = (a->len > b->len) ? a->len : b->len;
    uint64_t carry = 0;

    for (int i = 0; i < max_len || carry; i++) {
        uint64_t sum = carry;
        if (i < a->len) sum += a->words[i];
        if (i < b->len) sum += b->words[i];
        c->words[i] = (uint32_t)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
        if (i + 1 > max_len) max_len = i + 1;
    }

    c->len = max_len + (carry ? 1 : 0);
    if (c->len > BN_MAX_WORDS) c->len = BN_MAX_WORDS;
    bn_trim(c);
}

void bn_sub(bignum *c, const bignum *a, const bignum *b)
{
    /*
     * Subtraction with borrow. Assumes a >= b.
     * Same as addition but we track borrow instead of carry.
     */
    int64_t borrow = 0;

    for (int i = 0; i < a->len; i++) {
        int64_t diff = (int64_t)a->words[i] - borrow;
        if (i < b->len) diff -= (int64_t)b->words[i];

        if (diff < 0) {
            diff += (int64_t)1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        c->words[i] = (uint32_t)diff;
    }

    c->len = a->len;
    bn_trim(c);
}

void bn_mul(bignum *c, const bignum *a, const bignum *b)
{
    /*
     * Uses assembly 64-bit MUL + ADC carry chains for the inner loop.
     * Falls back to C schoolbook if needed.
     */
    bignum result;
    bn_zero(&result);

    /* === ASM FAST PATH (64-bit MUL) — always available on x86_64 === */
    fast_bn_mul_words(result.words, a->words, a->len, b->words, b->len);

    result.len = a->len + b->len;
    if (result.len > BN_MAX_WORDS) result.len = BN_MAX_WORDS;
    bn_trim(&result);
    *c = result;
}

/*
 * Left shift by one bit (multiply by 2).
 */
static void bn_shl1(bignum *n)
{
    uint32_t carry = 0;
    for (int i = 0; i < n->len; i++) {
        uint32_t new_carry = n->words[i] >> 31;
        n->words[i] = (n->words[i] << 1) | carry;
        carry = new_carry;
    }
    if (carry && n->len < BN_MAX_WORDS) {
        n->words[n->len] = carry;
        n->len++;
    }
}

/*
 * Right shift by one bit (divide by 2).
 */
static void bn_shr1(bignum *n)
{
    for (int i = 0; i < n->len - 1; i++) {
        n->words[i] = (n->words[i] >> 1) | (n->words[i + 1] << 31);
    }
    n->words[n->len - 1] >>= 1;
    bn_trim(n);
}

void bn_divmod(bignum *q, bignum *r, const bignum *a, const bignum *b)
{
    /*
     * Binary long division.
     *
     * This is the simplest correct division algorithm. For each bit of
     * the dividend (from MSB to LSB), shift the remainder left by 1,
     * add the bit, and if remainder >= divisor, subtract divisor and
     * set the corresponding quotient bit.
     *
     * O(n^2) in bit length — slow but correct and simple.
     */
    bignum quotient, remainder;
    bn_zero(&quotient);
    bn_zero(&remainder);

    int bits = bn_bit_length(a);

    for (int i = bits - 1; i >= 0; i--) {
        /* remainder = remainder << 1 */
        bn_shl1(&remainder);

        /* Add bit i of a to remainder */
        int word_idx = i / 32;
        int bit_idx = i % 32;
        if (a->words[word_idx] & ((uint32_t)1 << bit_idx)) {
            remainder.words[0] |= 1;
        }

        /* If remainder >= b, subtract b and set quotient bit */
        if (bn_cmp(&remainder, b) >= 0) {
            bn_sub(&remainder, &remainder, b);

            int qword = i / 32;
            int qbit = i % 32;
            if (qword < BN_MAX_WORDS) {
                quotient.words[qword] |= ((uint32_t)1 << qbit);
                if (qword + 1 > quotient.len) quotient.len = qword + 1;
            }
        }
    }

    bn_trim(&quotient);
    bn_trim(&remainder);

    if (q) *q = quotient;
    if (r) *r = remainder;
}

void bn_mod(bignum *c, const bignum *a, const bignum *b)
{
    bn_divmod(NULL, c, a, b);
}

void bn_mod_exp(bignum *result, const bignum *base, const bignum *exp, const bignum *mod)
{
    /*
     * Modular exponentiation using square-and-multiply.
     *
     * To compute base^exp mod mod:
     *
     *   result = 1
     *   b = base mod mod
     *   for each bit of exp (LSB to MSB):
     *     if bit is 1: result = result * b mod mod
     *     b = b * b mod mod
     *
     * This processes one bit of the exponent per iteration.
     * For a 2048-bit exponent, that's 2048 iterations with at most
     * 2 multiplications each — way better than 2^2048 multiplications!
     *
     * Example: 3^13 mod 7
     *   13 in binary = 1101
     *   Bit 0 (1): result = 1 * 3 = 3 mod 7 = 3,   b = 3*3 = 9 mod 7 = 2
     *   Bit 1 (0): result = 3 (unchanged),            b = 2*2 = 4 mod 7 = 4
     *   Bit 2 (1): result = 3 * 4 = 12 mod 7 = 5,    b = 4*4 = 16 mod 7 = 2
     *   Bit 3 (1): result = 5 * 2 = 10 mod 7 = 3
     *   Answer: 3^13 mod 7 = 3 ✓
     */
    bignum b, temp;
    bn_from_uint(result, 1);

    /* b = base mod mod */
    bn_mod(&b, base, mod);

    int bits = bn_bit_length(exp);

    for (int i = 0; i < bits; i++) {
        /* Check if bit i of exp is set */
        int word_idx = i / 32;
        int bit_idx = i % 32;

        if (exp->words[word_idx] & ((uint32_t)1 << bit_idx)) {
            /* result = result * b mod mod */
            bn_mul(&temp, result, &b);
            bn_mod(result, &temp, mod);
        }

        /* b = b * b mod mod */
        bn_mul(&temp, &b, &b);
        bn_mod(&b, &temp, mod);
    }
}
