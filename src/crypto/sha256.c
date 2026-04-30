/*
 * sha256.c — SHA-256 Implementation (FIPS 180-4)
 * ============================================================================
 * This implements the SHA-256 algorithm exactly as specified in the NIST
 * standard FIPS 180-4. Every line here corresponds to a step in the spec.
 *
 * THE BIG PICTURE:
 *   1. Pad the message to a multiple of 512 bits (64 bytes)
 *   2. Break into 64-byte blocks
 *   3. For each block:
 *      a. Expand 16 input words into 64 working words (message schedule)
 *      b. Run 64 rounds of compression on the state
 *   4. Output the final state as the hash
 *
 * THE COMPRESSION FUNCTION (what happens in each round):
 *   Each round mixes the current state with one word from the message
 *   schedule and a round constant. The mixing uses bitwise operations
 *   (rotations, XOR, AND) that make it impossible to reverse.
 * ============================================================================
 */

#include "sha256.h"
#include "fast/fast_crypto.h"
#include <string.h>

/*
 * Round constants K[0..63].
 *
 * These are the first 32 bits of the fractional parts of the cube roots
 * of the first 64 prime numbers (2, 3, 5, 7, 11, ...).
 *
 * Why primes? No particular mathematical reason — they just need to be
 * "nothing up my sleeve" numbers that aren't chosen to create weaknesses.
 * Using cube roots of primes is a transparent way to generate constants.
 */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Bitwise helper functions used in SHA-256.
 *
 * ROTR(x, n) = Rotate Right: shift x right by n bits, wrapping the
 *              bits that fall off the right back to the left.
 *              Example: ROTR(0b11001010, 3) = 0b01011001
 *
 * SHR(x, n)  = Shift Right: shift x right by n bits, filling with zeros.
 *              Unlike rotate, the bits that fall off are lost.
 *
 * These operations are the building blocks of the SHA-256 mixing functions.
 * Rotations preserve all bits (no information loss), while shifts lose bits.
 * The combination creates non-linear mixing that's hard to reverse.
 */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n)   ((x) >> (n))

/*
 * The six logical functions defined in the SHA-256 spec.
 * Each is a specific combination of rotations, shifts, XOR, AND, and NOT.
 *
 * Ch(x,y,z) = "Choice": for each bit position, if x=1 pick y, if x=0 pick z.
 *              It's a bitwise multiplexer/selector.
 *
 * Maj(x,y,z) = "Majority": for each bit, output the value that appears
 *               in at least 2 of the 3 inputs. Like a bitwise vote.
 *
 * Sigma0/Sigma1 = Used in the compression function (on state words)
 * sigma0/sigma1 = Used in the message schedule (on input words)
 *
 * The rotation amounts (2,13,22 / 6,11,25 / 7,18,3 / 17,19,10) are
 * carefully chosen so that the functions have good "diffusion" — each
 * output bit depends on many input bits.
 */
#define Ch(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x)       (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x)       (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x)       (ROTR(x, 7)  ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma1(x)       (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/*
 * Process one 64-byte block through the SHA-256 compression function.
 *
 * This is the core of SHA-256 — where all the actual hashing happens.
 * Everything else (init, update, final) is just bookkeeping to feed
 * data into this function one block at a time.
 */
static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
    /* === SHA-NI FAST PATH === */
    if (crypto_use_shani()) {
        fast_sha256_transform(ctx->state, block);
        return;
    }

    /* === C FALLBACK === */
    uint32_t W[64];  /* Message schedule: 64 words derived from the 16 input words */
    uint32_t a, b, c, d, e, f, g, h;

    /*
     * STEP 1: Prepare the message schedule W[0..63].
     *
     * W[0..15] = the 16 input words from the block (big-endian → native)
     * W[16..63] = derived from previous W values using sigma functions
     *
     * This "expands" the 16 input words into 64 words, spreading the
     * influence of each input bit across many rounds.
     */

    /* W[0..15]: Load 16 words from the block (big-endian byte order) */
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3]);
    }

    /* W[16..63]: Each word mixes four previous words */
    for (int i = 16; i < 64; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    /*
     * STEP 2: Initialize working variables with the current hash state.
     *
     * a-h correspond to H0-H7 in the spec. We use separate variables
     * because they get modified in each round.
     */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /*
     * STEP 3: The 64 compression rounds.
     *
     * Each round:
     *   T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
     *   T2 = Sigma0(a) + Maj(a,b,c)
     *   Then shift all variables down and inject T1 and T2.
     *
     * Visualize it like a conveyor belt: variables shift a→b→c→d→e→f→g→h,
     * with new values mixed in at 'a' and 'd'.
     *
     * After 64 rounds, every bit of the output depends on every bit of
     * the input in a hopelessly tangled way.
     */
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /*
     * STEP 4: Add the compressed values back to the running hash.
     *
     * This addition is what makes SHA-256 a "Merkle-Damgård" construction.
     * By adding (not replacing), we ensure that the hash of block N
     * depends on ALL previous blocks, not just block N.
     */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx *ctx)
{
    /*
     * Initial Hash Values H0-H7.
     *
     * These are the first 32 bits of the fractional parts of the square
     * roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
     *
     * Like the K constants, these are "nothing up my sleeve" numbers.
     */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;

    ctx->total_len = 0;
    ctx->buffer_len = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->total_len += len;

    /*
     * If we have leftover bytes in the buffer from a previous update(),
     * try to fill the buffer to a complete 64-byte block first.
     */
    if (ctx->buffer_len > 0) {
        size_t space = SHA256_BLOCK_SIZE - ctx->buffer_len;
        size_t to_copy = (len < space) ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    /* Process as many complete 64-byte blocks as possible directly from input */
    while (len >= SHA256_BLOCK_SIZE) {
        sha256_transform(ctx, data);
        data += SHA256_BLOCK_SIZE;
        len -= SHA256_BLOCK_SIZE;
    }

    /* Buffer any remaining bytes for the next update() or final() */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t hash[SHA256_DIGEST_SIZE])
{
    /*
     * SHA-256 PADDING:
     *
     * The message must be padded to a multiple of 512 bits (64 bytes).
     * The padding is:
     *   1. Append a single '1' bit (0x80 byte)
     *   2. Append zero bytes until we're 8 bytes short of a 64-byte boundary
     *   3. Append the original message length in bits as a 64-bit big-endian integer
     *
     * Why? The padding ensures that:
     *   - Every message has a unique padded form (prevents collisions)
     *   - The length is included (so "abc" and "abc\0" hash differently)
     *   - The final block is always full
     *
     * Example: hashing "abc" (3 bytes = 24 bits)
     *   61 62 63 80 00 00 00 00  00 00 00 00 00 00 00 00  ← data + 0x80 + zeros
     *   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ← more zeros
     *   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ← more zeros
     *   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 18  ← length in bits (24 = 0x18)
     */
    uint8_t pad[SHA256_BLOCK_SIZE * 2]; /* Worst case: need 2 blocks for padding */
    size_t pad_len;

    /* Start padding with 0x80 */
    size_t pos = ctx->buffer_len;
    memcpy(pad, ctx->buffer, pos);
    pad[pos++] = 0x80;

    /*
     * Calculate how much zero padding we need.
     * We need room for 8 bytes of length at the end of a 64-byte block.
     * If the current data + 1 (for 0x80) + 8 (for length) > 64,
     * we need an extra block.
     */
    if (pos > 56) {
        /* Not enough room in this block — fill it and add another */
        memset(pad + pos, 0, SHA256_BLOCK_SIZE - pos);
        pos = SHA256_BLOCK_SIZE;
        memset(pad + pos, 0, 56);
        pad_len = SHA256_BLOCK_SIZE * 2;
    } else {
        memset(pad + pos, 0, 56 - pos);
        pad_len = SHA256_BLOCK_SIZE;
    }

    /*
     * Append the total message length in BITS as a 64-bit big-endian value.
     * total_len is in bytes, so multiply by 8 (shift left by 3).
     */
    uint64_t total_bits = ctx->total_len * 8;
    pad[pad_len - 8] = (uint8_t)(total_bits >> 56);
    pad[pad_len - 7] = (uint8_t)(total_bits >> 48);
    pad[pad_len - 6] = (uint8_t)(total_bits >> 40);
    pad[pad_len - 5] = (uint8_t)(total_bits >> 32);
    pad[pad_len - 4] = (uint8_t)(total_bits >> 24);
    pad[pad_len - 3] = (uint8_t)(total_bits >> 16);
    pad[pad_len - 2] = (uint8_t)(total_bits >> 8);
    pad[pad_len - 1] = (uint8_t)(total_bits);

    /* Process the padded block(s) */
    for (size_t i = 0; i < pad_len; i += SHA256_BLOCK_SIZE) {
        sha256_transform(ctx, pad + i);
    }

    /*
     * OUTPUT: Write the hash state as 32 bytes in big-endian order.
     *
     * The 8 state words (each 32 bits) are concatenated to form the
     * 256-bit hash: H0 || H1 || H2 || H3 || H4 || H5 || H6 || H7
     */
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}
