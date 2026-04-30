/*
 * sha256.h — SHA-256 Hash Function
 * ============================================================================
 * SHA-256 is a cryptographic hash function. It takes ANY input (a file, a
 * string, a password, whatever) and produces a fixed 32-byte (256-bit) output
 * called a "digest" or "hash."
 *
 * KEY PROPERTIES:
 *   1. DETERMINISTIC: Same input → always same output.
 *   2. ONE-WAY: Given a hash, you can't figure out the input.
 *   3. AVALANCHE: Change 1 bit of input → ~50% of output bits change.
 *   4. COLLISION-RESISTANT: Infeasible to find two inputs with same hash.
 *
 * WHERE TLS USES SHA-256:
 *   - Verify handshake integrity (Finished messages)
 *   - HMAC-SHA256 for message authentication
 *   - Part of the PRF (pseudo-random function) for key derivation
 *   - Certificate signature verification
 *
 * The algorithm processes data in 64-byte (512-bit) blocks. If your input
 * isn't a multiple of 64 bytes, it gets padded. Each block goes through
 * 64 rounds of mixing with a 256-bit state (eight 32-bit words).
 * ============================================================================
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE  64   /* Input block size: 512 bits = 64 bytes */
#define SHA256_DIGEST_SIZE 32   /* Output digest size: 256 bits = 32 bytes */

/*
 * SHA-256 context — holds the running state between update() calls.
 *
 * This lets you hash data incrementally:
 *   sha256_init(&ctx);
 *   sha256_update(&ctx, chunk1, len1);
 *   sha256_update(&ctx, chunk2, len2);
 *   sha256_final(&ctx, hash);
 *
 * Internally, it buffers partial blocks and processes complete 64-byte blocks.
 */
typedef struct {
    uint32_t state[8];           /* The eight 32-bit hash state words (H0-H7) */
    uint64_t total_len;          /* Total bytes processed so far */
    uint8_t  buffer[SHA256_BLOCK_SIZE]; /* Partial block buffer */
    size_t   buffer_len;         /* How many bytes are in the buffer */
} sha256_ctx;

/* Initialize context with the standard IV (Initial Values from spec) */
void sha256_init(sha256_ctx *ctx);

/* Feed data into the hash. Can be called multiple times. */
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);

/* Finalize: pad the message, process last block(s), output 32-byte digest */
void sha256_final(sha256_ctx *ctx, uint8_t hash[SHA256_DIGEST_SIZE]);

/* Convenience: hash a complete message in one call */
void sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
