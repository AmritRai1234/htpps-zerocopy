/*
 * hmac.c — HMAC-SHA256 Implementation (RFC 2104)
 * ============================================================================
 * HMAC is beautifully simple — it's just two SHA-256 hashes with key mixing.
 * The entire implementation is about 30 lines of real code.
 *
 * The trick is XORing the key with two different constants (ipad/opad).
 * This creates two related-but-different keys, and hashing with both
 * prevents "length extension attacks" that would break naive H(key||msg).
 * ============================================================================
 */

#include "hmac.h"
#include "sha256.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[HMAC_SHA256_SIZE])
{
    uint8_t k_padded[SHA256_BLOCK_SIZE]; /* Key padded/hashed to exactly 64 bytes */
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    sha256_ctx ctx;

    /*
     * STEP 1: Prepare the key.
     *
     * If key > 64 bytes: hash it down to 32 bytes (keys longer than the
     *   block size are hashed first per the spec).
     * If key <= 64 bytes: use it directly, pad with zeros.
     *
     * Either way, we end up with a 64-byte padded key.
     */
    memset(k_padded, 0, SHA256_BLOCK_SIZE);
    if (key_len > SHA256_BLOCK_SIZE) {
        /* Long key: hash it first */
        sha256(key, key_len, k_padded); /* Result is 32 bytes, rest is zeros */
    } else {
        memcpy(k_padded, key, key_len);
    }

    /*
     * STEP 2: Inner hash = SHA256( (K xor ipad) || message )
     *
     * ipad = 0x36 repeated 64 times.
     * We XOR the key with ipad, then hash that followed by the message.
     */
    uint8_t inner_key[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_key[i] = k_padded[i] ^ 0x36;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, inner_key, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner_hash);

    /*
     * STEP 3: Outer hash = SHA256( (K xor opad) || inner_hash )
     *
     * opad = 0x5C repeated 64 times.
     * We XOR the key with opad, then hash that followed by the inner hash.
     *
     * This "double hashing" structure is what makes HMAC secure against
     * attacks that exploit the internal structure of SHA-256.
     */
    uint8_t outer_key[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        outer_key[i] = k_padded[i] ^ 0x5C;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, outer_key, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}
