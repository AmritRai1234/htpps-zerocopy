/*
 * hmac.h — HMAC-SHA256 (Keyed-Hash Message Authentication Code)
 * ============================================================================
 * HMAC answers the question: "Was this message sent by someone who knows
 * the secret key, and was it modified in transit?"
 *
 * SHA-256 alone proves INTEGRITY (message wasn't modified), but anyone can
 * compute a SHA-256 hash. HMAC adds AUTHENTICATION — only someone with the
 * secret key can produce a valid HMAC.
 *
 * HOW HMAC WORKS (RFC 2104):
 *   HMAC(K, M) = SHA256( (K xor opad) || SHA256( (K xor ipad) || M ) )
 *
 *   Where:
 *     K     = secret key (padded to block size)
 *     M     = message
 *     ipad  = 0x36 repeated to fill a block (inner padding)
 *     opad  = 0x5c repeated to fill a block (outer padding)
 *     ||    = concatenation
 *
 *   In English:
 *     1. XOR the key with 0x36 bytes → inner key
 *     2. Hash(inner_key || message) → inner hash
 *     3. XOR the key with 0x5C bytes → outer key
 *     4. Hash(outer_key || inner_hash) → HMAC result
 *
 * WHERE TLS USES HMAC:
 *   - Message authentication in the record layer (MAC-then-encrypt in CBC)
 *   - Inside the PRF (pseudo-random function) for key derivation
 *   - Verify Finished messages in the handshake
 * ============================================================================
 */

#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

#define HMAC_SHA256_SIZE 32  /* Output size = SHA-256 digest size */

/*
 * Compute HMAC-SHA256.
 *
 * @param key:     Secret key (any length, will be hashed if > 64 bytes)
 * @param key_len: Key length in bytes
 * @param msg:     Message to authenticate
 * @param msg_len: Message length in bytes
 * @param out:     Output buffer (32 bytes)
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[HMAC_SHA256_SIZE]);

#endif /* HMAC_H */
