/*
 * prf.c — TLS Pseudo-Random Function (PRF)
 * ============================================================================
 * The PRF is how TLS derives keys from secrets. It's built on HMAC-SHA256.
 *
 * TLS uses the PRF for:
 *   1. Deriving master_secret from pre_master_secret
 *   2. Deriving the key_block (all session keys) from master_secret
 *   3. Computing Finished message verify_data
 *
 * The PRF works by:
 *   P_SHA256(secret, seed) = HMAC(secret, A(1) || seed) ||
 *                             HMAC(secret, A(2) || seed) ||
 *                             HMAC(secret, A(3) || seed) || ...
 *
 *   Where A(0) = seed, A(i) = HMAC(secret, A(i-1))
 *
 *   PRF(secret, label, seed) = P_SHA256(secret, label || seed)
 *
 * This generates an arbitrary amount of pseudorandom output.
 * ============================================================================
 */

#include "tls.h"
#include "../crypto/hmac.h"
#include <string.h>

void tls_prf(const uint8_t *secret, size_t secret_len,
             const char *label,
             const uint8_t *seed, size_t seed_len,
             uint8_t *output, size_t output_len)
{
    /*
     * Build the full seed: label || seed
     * The label is an ASCII string like "master secret" or "key expansion"
     */
    size_t label_len = strlen(label);
    size_t full_seed_len = label_len + seed_len;
    uint8_t full_seed[256];

    if (full_seed_len > sizeof(full_seed)) return; /* shouldn't happen */
    memcpy(full_seed, label, label_len);
    memcpy(full_seed + label_len, seed, seed_len);

    /*
     * P_SHA256 expansion:
     *   A(0) = full_seed
     *   A(i) = HMAC(secret, A(i-1))
     *   output = HMAC(secret, A(1) || full_seed) ||
     *            HMAC(secret, A(2) || full_seed) || ...
     *
     * Each iteration produces 32 bytes (SHA-256 output size).
     * We keep going until we've produced enough output.
     */
    uint8_t A[32]; /* A(i) */
    uint8_t hmac_input[32 + 256]; /* A(i) || full_seed */
    uint8_t hmac_out[32];

    /* A(1) = HMAC(secret, A(0)) = HMAC(secret, full_seed) */
    hmac_sha256(secret, secret_len, full_seed, full_seed_len, A);

    size_t produced = 0;
    while (produced < output_len) {
        /* HMAC(secret, A(i) || full_seed) */
        memcpy(hmac_input, A, 32);
        memcpy(hmac_input + 32, full_seed, full_seed_len);
        hmac_sha256(secret, secret_len, hmac_input, 32 + full_seed_len, hmac_out);

        /* Copy to output (might need less than 32 bytes on last iteration) */
        size_t to_copy = output_len - produced;
        if (to_copy > 32) to_copy = 32;
        memcpy(output + produced, hmac_out, to_copy);
        produced += to_copy;

        /* A(i+1) = HMAC(secret, A(i)) */
        hmac_sha256(secret, secret_len, A, 32, A);
    }
}
