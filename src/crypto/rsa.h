/*
 * rsa.h — RSA Asymmetric Encryption
 * ============================================================================
 * RSA is the asymmetric cipher used in TLS for key exchange.
 * "Asymmetric" means there are TWO keys: public and private.
 *
 * HOW RSA WORKS:
 *   1. Choose two large primes p and q
 *   2. Compute n = p * q (the "modulus")
 *   3. Compute d such that e*d ≡ 1 (mod (p-1)(q-1))
 *   4. Public key = (n, e) — anyone can have this
 *   5. Private key = (n, d) — only the server has this
 *
 *   Encrypt: C = M^e mod n  (using public key)
 *   Decrypt: M = C^d mod n  (using private key)
 *
 * The security relies on the fact that factoring n = p*q is
 * computationally infeasible for large primes (2048-bit n).
 *
 * IN TLS:
 *   1. Client generates a random "pre-master secret" (48 bytes)
 *   2. Client encrypts it with the server's public key (from the certificate)
 *   3. Client sends the encrypted blob to the server
 *   4. Server decrypts it with its private key
 *   5. Now both sides know the pre-master secret
 *   6. They derive encryption keys from it
 *
 * We only need to DECRYPT on the server side (client does the encryption).
 * ============================================================================
 */

#ifndef RSA_H
#define RSA_H

#include "bignum.h"
#include <stdint.h>
#include <stddef.h>

/* RSA private key components */
typedef struct {
    bignum n;    /* Modulus: n = p * q */
    bignum e;    /* Public exponent (usually 65537 = 0x10001) */
    bignum d;    /* Private exponent */
    bignum p;    /* Prime factor 1 */
    bignum q;    /* Prime factor 2 */
    int bits;    /* Key size in bits (e.g., 2048) */
} rsa_key;

/*
 * Load an RSA private key from a PEM file.
 *
 * The PEM file is the standard format output by:
 *   openssl genrsa -out key.pem 2048
 *
 * Returns 0 on success, -1 on error.
 */
int rsa_load_private_key(const char *pem_path, rsa_key *key);

/*
 * RSA decrypt with PKCS#1 v1.5 unpadding.
 *
 * The client sends: ct = msg^e mod n (encrypted with our public key)
 * We compute:       msg = ct^d mod n (decrypted with our private key)
 * Then we strip the PKCS#1 v1.5 padding to get the actual pre-master secret.
 *
 * PKCS#1 v1.5 padding format:
 *   0x00 | 0x02 | [random non-zero bytes] | 0x00 | [actual data]
 *
 * @param key:      Our private key
 * @param ct:       Ciphertext (encrypted pre-master secret from client)
 * @param ct_len:   Ciphertext length (should be key_size / 8 bytes)
 * @param pt:       Output plaintext buffer
 * @param pt_len:   Set to actual plaintext length
 *
 * Returns 0 on success, -1 on error.
 */
int rsa_decrypt_pkcs1(const rsa_key *key,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *pt, size_t pt_max, size_t *pt_len);

#endif /* RSA_H */
