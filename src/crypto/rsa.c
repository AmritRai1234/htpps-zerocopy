/*
 * rsa.c — RSA Implementation
 * ============================================================================
 */

#include "rsa.h"
#include "pem.h"
#include "bignum.h"
#include <stdio.h>
#include <string.h>

int rsa_load_private_key(const char *pem_path, rsa_key *key)
{
    /*
     * An RSA private key in PKCS#1 DER format is:
     *
     * SEQUENCE {
     *   INTEGER version     (0)
     *   INTEGER n           (modulus)
     *   INTEGER e           (public exponent)
     *   INTEGER d           (private exponent)
     *   INTEGER p           (prime 1)
     *   INTEGER q           (prime 2)
     *   INTEGER dp          (d mod (p-1))  — we ignore these
     *   INTEGER dq          (d mod (q-1))  — CRT optimization
     *   INTEGER qinv        (q^-1 mod p)   — we don't use CRT
     * }
     */
    uint8_t der[8192];
    size_t der_len;

    if (pem_read_file(pem_path, der, sizeof(der), &der_len) < 0) {
        fprintf(stderr, "Failed to read PEM file: %s\n", pem_path);
        return -1;
    }

    printf("[RSA] Loaded %zu bytes of DER data\n", der_len);

    const uint8_t *p = der;
    size_t remaining = der_len;

    /* Read outer SEQUENCE */
    size_t seq_len;
    if (asn1_read_sequence(&p, &remaining, &seq_len) < 0) {
        fprintf(stderr, "Failed to read SEQUENCE\n");
        return -1;
    }

    /* Read version (should be 0) */
    uint8_t ver_buf[8];
    size_t ver_len;
    if (asn1_read_integer(&p, &remaining, ver_buf, sizeof(ver_buf), &ver_len) < 0) {
        fprintf(stderr, "Failed to read version\n");
        return -1;
    }

    /* Read n (modulus) */
    uint8_t int_buf[512];
    size_t int_len;

    if (asn1_read_integer(&p, &remaining, int_buf, sizeof(int_buf), &int_len) < 0) {
        fprintf(stderr, "Failed to read n\n");
        return -1;
    }
    bn_from_bytes(&key->n, int_buf, int_len);
    key->bits = bn_bit_length(&key->n);
    printf("[RSA] Modulus: %d bits\n", key->bits);

    /* Read e (public exponent) */
    if (asn1_read_integer(&p, &remaining, int_buf, sizeof(int_buf), &int_len) < 0) {
        fprintf(stderr, "Failed to read e\n");
        return -1;
    }
    bn_from_bytes(&key->e, int_buf, int_len);

    /* Read d (private exponent) */
    if (asn1_read_integer(&p, &remaining, int_buf, sizeof(int_buf), &int_len) < 0) {
        fprintf(stderr, "Failed to read d\n");
        return -1;
    }
    bn_from_bytes(&key->d, int_buf, int_len);

    /* Read p (prime 1) */
    if (asn1_read_integer(&p, &remaining, int_buf, sizeof(int_buf), &int_len) < 0) {
        fprintf(stderr, "Failed to read p\n");
        return -1;
    }
    bn_from_bytes(&key->p, int_buf, int_len);

    /* Read q (prime 2) */
    if (asn1_read_integer(&p, &remaining, int_buf, sizeof(int_buf), &int_len) < 0) {
        fprintf(stderr, "Failed to read q\n");
        return -1;
    }
    bn_from_bytes(&key->q, int_buf, int_len);

    printf("[RSA] Key loaded successfully (e=%u)\n", key->e.words[0]);
    return 0;
}

int rsa_decrypt_pkcs1(const rsa_key *key,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *pt, size_t pt_max, size_t *pt_len)
{
    /*
     * RSA decryption: plaintext = ciphertext^d mod n
     *
     * The ciphertext is the pre-master secret encrypted by the client
     * using our public key. We decrypt it using our private key.
     */
    bignum ct_bn, pt_bn;

    /* Convert ciphertext bytes to bignum */
    bn_from_bytes(&ct_bn, ct, ct_len);

    /* The magic: pt = ct^d mod n */
    printf("[RSA] Performing modular exponentiation (%d-bit key)...\n", key->bits);
    bn_mod_exp(&pt_bn, &ct_bn, &key->d, &key->n);

    /* Convert back to bytes */
    size_t key_bytes = (size_t)((key->bits + 7) / 8);
    uint8_t decrypted[512];
    if (key_bytes > sizeof(decrypted)) return -1;
    bn_to_bytes(&pt_bn, decrypted, key_bytes);

    /*
     * Strip PKCS#1 v1.5 padding.
     *
     * Format: 0x00 | 0x02 | [random non-zero bytes] | 0x00 | [plaintext]
     *
     * The padding must start with 0x00 0x02, followed by at least 8
     * non-zero random bytes, then a 0x00 separator, then the actual data.
     */
    if (key_bytes < 11) return -1;  /* Minimum: 2 + 8 + 1 = 11 bytes of overhead */
    if (decrypted[0] != 0x00 || decrypted[1] != 0x02) {
        fprintf(stderr, "[RSA] Invalid PKCS#1 padding (expected 0x00 0x02, got 0x%02x 0x%02x)\n",
                decrypted[0], decrypted[1]);
        return -1;
    }

    /* Find the 0x00 separator after the random padding */
    size_t sep = 2;
    while (sep < key_bytes && decrypted[sep] != 0x00) {
        sep++;
    }

    if (sep >= key_bytes || sep < 10) {
        /* Must have at least 8 bytes of padding */
        fprintf(stderr, "[RSA] PKCS#1 padding too short or missing separator\n");
        return -1;
    }

    sep++; /* Skip the 0x00 separator */

    /* The actual plaintext starts after the separator */
    size_t data_len = key_bytes - sep;
    if (data_len > pt_max) return -1;

    memcpy(pt, decrypted + sep, data_len);
    *pt_len = data_len;

    return 0;
}
