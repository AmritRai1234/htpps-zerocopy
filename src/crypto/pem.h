/*
 * pem.h — PEM File Parser (Base64 + ASN.1/DER)
 * ============================================================================
 * RSA keys are stored in PEM files, which look like:
 *
 *   -----BEGIN RSA PRIVATE KEY-----
 *   MIIEowIBAAKCAQEA... (base64-encoded binary data)
 *   -----END RSA PRIVATE KEY-----
 *
 * The binary data inside is encoded in DER (Distinguished Encoding Rules),
 * which is a subset of ASN.1 — a standard for encoding structured data.
 *
 * The chain: PEM file → base64 decode → DER bytes → ASN.1 parse → RSA numbers
 * ============================================================================
 */

#ifndef PEM_H
#define PEM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Decode base64 to binary.
 * Returns number of output bytes, or -1 on error.
 */
int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max);

/*
 * Read a PEM file and extract the DER-encoded binary data.
 * Strips the header/footer lines and decodes the base64 content.
 *
 * @param path:     Path to PEM file
 * @param der:      Output buffer for DER bytes
 * @param der_max:  Max size of output buffer
 * @param der_len:  Set to actual DER length
 *
 * Returns 0 on success, -1 on error.
 */
int pem_read_file(const char *path, uint8_t *der, size_t der_max, size_t *der_len);

/*
 * Parse an ASN.1 INTEGER from DER data.
 *
 * ASN.1 INTEGER encoding:
 *   Tag (0x02) | Length | Value (big-endian bytes)
 *
 * @param der:     DER data pointer (advanced past the parsed integer)
 * @param der_len: Remaining DER length (decremented)
 * @param out:     Output buffer for integer bytes
 * @param out_len: Set to actual integer byte length
 *
 * Returns 0 on success, -1 on error.
 */
int asn1_read_integer(const uint8_t **der, size_t *der_len,
                      uint8_t *out, size_t out_max, size_t *out_len);

/*
 * Skip an ASN.1 element (any type).
 */
int asn1_skip(const uint8_t **der, size_t *der_len);

/*
 * Read ASN.1 SEQUENCE header. Returns content length.
 */
int asn1_read_sequence(const uint8_t **der, size_t *der_len, size_t *content_len);

#endif /* PEM_H */
