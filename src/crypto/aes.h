/*
 * aes.h — AES-128 Block Cipher
 * ============================================================================
 * AES (Advanced Encryption Standard) is the symmetric cipher that encrypts
 * actual data in TLS. "Symmetric" means the same key encrypts AND decrypts.
 *
 * AES operates on 16-byte (128-bit) blocks. It takes a 16-byte plaintext
 * block and a 16-byte key, and produces a 16-byte ciphertext block.
 *
 * But real messages are longer than 16 bytes! So we need a "mode of
 * operation" that chains multiple blocks together. We use CBC:
 *
 * CBC (Cipher Block Chaining):
 *   - Before encrypting each block, XOR it with the previous ciphertext block
 *   - The first block is XORed with an IV (Initialization Vector)
 *   - This means identical plaintext blocks produce different ciphertext
 *     (because they're XORed with different previous blocks)
 *
 * WHERE TLS USES AES:
 *   - Encrypting HTTP data after the handshake
 *   - Our cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256
 *     means: RSA for key exchange, AES-128-CBC for encryption, SHA256 for MAC
 * ============================================================================
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16  /* AES always operates on 16-byte blocks */

/*
 * Encrypt a single 16-byte block.
 * This is the raw AES block cipher — no mode of operation.
 */
void aes128_encrypt_block(const uint8_t in[16], uint8_t out[16],
                          const uint8_t key[16]);

/*
 * Decrypt a single 16-byte block.
 */
void aes128_decrypt_block(const uint8_t in[16], uint8_t out[16],
                          const uint8_t key[16]);

/*
 * AES-128-CBC encryption with PKCS#7 padding.
 *
 * PKCS#7 padding: if the last block has N free bytes, fill them all with
 * the value N. If the input is already a multiple of 16, add a full
 * block of 16 bytes of value 0x10.
 *
 * @param in:      Plaintext input
 * @param in_len:  Input length (any length, will be padded)
 * @param out:     Ciphertext output (must be at least in_len + 16 bytes)
 * @param out_len: Set to actual ciphertext length
 * @param key:     16-byte AES key
 * @param iv:      16-byte initialization vector
 */
void aes128_cbc_encrypt(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len,
                        const uint8_t key[16], const uint8_t iv[16]);

/*
 * AES-128-CBC decryption with PKCS#7 unpadding.
 *
 * @param in:      Ciphertext input (must be multiple of 16)
 * @param in_len:  Input length
 * @param out:     Plaintext output
 * @param out_len: Set to actual plaintext length (after removing padding)
 * @param key:     16-byte AES key
 * @param iv:      16-byte initialization vector
 *
 * Returns 0 on success, -1 on padding error (possible tampering).
 */
int aes128_cbc_decrypt(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len,
                       const uint8_t key[16], const uint8_t iv[16]);

#endif /* AES_H */
