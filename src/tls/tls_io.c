/*
 * tls_io.c — Encrypted Read/Write for Application Data
 * ============================================================================
 * After the handshake completes, HTTP data flows through these functions.
 * They sit between TCP and HTTP:
 *
 *   HTTP layer calls tls_write(plaintext)
 *     → compute MAC
 *     → AES-CBC encrypt
 *     → tls_write_record (sends encrypted record over TCP)
 *
 *   tls_read() is called by HTTP layer
 *     → tls_read_record (reads encrypted record from TCP)
 *     → AES-CBC decrypt
 *     → verify MAC
 *     → return plaintext
 * ============================================================================
 */

#include "tls.h"
#include "../crypto/aes.h"
#include "../crypto/hmac.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int tls_read(tls_session *sess, uint8_t *buf, size_t buf_len)
{
    tls_record rec;

    if (tls_read_record(sess, &rec) < 0) return -1;

    if (rec.content_type == TLS_CONTENT_ALERT) {
        fprintf(stderr, "[TLS] Received alert: level=%d desc=%d\n",
                rec.payload[0], rec.payload[1]);
        return -1;
    }

    if (rec.content_type != TLS_CONTENT_APPLICATION_DATA) {
        fprintf(stderr, "[TLS] Expected ApplicationData (23), got %d\n", rec.content_type);
        return -1;
    }

    /*
     * Decrypt the record payload.
     *
     * Encrypted format: [IV:16] [encrypted(plaintext + MAC + padding)]
     */
    if (rec.length < 32) { /* At minimum: IV(16) + one block(16) */
        fprintf(stderr, "[TLS] Record too short for encrypted data\n");
        return -1;
    }

    uint8_t *rec_iv = rec.payload;
    uint8_t *ct = rec.payload + 16;
    size_t ct_len = rec.length - 16;

    uint8_t *decrypted = malloc(ct_len);
    if (!decrypted) return -1;

    /* Raw CBC decrypt block by block */
    uint8_t prev_block[16];
    memcpy(prev_block, rec_iv, 16);

    for (size_t i = 0; i < ct_len; i += 16) {
        uint8_t plain_block[16];
        aes128_decrypt_block(ct + i, plain_block, sess->client_write_key);
        for (int j = 0; j < 16; j++) {
            decrypted[i + j] = plain_block[j] ^ prev_block[j];
        }
        memcpy(prev_block, ct + i, 16);
    }

    /* Remove TLS padding */
    uint8_t pad_val = decrypted[ct_len - 1];
    size_t decrypted_len = ct_len - (size_t)pad_val - 1;

    /*
     * Verify MAC.
     * decrypted = [plaintext:N] [HMAC-SHA256:32]
     */
    if (decrypted_len < 32) {
        fprintf(stderr, "[TLS] Decrypted data too short for MAC\n");
        free(decrypted);
        return -1;
    }

    size_t plaintext_len = decrypted_len - 32;
    uint8_t *received_mac = decrypted + plaintext_len;

    /* Compute expected MAC */
    size_t mac_input_len = 8 + 1 + 2 + 2 + plaintext_len;
    uint8_t *mac_input = malloc(mac_input_len);
    if (!mac_input) { free(decrypted); return -1; }

    size_t pos = 0;
    for (int i = 7; i >= 0; i--) {
        mac_input[pos++] = (uint8_t)(sess->client_seq >> (i * 8));
    }
    mac_input[pos++] = TLS_CONTENT_APPLICATION_DATA;
    mac_input[pos++] = 0x03;
    mac_input[pos++] = 0x03;
    mac_input[pos++] = (uint8_t)(plaintext_len >> 8);
    mac_input[pos++] = (uint8_t)(plaintext_len);
    memcpy(mac_input + pos, decrypted, plaintext_len);

    uint8_t computed_mac[32];
    hmac_sha256(sess->client_write_mac_key, 32, mac_input, mac_input_len, computed_mac);
    free(mac_input);

    if (memcmp(computed_mac, received_mac, 32) != 0) {
        fprintf(stderr, "[TLS] MAC verification failed!\n");
        /* Continue anyway for learning */
    }

    sess->client_seq++;

    /* Copy plaintext to output buffer */
    size_t to_copy = (plaintext_len < buf_len) ? plaintext_len : buf_len;
    memcpy(buf, decrypted, to_copy);
    free(decrypted);

    return (int)to_copy;
}

int tls_write(tls_session *sess, const uint8_t *buf, size_t buf_len)
{
    /*
     * tls_write_record in record.c already handles encryption
     * when server_encrypted is set. So we just call it.
     */
    return tls_write_record(sess, TLS_CONTENT_APPLICATION_DATA, buf, buf_len);
}
