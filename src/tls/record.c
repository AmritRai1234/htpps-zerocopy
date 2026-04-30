/*
 * record.c — TLS Record Layer
 * ============================================================================
 * Every TLS message (handshake, alert, encrypted data) is wrapped in a record:
 *
 *   +---+---+---+---+---+---+---+---+---+---+---+
 *   | ContentType | Version | Length  |  Payload  |
 *   |  (1 byte)   | (2 bytes)|(2 bytes)|  (N bytes)|
 *   +---+---+---+---+---+---+---+---+---+---+---+
 *
 * When encryption is active, the payload is:
 *   [IV:16] [encrypted_data] [MAC:32] [padding]
 *
 * We handle both plaintext records (during handshake) and encrypted records
 * (after ChangeCipherSpec).
 * ============================================================================
 */

#include "tls.h"
#include "../crypto/aes.h"
#include "../crypto/hmac.h"
#include "../crypto/sha256.h"
#include "../tcp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Read exactly `len` bytes from TCP.
 * recv() might return fewer bytes than requested, so we loop.
 */
static int read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        int n = tcp_recv(fd, buf + total, len - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return (int)total;
}

int tls_read_record(tls_session *sess, tls_record *rec)
{
    /*
     * Read the 5-byte record header first:
     *   byte 0:   ContentType
     *   bytes 1-2: Protocol Version (big-endian)
     *   bytes 3-4: Payload Length (big-endian)
     */
    uint8_t header[TLS_RECORD_HEADER_SIZE];
    if (read_exact(sess->fd, header, TLS_RECORD_HEADER_SIZE) < 0) {
        return -1;
    }

    rec->content_type = header[0];
    rec->version = ((uint16_t)header[1] << 8) | header[2];
    rec->length = ((uint16_t)header[3] << 8) | header[4];

    if (rec->length > TLS_MAX_FRAGMENT) {
        fprintf(stderr, "[TLS] Record too large: %u bytes\n", rec->length);
        return -1;
    }

    /* Read the payload */
    if (read_exact(sess->fd, rec->payload, rec->length) < 0) {
        return -1;
    }

    /*
     * If client encryption is active, decrypt the payload.
     *
     * Encrypted record format (CBC mode):
     *   [IV:16] [encrypted(plaintext + MAC + padding)]
     *
     * After decryption:
     *   [plaintext] [HMAC-SHA256:32] [PKCS7 padding]
     */
    if (sess->client_encrypted && rec->content_type == TLS_CONTENT_APPLICATION_DATA) {
        /* This is handled in tls_read() in tls_io.c */
    }

    return 0;
}

int tls_write_record(tls_session *sess, uint8_t content_type,
                     const uint8_t *data, size_t data_len)
{
    uint8_t header[TLS_RECORD_HEADER_SIZE];

    if (!sess->server_encrypted) {
        /*
         * PLAINTEXT record — just wrap and send.
         * Used during the handshake before ChangeCipherSpec.
         */
        header[0] = content_type;
        header[1] = (uint8_t)(TLS_VERSION_1_2 >> 8);
        header[2] = (uint8_t)(TLS_VERSION_1_2 & 0xFF);
        header[3] = (uint8_t)(data_len >> 8);
        header[4] = (uint8_t)(data_len & 0xFF);

        if (tcp_send(sess->fd, header, TLS_RECORD_HEADER_SIZE) < 0) return -1;
        if (data_len > 0 && tcp_send(sess->fd, data, data_len) < 0) return -1;

        return 0;
    }

    /*
     * ENCRYPTED record — compute MAC, add TLS padding, encrypt with AES-CBC.
     *
     * TLS encrypted record payload structure:
     *   [explicit_IV:16] [encrypted( data + MAC + padding )]
     *
     * TLS PADDING (different from PKCS#7!):
     *   TLS padding: all bytes = padding_length, where padding_length
     *   is the number of padding bytes MINUS ONE.
     *   Example: if we need 5 padding bytes → 04 04 04 04 04
     *   (PKCS#7 would use 05 05 05 05 05)
     *
     * The padding includes one byte for the padding_length field itself,
     * so the total padded content = data + MAC + pad is a multiple of 16.
     */

    /* Generate random IV from /dev/urandom */
    uint8_t iv[16];
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand) {
        if (fread(iv, 1, 16, urand) != 16) {
            /* Fallback to less random source */
            for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(rand() & 0xFF);
        }
        fclose(urand);
    } else {
        srand((unsigned)time(NULL) ^ (unsigned)sess->server_seq);
        for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(rand() & 0xFF);
    }

    /* Compute MAC: HMAC-SHA256(mac_key, seq_num || type || version || length || data) */
    size_t mac_input_len = 8 + 1 + 2 + 2 + data_len;
    uint8_t *mac_input = malloc(mac_input_len);
    if (!mac_input) return -1;

    size_t pos = 0;
    for (int i = 7; i >= 0; i--) {
        mac_input[pos++] = (uint8_t)(sess->server_seq >> (i * 8));
    }
    mac_input[pos++] = content_type;
    mac_input[pos++] = (uint8_t)(TLS_VERSION_1_2 >> 8);
    mac_input[pos++] = (uint8_t)(TLS_VERSION_1_2 & 0xFF);
    mac_input[pos++] = (uint8_t)(data_len >> 8);
    mac_input[pos++] = (uint8_t)(data_len & 0xFF);
    memcpy(mac_input + pos, data, data_len);

    uint8_t mac[32];
    hmac_sha256(sess->server_write_mac_key, 32, mac_input, mac_input_len, mac);
    free(mac_input);

    /*
     * Build the plaintext to encrypt: data + MAC + TLS_padding
     *
     * TLS padding: content before padding = data_len + 32 (MAC)
     * We need total to be multiple of 16 (AES block size).
     * padding_length = (16 - ((data_len + 32) % 16)) - 1 ... but need at least 0
     * Actually: padding_length value = number of padding bytes - 1
     * Total padding bytes = padding_length + 1
     * We need: (data_len + 32 + padding_length + 1) % 16 == 0
     */
    size_t content_len = data_len + 32; /* data + MAC */
    uint8_t pad_length = (uint8_t)(16 - 1 - (content_len % 16));
    /* pad_length is the value written, total padding = pad_length + 1 */
    size_t total_pad = (size_t)pad_length + 1;
    size_t pt_len = content_len + total_pad;

    uint8_t *pt = malloc(pt_len);
    if (!pt) return -1;
    memcpy(pt, data, data_len);
    memcpy(pt + data_len, mac, 32);
    memset(pt + content_len, pad_length, total_pad);

    /* Encrypt with raw AES-128-CBC (block by block, no PKCS#7) */
    uint8_t *ct = malloc(pt_len);
    if (!ct) { free(pt); return -1; }

    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t i = 0; i < pt_len; i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = pt[i + j] ^ prev[j];
        }
        aes128_encrypt_block(block, ct + i, sess->server_write_key);
        memcpy(prev, ct + i, 16);
    }
    free(pt);

    /* Send: header + IV + ciphertext */
    size_t total_payload = 16 + pt_len;

    header[0] = content_type;
    header[1] = (uint8_t)(TLS_VERSION_1_2 >> 8);
    header[2] = (uint8_t)(TLS_VERSION_1_2 & 0xFF);
    header[3] = (uint8_t)(total_payload >> 8);
    header[4] = (uint8_t)(total_payload & 0xFF);

    if (tcp_send(sess->fd, header, TLS_RECORD_HEADER_SIZE) < 0) { free(ct); return -1; }
    if (tcp_send(sess->fd, iv, 16) < 0) { free(ct); return -1; }
    if (tcp_send(sess->fd, ct, pt_len) < 0) { free(ct); return -1; }

    free(ct);
    sess->server_seq++;

    return 0;
}

/* ========================================================================== */
/* Session Init / Cleanup                                                      */
/* ========================================================================== */

int tls_load_cert(const char *pem_path, uint8_t *der, size_t der_max, size_t *der_len)
{
    /* Reuse our PEM parser */
    extern int pem_read_file(const char *path, uint8_t *d, size_t dm, size_t *dl);
    return pem_read_file(pem_path, der, der_max, der_len);
}

int tls_session_init(tls_session *sess, int fd,
                     const char *cert_path, const char *key_path)
{
    memset(sess, 0, sizeof(*sess));
    sess->fd = fd;

    /* Load certificate */
    if (tls_load_cert(cert_path, sess->cert_der, sizeof(sess->cert_der),
                      &sess->cert_der_len) < 0) {
        fprintf(stderr, "[TLS] Failed to load certificate\n");
        return -1;
    }
    printf("[TLS] Certificate loaded: %zu bytes DER\n", sess->cert_der_len);

    /* Load private key */
    if (rsa_load_private_key(key_path, &sess->key) < 0) {
        fprintf(stderr, "[TLS] Failed to load private key\n");
        return -1;
    }

    /* Initialize handshake hash */
    sha256_init(&sess->handshake_hash);

    return 0;
}

void tls_session_cleanup(tls_session *sess)
{
    /* Zero out sensitive data */
    memset(sess->pre_master_secret, 0, sizeof(sess->pre_master_secret));
    memset(sess->master_secret, 0, sizeof(sess->master_secret));
    memset(sess->client_write_key, 0, sizeof(sess->client_write_key));
    memset(sess->server_write_key, 0, sizeof(sess->server_write_key));
    memset(sess->client_write_mac_key, 0, sizeof(sess->client_write_mac_key));
    memset(sess->server_write_mac_key, 0, sizeof(sess->server_write_mac_key));
}
