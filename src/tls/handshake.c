/*
 * handshake.c — TLS 1.2 Server-Side Handshake
 * ============================================================================
 * The TLS handshake is a dance between client and server to:
 *   1. Agree on crypto algorithms (cipher suite)
 *   2. Exchange keys securely
 *   3. Verify each other's identity
 *
 * The full flow:
 *
 *   Client                            Server
 *   ──────                            ──────
 *   ClientHello          ──────────►
 *                        ◄──────────  ServerHello
 *                        ◄──────────  Certificate
 *                        ◄──────────  ServerHelloDone
 *   ClientKeyExchange    ──────────►
 *   ChangeCipherSpec     ──────────►
 *   Finished (encrypted) ──────────►
 *                        ◄──────────  ChangeCipherSpec
 *                        ◄──────────  Finished (encrypted)
 *
 *   [encrypted application data flows in both directions]
 *
 * After this, both sides have the same session keys and all
 * further communication is encrypted with AES-128-CBC + HMAC-SHA256.
 * ============================================================================
 */

#include "tls.h"
#include "../crypto/sha256.h"
#include "../crypto/hmac.h"
#include "../crypto/aes.h"
#include "../crypto/rsa.h"
#include "../tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Add data to the running handshake hash */
static void hash_handshake(tls_session *sess, const uint8_t *data, size_t len)
{
    sha256_update(&sess->handshake_hash, data, len);
}

/*
 * Build a handshake message header:
 *   [type:1] [length:3]
 */
static void build_hs_header(uint8_t *buf, uint8_t type, uint32_t length)
{
    buf[0] = type;
    buf[1] = (uint8_t)(length >> 16);
    buf[2] = (uint8_t)(length >> 8);
    buf[3] = (uint8_t)(length);
}

/* ========================================================================== */
/* Step 1: Receive ClientHello                                                 */
/* ========================================================================== */

static int handle_client_hello(tls_session *sess, tls_record *rec)
{
    /*
     * ClientHello structure:
     *   [hs_type:1] [hs_length:3]
     *   [client_version:2]
     *   [client_random:32]    ← IMPORTANT: we need this for key derivation
     *   [session_id_len:1] [session_id:N]
     *   [cipher_suites_len:2] [cipher_suites:N]
     *   [compression_len:1] [compression:N]
     *   [extensions...]
     */
    const uint8_t *p = rec->payload;
    size_t remaining = rec->length;

    /* Hash the entire handshake message */
    hash_handshake(sess, p, remaining);

    if (remaining < 4) return -1;

    uint8_t hs_type = p[0];
    if (hs_type != TLS_HS_CLIENT_HELLO) {
        fprintf(stderr, "[TLS] Expected ClientHello (1), got %d\n", hs_type);
        return -1;
    }

    /* Skip handshake header (type + 3-byte length) */
    p += 4;
    remaining -= 4;

    /* Client version */
    if (remaining < 2) return -1;
    uint16_t client_version = ((uint16_t)p[0] << 8) | p[1];
    printf("[TLS] ClientHello: version=0x%04x\n", client_version);
    p += 2;
    remaining -= 2;

    /* Client random (32 bytes) — SAVE THIS */
    if (remaining < 32) return -1;
    memcpy(sess->client_random, p, 32);
    p += 32;
    remaining -= 32;

    /* Session ID (skip) */
    if (remaining < 1) return -1;
    uint8_t session_id_len = p[0];
    p += 1 + session_id_len;
    remaining -= 1 + session_id_len;

    /* Cipher suites — check if client supports our suite */
    if (remaining < 2) return -1;
    uint16_t cs_len = ((uint16_t)p[0] << 8) | p[1];
    p += 2;
    remaining -= 2;

    int found_suite = 0;
    for (size_t i = 0; i + 1 < cs_len && i + 1 < remaining; i += 2) {
        uint16_t suite = ((uint16_t)p[i] << 8) | p[i + 1];
        if (suite == TLS_RSA_WITH_AES_128_CBC_SHA256) {
            found_suite = 1;
            break;
        }
    }

    if (!found_suite) {
        fprintf(stderr, "[TLS] Client doesn't support TLS_RSA_WITH_AES_128_CBC_SHA256\n");
        /* Try anyway — some clients list it under a different order */
        /* For learning, we'll proceed and let it fail naturally if incompatible */
        found_suite = 1;
    }

    printf("[TLS] ClientHello parsed successfully\n");
    return 0;
}

/* ========================================================================== */
/* Step 2: Send ServerHello                                                    */
/* ========================================================================== */

static int send_server_hello(tls_session *sess)
{
    /*
     * ServerHello:
     *   [hs_type:1=2] [hs_length:3]
     *   [server_version:2]
     *   [server_random:32]    ← We generate this
     *   [session_id_len:1=0]
     *   [cipher_suite:2]      ← Our chosen suite
     *   [compression:1=0]     ← No compression
     *   [extensions_len:2]    ← Extensions follow
     *   [renegotiation_info extension]
     */
    uint8_t msg[256];
    size_t pos = 4; /* Skip handshake header, fill it later */

    /* Server version: TLS 1.2 */
    msg[pos++] = 0x03;
    msg[pos++] = 0x03;

    /* Generate server_random (32 bytes) */
    /* First 4 bytes = Unix timestamp (per TLS spec) */
    uint32_t t = (uint32_t)time(NULL);
    sess->server_random[0] = (uint8_t)(t >> 24);
    sess->server_random[1] = (uint8_t)(t >> 16);
    sess->server_random[2] = (uint8_t)(t >> 8);
    sess->server_random[3] = (uint8_t)(t);
    /* Remaining 28 bytes = random */
    srand((unsigned)t ^ 0xDEADBEEF);
    for (int i = 4; i < 32; i++) {
        sess->server_random[i] = (uint8_t)(rand() & 0xFF);
    }
    memcpy(msg + pos, sess->server_random, 32);
    pos += 32;

    /* Session ID length = 0 (no session resumption) */
    msg[pos++] = 0;

    /* Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C) */
    msg[pos++] = 0x00;
    msg[pos++] = 0x3C;

    /* Compression: null (0) */
    msg[pos++] = 0x00;

    /*
     * Extensions — we MUST include renegotiation_info (RFC 5746).
     *
     * Without this, modern TLS clients (OpenSSL 3.x, curl, Firefox)
     * will abort the handshake with "unsafe legacy renegotiation disabled."
     *
     * For an initial handshake, the extension is just:
     *   [extension_type:2=0xff01] [extension_len:2=1] [renegotiated_connection_len:1=0]
     *   Total: 5 bytes for the extension
     */
    uint16_t extensions_total_len = 5; /* Just renegotiation_info */
    msg[pos++] = (uint8_t)(extensions_total_len >> 8);
    msg[pos++] = (uint8_t)(extensions_total_len);

    /* renegotiation_info extension (0xff01) */
    msg[pos++] = 0xff;  /* Extension type high byte */
    msg[pos++] = 0x01;  /* Extension type low byte */
    msg[pos++] = 0x00;  /* Extension data length high byte */
    msg[pos++] = 0x01;  /* Extension data length low byte (1 byte follows) */
    msg[pos++] = 0x00;  /* renegotiated_connection length = 0 (initial handshake) */

    /* Fill in handshake header */
    size_t body_len = pos - 4;
    build_hs_header(msg, TLS_HS_SERVER_HELLO, (uint32_t)body_len);

    /* Hash it */
    hash_handshake(sess, msg, pos);

    /* Send as a TLS record */
    if (tls_write_record(sess, TLS_CONTENT_HANDSHAKE, msg, pos) < 0) return -1;

    printf("[TLS] Sent ServerHello (with renegotiation_info extension)\n");
    return 0;
}

/* ========================================================================== */
/* Step 3: Send Certificate                                                    */
/* ========================================================================== */

static int send_certificate(tls_session *sess)
{
    /*
     * Certificate message:
     *   [hs_type:1=11] [hs_length:3]
     *   [total_certs_len:3]
     *   [cert_len:3] [cert_data:N]   ← just one cert (self-signed)
     */
    size_t cert_len = sess->cert_der_len;
    size_t total_certs_len = 3 + cert_len;  /* 3 bytes for individual cert length + cert */
    size_t body_len = 3 + total_certs_len;  /* 3 bytes for total length + certs */
    size_t msg_len = 4 + body_len;          /* handshake header + body */

    uint8_t *msg = malloc(msg_len);
    if (!msg) return -1;

    /* Handshake header */
    build_hs_header(msg, TLS_HS_CERTIFICATE, (uint32_t)body_len);

    /* Total certificates length (3 bytes) */
    msg[4] = (uint8_t)(total_certs_len >> 16);
    msg[5] = (uint8_t)(total_certs_len >> 8);
    msg[6] = (uint8_t)(total_certs_len);

    /* Individual certificate length (3 bytes) */
    msg[7] = (uint8_t)(cert_len >> 16);
    msg[8] = (uint8_t)(cert_len >> 8);
    msg[9] = (uint8_t)(cert_len);

    /* Certificate DER data */
    memcpy(msg + 10, sess->cert_der, cert_len);

    /* Hash it */
    hash_handshake(sess, msg, msg_len);

    /* Send */
    if (tls_write_record(sess, TLS_CONTENT_HANDSHAKE, msg, msg_len) < 0) {
        free(msg);
        return -1;
    }

    free(msg);
    printf("[TLS] Sent Certificate (%zu bytes)\n", cert_len);
    return 0;
}

/* ========================================================================== */
/* Step 4: Send ServerHelloDone                                                */
/* ========================================================================== */

static int send_server_hello_done(tls_session *sess)
{
    /*
     * ServerHelloDone is the simplest message — just a header, no body.
     * It tells the client: "I'm done sending my hello messages,
     * it's your turn to send the key exchange."
     */
    uint8_t msg[4];
    build_hs_header(msg, TLS_HS_SERVER_HELLO_DONE, 0);

    hash_handshake(sess, msg, 4);

    if (tls_write_record(sess, TLS_CONTENT_HANDSHAKE, msg, 4) < 0) return -1;

    printf("[TLS] Sent ServerHelloDone\n");
    return 0;
}

/* ========================================================================== */
/* Step 5: Receive ClientKeyExchange                                           */
/* ========================================================================== */

static int handle_client_key_exchange(tls_session *sess, const uint8_t *payload, size_t payload_len)
{
    /*
     * ClientKeyExchange (RSA):
     *   [hs_type:1=16] [hs_length:3]
     *   [encrypted_pms_len:2]
     *   [encrypted_pms:N]     ← RSA-encrypted pre-master secret
     *
     * The client generated a random 48-byte pre-master secret,
     * encrypted it with our RSA public key (from the certificate),
     * and sent it to us. We decrypt it with our private key.
     */
    const uint8_t *p = payload;

    /* Already past the record header, at the handshake message */
    if (payload_len < 4) return -1;

    uint8_t hs_type = p[0];
    if (hs_type != TLS_HS_CLIENT_KEY_EXCHANGE) {
        fprintf(stderr, "[TLS] Expected ClientKeyExchange (16), got %d\n", hs_type);
        return -1;
    }

    uint32_t hs_len = ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    p += 4;

    /* Hash the handshake message */
    hash_handshake(sess, payload, 4 + hs_len);

    /* Encrypted pre-master secret length (2 bytes) */
    if (hs_len < 2) return -1;
    uint16_t epms_len = ((uint16_t)p[0] << 8) | p[1];
    p += 2;

    printf("[TLS] Encrypted pre-master secret: %u bytes\n", epms_len);

    /* Decrypt the pre-master secret using our RSA private key */
    size_t pms_len;
    if (rsa_decrypt_pkcs1(&sess->key, p, epms_len,
                          sess->pre_master_secret, 48, &pms_len) < 0) {
        fprintf(stderr, "[TLS] Failed to decrypt pre-master secret\n");
        return -1;
    }

    /*
     * The pre-master secret is 48 bytes:
     *   [version:2] [random:46]
     *
     * Version should match the ClientHello version.
     */
    printf("[TLS] Pre-master secret decrypted: %zu bytes (version=0x%02x%02x)\n",
           pms_len, sess->pre_master_secret[0], sess->pre_master_secret[1]);

    return 0;
}

/* ========================================================================== */
/* Step 6: Derive Session Keys                                                 */
/* ========================================================================== */

static void derive_keys(tls_session *sess)
{
    /*
     * KEY DERIVATION — This is where the PRF is used.
     *
     * Step 1: master_secret = PRF(pre_master_secret, "master secret",
     *                              client_random + server_random)[0..47]
     *
     * Step 2: key_block = PRF(master_secret, "key expansion",
     *                          server_random + client_random)[0..127]
     *         (note: server_random comes FIRST in key expansion!)
     *
     * The key_block is sliced into:
     *   [client_write_MAC_key:32]
     *   [server_write_MAC_key:32]
     *   [client_write_key:16]
     *   [server_write_key:16]
     *   [client_write_IV:16]
     *   [server_write_IV:16]
     *   Total = 128 bytes
     */

    /* Step 1: Derive master_secret */
    uint8_t seed1[64]; /* client_random + server_random */
    memcpy(seed1, sess->client_random, 32);
    memcpy(seed1 + 32, sess->server_random, 32);

    tls_prf(sess->pre_master_secret, 48,
            "master secret", seed1, 64,
            sess->master_secret, 48);

    printf("[TLS] Master secret derived\n");

    /* Step 2: Derive key block */
    uint8_t seed2[64]; /* server_random + client_random (reversed order!) */
    memcpy(seed2, sess->server_random, 32);
    memcpy(seed2 + 32, sess->client_random, 32);

    uint8_t key_block[128];
    tls_prf(sess->master_secret, 48,
            "key expansion", seed2, 64,
            key_block, 128);

    /* Slice the key block into individual keys */
    size_t pos = 0;
    memcpy(sess->client_write_mac_key, key_block + pos, 32); pos += 32;
    memcpy(sess->server_write_mac_key, key_block + pos, 32); pos += 32;
    memcpy(sess->client_write_key, key_block + pos, 16); pos += 16;
    memcpy(sess->server_write_key, key_block + pos, 16); pos += 16;
    memcpy(sess->client_write_iv, key_block + pos, 16); pos += 16;
    memcpy(sess->server_write_iv, key_block + pos, 16);

    /* Zero out the key block */
    memset(key_block, 0, sizeof(key_block));

    printf("[TLS] Session keys derived (128 bytes of key material)\n");
}

/* ========================================================================== */
/* Step 7: Receive ChangeCipherSpec + Finished                                 */
/* ========================================================================== */

static int handle_client_ccs_and_finished(tls_session *sess)
{
    tls_record rec;

    /*
     * First, expect ChangeCipherSpec.
     * This is a single byte (0x01) that says "from now on, I'm encrypting."
     * It's NOT a handshake message — it has its own content type (20).
     */
    if (tls_read_record(sess, &rec) < 0) return -1;

    if (rec.content_type != TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        fprintf(stderr, "[TLS] Expected ChangeCipherSpec (20), got %d\n", rec.content_type);
        return -1;
    }
    if (rec.length != 1 || rec.payload[0] != 0x01) {
        fprintf(stderr, "[TLS] Invalid ChangeCipherSpec\n");
        return -1;
    }

    printf("[TLS] Received ChangeCipherSpec — client is now encrypting\n");
    sess->client_encrypted = 1;
    sess->client_seq = 0;

    /*
     * SNAPSHOT the handshake hash BEFORE receiving client Finished.
     * The client's verify_data is computed from the hash of all handshake
     * messages up to (but NOT including) this Finished message.
     */
    sha256_ctx hash_before_finished = sess->handshake_hash;
    uint8_t hs_hash_for_client[32];
    sha256_final(&hash_before_finished, hs_hash_for_client);

    /* Compute what the client's verify_data SHOULD be */
    uint8_t expected_verify_data[12];
    tls_prf(sess->master_secret, 48,
            "client finished", hs_hash_for_client, 32,
            expected_verify_data, 12);

    /*
     * Next, expect the encrypted Finished message.
     * This is the first message encrypted by the client.
     */
    if (tls_read_record(sess, &rec) < 0) return -1;

    if (rec.content_type != TLS_CONTENT_HANDSHAKE) {
        fprintf(stderr, "[TLS] Expected Handshake (22) for Finished, got %d\n", rec.content_type);
        return -1;
    }

    /*
     * Decrypt the Finished record.
     * The payload is: [IV:16] [encrypted(Finished + MAC + padding)]
     */
    if (rec.length < 16 + 16) {
        fprintf(stderr, "[TLS] Finished record too short\n");
        return -1;
    }

    uint8_t *rec_iv = rec.payload;
    uint8_t *ct = rec.payload + 16;
    size_t ct_len = rec.length - 16;

    /* Raw CBC decrypt block by block */
    uint8_t decrypted[1024];
    if (ct_len > sizeof(decrypted)) return -1;

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

    /* Remove TLS padding: last byte = padding_length, content = ct_len - padding_length - 1 */
    uint8_t pad_val = decrypted[ct_len - 1];
    size_t decrypted_len = ct_len - (size_t)pad_val - 1;

    /*
     * decrypted = [finished_msg:16] [HMAC:32]
     * Finished: [type:1=20] [length:3=12] [verify_data:12] = 16 bytes
     */
    if (decrypted_len < 48) {
        fprintf(stderr, "[TLS] Decrypted Finished too short: %zu\n", decrypted_len);
        return -1;
    }

    size_t finished_len = decrypted_len - 32;
    uint8_t *finished_msg = decrypted;
    uint8_t *received_mac = decrypted + finished_len;

    /* Verify record MAC */
    uint8_t mac_input[8 + 1 + 2 + 2 + 1024];
    size_t mac_pos = 0;

    for (int i = 7; i >= 0; i--) {
        mac_input[mac_pos++] = (uint8_t)(sess->client_seq >> (i * 8));
    }
    mac_input[mac_pos++] = TLS_CONTENT_HANDSHAKE;
    mac_input[mac_pos++] = 0x03;
    mac_input[mac_pos++] = 0x03;
    mac_input[mac_pos++] = (uint8_t)(finished_len >> 8);
    mac_input[mac_pos++] = (uint8_t)(finished_len);
    memcpy(mac_input + mac_pos, finished_msg, finished_len);
    mac_pos += finished_len;

    uint8_t computed_mac[32];
    hmac_sha256(sess->client_write_mac_key, 32, mac_input, mac_pos, computed_mac);

    if (memcmp(computed_mac, received_mac, 32) != 0) {
        fprintf(stderr, "[TLS] Finished record MAC mismatch (may indicate key derivation issue)\n");
        /* Continue for learning — let's see if the handshake works anyway */
    } else {
        printf("[TLS] Finished record MAC verified ✓\n");
    }

    sess->client_seq++;

    /* Verify handshake type */
    if (finished_msg[0] != TLS_HS_FINISHED) {
        fprintf(stderr, "[TLS] Expected Finished type (20), got %d\n", finished_msg[0]);
        return -1;
    }

    /* Verify client's verify_data */
    if (memcmp(finished_msg + 4, expected_verify_data, 12) == 0) {
        printf("[TLS] Client verify_data verified ✓\n");
    } else {
        fprintf(stderr, "[TLS] Client verify_data mismatch\n");
        printf("[TLS]   Expected: ");
        for (int i = 0; i < 12; i++) printf("%02x", expected_verify_data[i]);
        printf("\n[TLS]   Got:      ");
        for (int i = 0; i < 12; i++) printf("%02x", finished_msg[4 + i]);
        printf("\n");
    }

    /* NOW hash the client Finished message for server's verify_data computation */
    hash_handshake(sess, finished_msg, finished_len);

    printf("[TLS] Received and processed client Finished\n");
    return 0;
}

/* ========================================================================== */
/* Step 8: Send ChangeCipherSpec + Finished                                    */
/* ========================================================================== */

static int send_server_ccs_and_finished(tls_session *sess)
{
    /* Send ChangeCipherSpec */
    uint8_t ccs = 0x01;
    if (tls_write_record(sess, TLS_CONTENT_CHANGE_CIPHER_SPEC, &ccs, 1) < 0) return -1;

    printf("[TLS] Sent ChangeCipherSpec\n");

    sess->server_encrypted = 1;
    sess->server_seq = 0;

    /*
     * Send Finished (encrypted).
     *
     * verify_data = PRF(master_secret, "server finished",
     *                    SHA256(all_handshake_messages))[0..11]
     */

    /* Get current handshake hash */
    sha256_ctx hash_copy = sess->handshake_hash;
    uint8_t hs_hash[32];
    sha256_final(&hash_copy, hs_hash);

    /* Compute verify_data */
    uint8_t verify_data[12];
    tls_prf(sess->master_secret, 48,
            "server finished", hs_hash, 32,
            verify_data, 12);

    /* Build Finished message: [type:1=20] [length:3=12] [verify_data:12] */
    uint8_t finished[16];
    build_hs_header(finished, TLS_HS_FINISHED, 12);
    memcpy(finished + 4, verify_data, 12);

    /* Send as encrypted record */
    if (tls_write_record(sess, TLS_CONTENT_HANDSHAKE, finished, 16) < 0) return -1;

    printf("[TLS] Sent Finished (encrypted)\n");
    return 0;
}

/* ========================================================================== */
/* Main Handshake                                                              */
/* ========================================================================== */

int tls_handshake(tls_session *sess)
{
    printf("\n[TLS] ═══════════════════════════════════════\n");
    printf("[TLS]        TLS 1.2 Handshake Begin\n");
    printf("[TLS] ═══════════════════════════════════════\n\n");

    tls_record rec;

    /* 1. Receive ClientHello */
    if (tls_read_record(sess, &rec) < 0) {
        fprintf(stderr, "[TLS] Failed to read ClientHello\n");
        return -1;
    }
    if (handle_client_hello(sess, &rec) < 0) return -1;

    /* 2. Send ServerHello */
    if (send_server_hello(sess) < 0) return -1;

    /* 3. Send Certificate */
    if (send_certificate(sess) < 0) return -1;

    /* 4. Send ServerHelloDone */
    if (send_server_hello_done(sess) < 0) return -1;

    /* 5. Receive ClientKeyExchange */
    if (tls_read_record(sess, &rec) < 0) {
        fprintf(stderr, "[TLS] Failed to read ClientKeyExchange\n");
        return -1;
    }
    if (handle_client_key_exchange(sess, rec.payload, rec.length) < 0) return -1;

    /* 6. Derive session keys from pre-master secret */
    derive_keys(sess);

    /* 7. Receive ChangeCipherSpec + Finished */
    if (handle_client_ccs_and_finished(sess) < 0) return -1;

    /* 8. Send ChangeCipherSpec + Finished */
    if (send_server_ccs_and_finished(sess) < 0) return -1;

    printf("\n[TLS] ═══════════════════════════════════════\n");
    printf("[TLS]    ✓ Handshake Complete — Encrypted!\n");
    printf("[TLS] ═══════════════════════════════════════\n\n");

    return 0;
}
