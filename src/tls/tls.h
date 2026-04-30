/*
 * tls.h — TLS 1.2 Types, Constants & Session State
 * ============================================================================
 * TLS (Transport Layer Security) wraps TCP to provide:
 *   1. CONFIDENTIALITY — data is encrypted (AES)
 *   2. INTEGRITY — data can't be modified (HMAC)
 *   3. AUTHENTICATION — server proves its identity (RSA + certificates)
 *
 * The TLS protocol has TWO main parts:
 *   1. HANDSHAKE — negotiate algorithms, exchange keys, verify identity
 *   2. RECORD LAYER — wrap all data in encrypted records
 *
 * Every TLS message is wrapped in a "record":
 *   [ContentType:1] [Version:2] [Length:2] [Payload:Length]
 *
 * Content types:
 *   20 = ChangeCipherSpec (switch to encryption)
 *   21 = Alert (errors)
 *   22 = Handshake (key exchange)
 *   23 = ApplicationData (actual HTTP after handshake)
 * ============================================================================
 */

#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/rsa.h"
#include "../crypto/sha256.h"

/* ========================================================================== */
/* TLS Constants                                                               */
/* ========================================================================== */

/* Protocol versions */
#define TLS_VERSION_1_0  0x0301
#define TLS_VERSION_1_2  0x0303

/* Content types (the first byte of every TLS record) */
#define TLS_CONTENT_CHANGE_CIPHER_SPEC  20
#define TLS_CONTENT_ALERT               21
#define TLS_CONTENT_HANDSHAKE           22
#define TLS_CONTENT_APPLICATION_DATA    23

/* Handshake message types */
#define TLS_HS_CLIENT_HELLO        1
#define TLS_HS_SERVER_HELLO        2
#define TLS_HS_CERTIFICATE         11
#define TLS_HS_SERVER_HELLO_DONE   14
#define TLS_HS_CLIENT_KEY_EXCHANGE 16
#define TLS_HS_FINISHED            20

/*
 * Our cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256
 *
 * This means:
 *   RSA         — key exchange (client encrypts pre-master secret with our public key)
 *   AES_128_CBC — symmetric encryption (128-bit AES in CBC mode)
 *   SHA256      — MAC algorithm (HMAC-SHA256 for message authentication)
 *
 * Suite ID: 0x003C
 */
#define TLS_RSA_WITH_AES_128_CBC_SHA256  0x003C

/* Maximum sizes */
#define TLS_MAX_RECORD_SIZE   16384   /* Max plaintext in one record: 2^14 */
#define TLS_RECORD_HEADER_SIZE 5      /* ContentType + Version + Length */
#define TLS_MAX_FRAGMENT       (TLS_MAX_RECORD_SIZE + 2048) /* With overhead */

/* ========================================================================== */
/* TLS Record                                                                  */
/* ========================================================================== */

typedef struct {
    uint8_t  content_type;       /* 20, 21, 22, or 23 */
    uint16_t version;            /* 0x0303 for TLS 1.2 */
    uint16_t length;             /* Payload length */
    uint8_t  payload[TLS_MAX_FRAGMENT];
} tls_record;

/* ========================================================================== */
/* TLS Session State                                                           */
/* ========================================================================== */

/*
 * This struct holds everything needed for an active TLS session.
 *
 * During the handshake, we fill in the randoms, pre-master secret, and
 * derive the session keys. After the handshake, we use the keys for
 * encrypting/decrypting application data.
 */
typedef struct {
    int fd;                       /* Underlying TCP socket */

    /* Handshake state */
    uint8_t client_random[32];    /* 32 bytes of randomness from client */
    uint8_t server_random[32];    /* 32 bytes of randomness from server */
    uint8_t pre_master_secret[48]; /* 48-byte pre-master secret */
    uint8_t master_secret[48];    /* 48-byte master secret (derived) */

    /*
     * Session keys — derived from master_secret.
     *
     * TLS derives a "key block" and slices it into:
     *   - client_write_MAC_key (32 bytes for SHA-256)
     *   - server_write_MAC_key (32 bytes for SHA-256)
     *   - client_write_key (16 bytes for AES-128)
     *   - server_write_key (16 bytes for AES-128)
     *   - client_write_IV (16 bytes for AES-CBC)
     *   - server_write_IV (16 bytes for AES-CBC)
     */
    uint8_t client_write_mac_key[32];
    uint8_t server_write_mac_key[32];
    uint8_t client_write_key[16];
    uint8_t server_write_key[16];
    uint8_t client_write_iv[16];
    uint8_t server_write_iv[16];

    /* Sequence numbers (for MAC computation) */
    uint64_t client_seq;          /* Client → server message counter */
    uint64_t server_seq;          /* Server → client message counter */

    /* Are we encrypting yet? */
    int client_encrypted;         /* Client has sent ChangeCipherSpec */
    int server_encrypted;         /* We have sent ChangeCipherSpec */

    /* Handshake hash — SHA-256 of all handshake messages */
    sha256_ctx handshake_hash;

    /* Certificate DER bytes (to send in Certificate message) */
    uint8_t  cert_der[4096];
    size_t   cert_der_len;

    /* RSA private key */
    rsa_key  key;
} tls_session;

/* ========================================================================== */
/* TLS Functions                                                               */
/* ========================================================================== */

/* Record layer */
int tls_read_record(tls_session *sess, tls_record *rec);
int tls_write_record(tls_session *sess, uint8_t content_type,
                     const uint8_t *data, size_t data_len);

/* Handshake */
int tls_handshake(tls_session *sess);

/* PRF (Pseudo-Random Function) */
void tls_prf(const uint8_t *secret, size_t secret_len,
             const char *label,
             const uint8_t *seed, size_t seed_len,
             uint8_t *output, size_t output_len);

/* Encrypted I/O (after handshake) */
int tls_read(tls_session *sess, uint8_t *buf, size_t buf_len);
int tls_write(tls_session *sess, const uint8_t *buf, size_t buf_len);

/* Session init/cleanup */
int tls_session_init(tls_session *sess, int fd,
                     const char *cert_path, const char *key_path);
void tls_session_cleanup(tls_session *sess);

/* Load certificate DER from PEM */
int tls_load_cert(const char *pem_path, uint8_t *der, size_t der_max, size_t *der_len);

#endif /* TLS_H */
