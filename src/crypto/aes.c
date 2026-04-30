/*
 * aes.c — AES-128 Implementation (FIPS 197)
 * ============================================================================
 * AES transforms a 16-byte block through multiple rounds of substitution
 * and permutation. AES-128 uses 10 rounds.
 *
 * Each round applies four operations:
 *   1. SubBytes  — Substitute each byte using a lookup table (S-box)
 *   2. ShiftRows — Rotate rows of the 4x4 state matrix
 *   3. MixColumns — Mix bytes within each column (linear transformation)
 *   4. AddRoundKey — XOR the state with a round key
 *
 * The state is viewed as a 4x4 matrix of bytes:
 *   [ s0  s4  s8  s12 ]
 *   [ s1  s5  s9  s13 ]
 *   [ s2  s6  s10 s14 ]
 *   [ s3  s7  s11 s15 ]
 *
 * NOTE: AES arranges bytes column-by-column, not row-by-row!
 * ============================================================================
 */

#include "aes.h"
#include "fast/fast_crypto.h"
#include <string.h>

/*
 * The S-box (Substitution box).
 *
 * This is the only non-linear operation in AES. Each byte is replaced
 * by looking it up in this 256-entry table.
 *
 * The S-box is derived from the multiplicative inverse in GF(2^8)
 * followed by an affine transformation. This gives it good cryptographic
 * properties — it's resistant to linear and differential cryptanalysis.
 *
 * Example: byte 0x53 → S_BOX[0x53] = 0xED
 */
static const uint8_t S_BOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse S-box for decryption */
static const uint8_t INV_S_BOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/*
 * Round constants for key expansion.
 * Rcon[i] = x^(i-1) in GF(2^8). Used to prevent symmetry in the key schedule.
 */
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/*
 * GF(2^8) multiplication helpers for MixColumns.
 *
 * AES MixColumns uses multiplication in the Galois field GF(2^8) with
 * the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
 *
 * xtime(a) = a * 2 in GF(2^8). If the high bit is set, we subtract
 * the polynomial (XOR with 0x1B). This is the core primitive —
 * multiplication by any constant can be built from xtime and XOR.
 */
static uint8_t xtime(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
}

/* Multiply two bytes in GF(2^8) — used in InvMixColumns */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    uint8_t hi;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

/* ========================================================================== */
/* Key Expansion                                                               */
/* ========================================================================== */

/*
 * Expand the 16-byte key into 11 round keys (176 bytes total).
 *
 * AES-128 needs 11 round keys (1 for initial AddRoundKey + 10 rounds).
 * Each round key is 16 bytes = 4 words of 4 bytes each.
 * Total: 11 * 4 = 44 words.
 *
 * The first 4 words are just the original key. Each subsequent word is
 * derived from the previous word and the word 4 positions back.
 * Every 4th word also goes through the S-box and gets XORed with Rcon.
 */
static void key_expansion(const uint8_t key[16], uint8_t round_keys[176])
{
    /* First round key = the original key */
    memcpy(round_keys, key, 16);

    /* Generate remaining 40 words */
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, &round_keys[(i - 1) * 4], 4);

        if (i % 4 == 0) {
            /* RotWord: rotate left by 1 byte */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            /* SubWord: apply S-box to each byte */
            temp[0] = S_BOX[temp[0]];
            temp[1] = S_BOX[temp[1]];
            temp[2] = S_BOX[temp[2]];
            temp[3] = S_BOX[temp[3]];

            /* XOR with round constant */
            temp[0] ^= RCON[i / 4];
        }

        /* W[i] = W[i-4] XOR temp */
        round_keys[i * 4 + 0] = round_keys[(i - 4) * 4 + 0] ^ temp[0];
        round_keys[i * 4 + 1] = round_keys[(i - 4) * 4 + 1] ^ temp[1];
        round_keys[i * 4 + 2] = round_keys[(i - 4) * 4 + 2] ^ temp[2];
        round_keys[i * 4 + 3] = round_keys[(i - 4) * 4 + 3] ^ temp[3];
    }
}

/* ========================================================================== */
/* AES Round Operations                                                        */
/* ========================================================================== */

/*
 * SubBytes — substitute each byte using the S-box.
 * This is the non-linear step. Without it, AES would just be matrix math.
 */
static void sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] = S_BOX[state[i]];
    }
}

static void inv_sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++) {
        state[i] = INV_S_BOX[state[i]];
    }
}

/*
 * ShiftRows — cyclically shift rows of the state matrix.
 *
 * The state matrix (column-major order in memory):
 *   Row 0: s[0], s[4], s[8],  s[12]  — no shift
 *   Row 1: s[1], s[5], s[9],  s[13]  — shift left by 1
 *   Row 2: s[2], s[6], s[10], s[14]  — shift left by 2
 *   Row 3: s[3], s[7], s[11], s[15]  — shift left by 3
 *
 * This provides DIFFUSION — it spreads bytes across columns so that
 * MixColumns can mix bytes that came from different input positions.
 */
static void shift_rows(uint8_t s[16])
{
    uint8_t t;

    /* Row 1: shift left by 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;

    /* Row 2: shift left by 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;

    /* Row 3: shift left by 3 (= right by 1) */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_shift_rows(uint8_t s[16])
{
    uint8_t t;

    /* Row 1: shift right by 1 */
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;

    /* Row 2: shift right by 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;

    /* Row 3: shift right by 3 (= left by 1) */
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

/*
 * MixColumns — mix bytes within each column.
 *
 * Each column is treated as a polynomial over GF(2^8) and multiplied
 * by a fixed polynomial: {03}x^3 + {01}x^2 + {01}x + {02}
 *
 * In matrix form:
 *   [2 3 1 1] [s0]
 *   [1 2 3 1] [s1]
 *   [1 1 2 3] [s2]
 *   [3 1 1 2] [s3]
 *
 * This provides DIFFUSION within a column — each output byte depends
 * on ALL four input bytes.
 */
static void mix_columns(uint8_t s[16])
{
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = s[c], a1 = s[c+1], a2 = s[c+2], a3 = s[c+3];

        s[c+0] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[c+1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[c+2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[c+3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

static void inv_mix_columns(uint8_t s[16])
{
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = s[c], a1 = s[c+1], a2 = s[c+2], a3 = s[c+3];

        s[c+0] = gf_mul(a0,0x0e) ^ gf_mul(a1,0x0b) ^ gf_mul(a2,0x0d) ^ gf_mul(a3,0x09);
        s[c+1] = gf_mul(a0,0x09) ^ gf_mul(a1,0x0e) ^ gf_mul(a2,0x0b) ^ gf_mul(a3,0x0d);
        s[c+2] = gf_mul(a0,0x0d) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0e) ^ gf_mul(a3,0x0b);
        s[c+3] = gf_mul(a0,0x0b) ^ gf_mul(a1,0x0d) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0e);
    }
}

/*
 * AddRoundKey — XOR the state with a round key.
 * This is where the key actually enters the computation.
 */
static void add_round_key(uint8_t state[16], const uint8_t *round_key)
{
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

/* ========================================================================== */
/* Block Encrypt / Decrypt                                                     */
/* ========================================================================== */

void aes128_encrypt_block(const uint8_t in[16], uint8_t out[16],
                          const uint8_t key[16])
{
    /* === AES-NI FAST PATH === */
    if (crypto_use_aesni()) {
        uint8_t round_keys[176];
        fast_aes128_key_expand(key, round_keys);
        fast_aes128_encrypt_block(in, out, round_keys);
        return;
    }

    /* === C FALLBACK === */
    uint8_t state[16];
    uint8_t round_keys[176];

    key_expansion(key, round_keys);
    memcpy(state, in, 16);

    /*
     * AES-128 encryption: 10 rounds.
     *
     * Round 0 (initial): AddRoundKey only
     * Rounds 1-9: SubBytes → ShiftRows → MixColumns → AddRoundKey
     * Round 10 (final): SubBytes → ShiftRows → AddRoundKey (no MixColumns!)
     *
     * The final round omits MixColumns — this makes encryption and
     * decryption structurally similar (an elegant design property).
     */
    add_round_key(state, round_keys);

    for (int round = 1; round <= 9; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + 160);

    memcpy(out, state, 16);
}

void aes128_decrypt_block(const uint8_t in[16], uint8_t out[16],
                          const uint8_t key[16])
{
    /* === AES-NI FAST PATH === */
    if (crypto_use_aesni()) {
        uint8_t round_keys[176];
        fast_aes128_key_expand(key, round_keys);
        fast_aes128_decrypt_block(in, out, round_keys);
        return;
    }

    /* === C FALLBACK === */
    uint8_t state[16];
    uint8_t round_keys[176];

    key_expansion(key, round_keys);
    memcpy(state, in, 16);

    /* Decryption is encryption in reverse with inverse operations */
    add_round_key(state, round_keys + 160);

    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys + round * 16);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys);

    memcpy(out, state, 16);
}

/* ========================================================================== */
/* CBC Mode                                                                    */
/* ========================================================================== */

void aes128_cbc_encrypt(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len,
                        const uint8_t key[16], const uint8_t iv[16])
{
    /*
     * PKCS#7 padding: pad to next multiple of 16.
     * If already aligned, add a full block of padding.
     * Padding value = number of padding bytes.
     */
    size_t pad_len = AES_BLOCK_SIZE - (in_len % AES_BLOCK_SIZE);
    size_t total_len = in_len + pad_len;

    /* Build padded plaintext */
    uint8_t padded[total_len];
    memcpy(padded, in, in_len);
    memset(padded + in_len, (uint8_t)pad_len, pad_len);

    /*
     * CBC encryption:
     *   C[0] = AES(P[0] XOR IV)
     *   C[i] = AES(P[i] XOR C[i-1])
     *
     * Each plaintext block is XORed with the previous ciphertext block
     * before encryption. This chains the blocks together.
     */
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t i = 0; i < total_len; i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = padded[i + j] ^ prev[j];
        }
        aes128_encrypt_block(block, out + i, key);
        memcpy(prev, out + i, 16);
    }

    *out_len = total_len;
}

int aes128_cbc_decrypt(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len,
                       const uint8_t key[16], const uint8_t iv[16])
{
    if (in_len == 0 || in_len % 16 != 0) return -1;

    /*
     * CBC decryption:
     *   P[0] = AES_DEC(C[0]) XOR IV
     *   P[i] = AES_DEC(C[i]) XOR C[i-1]
     */
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t i = 0; i < in_len; i += 16) {
        uint8_t decrypted[16];
        aes128_decrypt_block(in + i, decrypted, key);
        for (int j = 0; j < 16; j++) {
            out[i + j] = decrypted[j] ^ prev[j];
        }
        memcpy(prev, in + i, 16);
    }

    /* Remove PKCS#7 padding */
    uint8_t pad_val = out[in_len - 1];
    if (pad_val == 0 || pad_val > 16) return -1;

    /* Verify all padding bytes are correct */
    for (size_t i = 0; i < pad_val; i++) {
        if (out[in_len - 1 - i] != pad_val) return -1;
    }

    *out_len = in_len - pad_val;
    return 0;
}
