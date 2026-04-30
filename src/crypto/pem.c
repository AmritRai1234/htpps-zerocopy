/*
 * pem.c — PEM/Base64/ASN.1 Parser Implementation
 * ============================================================================
 */

#include "pem.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================================== */
/* Base64 Decoder                                                              */
/* ========================================================================== */

/*
 * Base64 encoding table: maps ASCII chars back to 6-bit values.
 *
 * Base64 represents binary data using 64 printable ASCII characters:
 *   A-Z = 0-25, a-z = 26-51, 0-9 = 52-61, + = 62, / = 63
 *
 * Every 3 bytes of binary data → 4 base64 characters.
 * 3 bytes = 24 bits = four 6-bit groups, each mapped to one base64 char.
 *
 * Padding: '=' at the end means the last group had fewer than 3 bytes.
 */
static const int B64_TABLE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63, /* +, / */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1, /* 0-9, = */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, /* A-O */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, /* P-Z */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, /* a-o */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1, /* p-z */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max)
{
    size_t out_pos = 0;
    int buf = 0, bits = 0;

    for (size_t i = 0; i < in_len; i++) {
        int val = B64_TABLE[(unsigned char)in[i]];
        if (val == -2) break;   /* '=' padding — we're done */
        if (val == -1) continue; /* Skip whitespace/newlines */

        buf = (buf << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (out_pos >= out_max) return -1;
            out[out_pos++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }

    return (int)out_pos;
}

/* ========================================================================== */
/* PEM File Reader                                                             */
/* ========================================================================== */

int pem_read_file(const char *path, uint8_t *der, size_t der_max, size_t *der_len)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("pem_read_file: fopen");
        return -1;
    }

    /* Read entire file */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *pem_data = malloc((size_t)file_size + 1);
    if (!pem_data) { fclose(fp); return -1; }

    size_t read = fread(pem_data, 1, (size_t)file_size, fp);
    pem_data[read] = '\0';
    fclose(fp);

    /*
     * Find the base64 content between -----BEGIN...---- and -----END...----
     * Skip the header and footer lines.
     */
    char *start = strstr(pem_data, "-----BEGIN");
    if (!start) { free(pem_data); return -1; }

    /* Skip to end of BEGIN line */
    start = strchr(start, '\n');
    if (!start) { free(pem_data); return -1; }
    start++;

    char *end = strstr(start, "-----END");
    if (!end) { free(pem_data); return -1; }

    size_t b64_len = (size_t)(end - start);

    /* Decode the base64 content */
    int decoded_len = base64_decode(start, b64_len, der, der_max);
    free(pem_data);

    if (decoded_len < 0) return -1;
    *der_len = (size_t)decoded_len;
    return 0;
}

/* ========================================================================== */
/* Minimal ASN.1/DER Parser                                                    */
/* ========================================================================== */

/*
 * Read ASN.1 length field.
 *
 * ASN.1 lengths can be:
 *   - Short form (1 byte):  if high bit is 0, the byte IS the length (0-127)
 *   - Long form (2+ bytes): high bit is 1, low 7 bits = number of length bytes
 *     then that many bytes follow containing the actual length
 *
 * Example: length 200
 *   Can't use short form (>127), so: 0x81, 0xC8
 *   0x81 = 1000_0001 → long form, 1 byte of length follows
 *   0xC8 = 200
 */
static int asn1_read_length(const uint8_t **p, size_t *remaining, size_t *length)
{
    if (*remaining < 1) return -1;

    uint8_t first = **p;
    (*p)++;
    (*remaining)--;

    if (!(first & 0x80)) {
        /* Short form */
        *length = first;
    } else {
        /* Long form */
        int num_bytes = first & 0x7F;
        if (num_bytes > 4 || (size_t)num_bytes > *remaining) return -1;

        *length = 0;
        for (int i = 0; i < num_bytes; i++) {
            *length = (*length << 8) | **p;
            (*p)++;
            (*remaining)--;
        }
    }

    return 0;
}

int asn1_read_sequence(const uint8_t **der, size_t *der_len, size_t *content_len)
{
    if (*der_len < 1 || **der != 0x30) return -1; /* 0x30 = SEQUENCE tag */
    (*der)++;
    (*der_len)--;
    return asn1_read_length(der, der_len, content_len);
}

int asn1_read_integer(const uint8_t **der, size_t *der_len,
                      uint8_t *out, size_t out_max, size_t *out_len)
{
    if (*der_len < 1 || **der != 0x02) return -1; /* 0x02 = INTEGER tag */
    (*der)++;
    (*der_len)--;

    size_t int_len;
    if (asn1_read_length(der, der_len, &int_len) < 0) return -1;
    if (int_len > *der_len) return -1;

    /* Save original length for advancing the pointer later */
    size_t orig_int_len = int_len;

    /* Skip leading zero byte (ASN.1 uses it for positive numbers with high bit set) */
    const uint8_t *int_data = *der;
    if (int_len > 0 && int_data[0] == 0x00) {
        int_data++;
        int_len--;
    }

    if (int_len > out_max) return -1;

    memcpy(out, int_data, int_len);
    *out_len = int_len;

    /* Advance past the full original integer value (including any leading zero) */
    *der += orig_int_len;
    *der_len -= orig_int_len;

    return 0;
}

int asn1_skip(const uint8_t **der, size_t *der_len)
{
    if (*der_len < 1) return -1;
    (*der)++; /* skip tag */
    (*der_len)--;

    size_t elem_len;
    if (asn1_read_length(der, der_len, &elem_len) < 0) return -1;
    if (elem_len > *der_len) return -1;

    *der += elem_len;
    *der_len -= elem_len;
    return 0;
}
