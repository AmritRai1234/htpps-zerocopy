# ============================================================================
# HTPPS Server — Makefile
# ============================================================================
# Build:  make
# Run:    ./server --https          (HTTPS on port 4443)
#         ./server --http           (HTTP on port 8080)
# Test:   make test                 (run crypto test suite)
# ============================================================================

CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -g -O2 -Isrc -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS = -lm

# Server source files
SRCS = src/main.c \
       src/tcp.c \
       src/http.c \
       src/router.c \
       src/crypto/sha256.c \
       src/crypto/hmac.c \
       src/crypto/aes.c \
       src/crypto/bignum.c \
       src/crypto/pem.c \
       src/crypto/rsa.c \
       src/crypto/fast/fast_crypto.c \
       src/tls/record.c \
       src/tls/prf.c \
       src/tls/handshake.c \
       src/tls/tls_io.c \
       jsengine/jsengine.c \
       jsengine/src/core/lexer.c \
       jsengine/src/core/parser.c \
       jsengine/src/core/value.c \
       jsengine/src/core/eval.c \
       jsengine/src/jit/jit.c

# Assembly sources
ASM_SRCS = jsengine/src/fast/math_ops.asm \
           src/crypto/fast/cpuid.asm \
           src/crypto/fast/crypto_ops.asm \
           src/fast/fast_io.asm
ASM_OBJS = $(ASM_SRCS:.asm=.o)

OBJS = $(SRCS:.c=.o) $(ASM_OBJS)
TARGET = server-zc

# ============================================================================
# Main targets
# ============================================================================

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.asm
	$(NASM) -f elf64 -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f src/crypto/*.o src/tls/*.o src/crypto/fast/*.o
	rm -f test_sha256 test_hmac test_aes test_rsa

# ============================================================================
# Test targets
# ============================================================================

# Fast crypto objects needed by all tests
FAST_OBJS = src/crypto/fast/fast_crypto.o src/crypto/fast/cpuid.o src/crypto/fast/crypto_ops.o

test_sha256: tests/test_sha256.c src/crypto/sha256.c $(FAST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_hmac: tests/test_hmac.c src/crypto/hmac.c src/crypto/sha256.c $(FAST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_aes: tests/test_aes.c src/crypto/aes.c $(FAST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_rsa: tests/test_rsa.c src/crypto/rsa.c src/crypto/bignum.c src/crypto/pem.c $(FAST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: test_sha256 test_hmac test_aes test_rsa
	./test_sha256
	./test_hmac
	./test_aes
	./test_rsa
	@echo ""
	@echo "=== All crypto tests passed ==="

.PHONY: all clean test
