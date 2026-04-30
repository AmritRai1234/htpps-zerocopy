# ============================================================================
# JS Engine Makefile
# ============================================================================
# C code compiled with GCC, assembly with NASM.
# Both linked together into one binary.
# ============================================================================

CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -Wno-stringop-truncation -std=c11 -O3 -march=native -flto -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS = -lm -flto

# C sources
C_SRCS = main.c \
         src/core/lexer.c \
         src/core/parser.c \
         src/core/value.c \
         src/core/eval.c \
         src/jit/jit.c

# Assembly sources (the fast math!)
ASM_SRCS = src/fast/math_ops.asm

# Object files
C_OBJS   = $(C_SRCS:.c=.o)
ASM_OBJS = $(ASM_SRCS:.asm=.o)

ALL_OBJS = $(C_OBJS) $(ASM_OBJS)

TARGET = js

.PHONY: all clean test

all: $(TARGET)
	@echo ""
	@echo "  ╦╔═╗  ╔═╗┌┐┌┌─┐┬┌┐┌┌─┐"
	@echo "  ║╚═╗  ║╣ ││││ ┬││││├┤ "
	@echo " ╚╝╚═╝  ╚═╝┘└┘└─┘┴┘└┘└─┘"
	@echo ""
	@echo "  Built! Run: ./js"
	@echo ""

$(TARGET): $(ALL_OBJS)
	$(CC) $(ALL_OBJS) -o $(TARGET) $(LDFLAGS)

# Compile C files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Assemble NASM files (ELF64 for Linux x86-64)
src/fast/%.o: src/fast/%.asm
	$(NASM) -f elf64 -o $@ $<

clean:
	rm -f $(ALL_OBJS) $(TARGET)
	@echo "Cleaned."

# Test: run a basic JS program
test: $(TARGET)
	@echo "=== Running test program ==="
	@echo 'let x = 10 + 5 * 3; console.log(x)' > /tmp/test_js.js
	@echo 'let y = "hello" + " " + "world"; console.log(y)' >> /tmp/test_js.js
	@echo 'console.log(2 + 3)' >> /tmp/test_js.js
	@echo 'console.log(100 / 3)' >> /tmp/test_js.js
	@echo 'console.log(7 % 3)' >> /tmp/test_js.js
	@echo 'console.log(10 > 5)' >> /tmp/test_js.js
	./$(TARGET) /tmp/test_js.js
	@echo "=== Done ==="
