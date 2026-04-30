; ============================================================================
; crypto_ops.asm — Hardware-Accelerated Crypto Operations
; ============================================================================
; AES-NI + SHA-NI + 64-bit BigNum multiply
; System V AMD64 ABI: args rdi,rsi,rdx,rcx,r8,r9; return rax
; ============================================================================

section .text

; ============================================================================
; AES-NI KEY EXPANSION
; ============================================================================
%macro AESKEYGEN 2
    aeskeygenassist xmm2, xmm1, %1
    pshufd xmm2, xmm2, 0xFF
    movdqa xmm3, xmm1
    pslldq xmm3, 4
    pxor   xmm1, xmm3
    pslldq xmm3, 4
    pxor   xmm1, xmm3
    pslldq xmm3, 4
    pxor   xmm1, xmm3
    pxor   xmm1, xmm2
    movdqu [rdi + %2], xmm1
%endmacro

global fast_aes128_key_expand
fast_aes128_key_expand:
    push rdi
    movdqu xmm1, [rdi]
    mov rdi, rsi
    movdqu [rdi], xmm1
    AESKEYGEN 0x01, 16
    AESKEYGEN 0x02, 32
    AESKEYGEN 0x04, 48
    AESKEYGEN 0x08, 64
    AESKEYGEN 0x10, 80
    AESKEYGEN 0x20, 96
    AESKEYGEN 0x40, 112
    AESKEYGEN 0x80, 128
    AESKEYGEN 0x1B, 144
    AESKEYGEN 0x36, 160
    pop rdi
    ret

; ============================================================================
; AES-NI ENCRYPT BLOCK
; ============================================================================
global fast_aes128_encrypt_block
fast_aes128_encrypt_block:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdx]
    pxor   xmm0, xmm1
    movdqu xmm1, [rdx+16]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+32]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+48]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+64]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+80]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+96]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+112]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+128]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+144]
    aesenc xmm0, xmm1
    movdqu xmm1, [rdx+160]
    aesenclast xmm0, xmm1
    movdqu [rsi], xmm0
    ret

; ============================================================================
; AES-NI DECRYPT BLOCK
; ============================================================================
global fast_aes128_decrypt_block
fast_aes128_decrypt_block:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdx+160]
    pxor   xmm0, xmm1
    movdqu xmm1, [rdx+144]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+128]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+112]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+96]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+80]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+64]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+48]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+32]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx+16]
    aesimc xmm1, xmm1
    aesdec xmm0, xmm1
    movdqu xmm1, [rdx]
    aesdeclast xmm0, xmm1
    movdqu [rsi], xmm0
    ret

; ============================================================================
; SHA-NI: SHA-256 TRANSFORM — uses only xmm0-xmm7 + stack saves
; ============================================================================

section .rodata
align 16
SHUF_MASK:
    db 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
align 16
SHA256_K:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .text

; Macro: 4 SHA-256 rounds with message schedule update
; %1=MSG_cur %2=MSG_next %3=MSG_prev %4=MSG_pprev %5=K_offset %6=do_msg_sched(0/1)
%macro SHA_4ROUNDS 6
    movdqa xmm2, %1
    paddd  xmm2, [rbx + %5]
    sha256rnds2 xmm1, xmm0      ; uses implicit xmm0 as 3rd operand... wait
%endmacro

; Actually, sha256rnds2 in NASM: sha256rnds2 xmm_dst, xmm_src, xmm0
; The third operand is ALWAYS xmm0 implicitly in the hardware encoding.
; So we need xmm0 to hold the message+K, and state in other regs.
;
; Standard layout:
;   xmm0 = scratch (holds MSG+K for sha256rnds2 implicit operand)
;   xmm1 = STATE0 (CDAB)
;   xmm2 = STATE1 (GHEF)
;   xmm3 = MSG0, xmm4 = MSG1, xmm5 = MSG2, xmm6 = MSG3
;   xmm7 = temp for palignr

global fast_sha256_transform
fast_sha256_transform:
    push rbx
    sub rsp, 48                  ; stack: [rsp]=SAVE_STATE0, [rsp+16]=SAVE_STATE1, [rsp+32]=SHUF

    lea rax, [rel SHUF_MASK]
    movdqa xmm7, [rax]
    movdqa [rsp+32], xmm7        ; save shuf mask on stack

    lea rbx, [rel SHA256_K]

    ; Load state: state[0..3]=ABCD, state[4..7]=EFGH
    movdqu xmm1, [rdi]           ; ABCD
    movdqu xmm2, [rdi+16]        ; EFGH

    ; Rearrange to SHA-NI layout: STATE0=FEBA, STATE1=HGDC
    pshufd xmm1, xmm1, 0xB1     ; BADC
    pshufd xmm2, xmm2, 0x1B     ; HGFE
    movdqa xmm7, xmm1
    palignr xmm1, xmm2, 8       ; FEBA = STATE0
    pblendw xmm2, xmm7, 0xF0    ; HGDC = STATE1

    ; Save initial state
    movdqa [rsp], xmm1
    movdqa [rsp+16], xmm2

    ; Load and byteswap message
    movdqa xmm7, [rsp+32]        ; reload shuf mask
    movdqu xmm3, [rsi]
    pshufb xmm3, xmm7
    movdqu xmm4, [rsi+16]
    pshufb xmm4, xmm7
    movdqu xmm5, [rsi+32]
    pshufb xmm5, xmm7
    movdqu xmm6, [rsi+48]
    pshufb xmm6, xmm7

    ; ====== Rounds 0-3 ======
    movdqa xmm0, xmm3
    paddd  xmm0, [rbx]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2

    ; ====== Rounds 4-7 ======
    movdqa xmm0, xmm4
    paddd  xmm0, [rbx+16]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm3, xmm4

    ; ====== Rounds 8-11 ======
    movdqa xmm0, xmm5
    paddd  xmm0, [rbx+32]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm4, xmm5

    ; ====== Rounds 12-15 ======
    movdqa xmm7, xmm6
    palignr xmm7, xmm5, 4
    paddd  xmm3, xmm7
    sha256msg2 xmm3, xmm6
    movdqa xmm0, xmm6
    paddd  xmm0, [rbx+48]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm5, xmm6

    ; ====== Rounds 16-19 ======
    movdqa xmm7, xmm3
    palignr xmm7, xmm6, 4
    paddd  xmm4, xmm7
    sha256msg2 xmm4, xmm3
    movdqa xmm0, xmm3
    paddd  xmm0, [rbx+64]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm6, xmm3

    ; ====== Rounds 20-23 ======
    movdqa xmm7, xmm4
    palignr xmm7, xmm3, 4
    paddd  xmm5, xmm7
    sha256msg2 xmm5, xmm4
    movdqa xmm0, xmm4
    paddd  xmm0, [rbx+80]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm3, xmm4

    ; ====== Rounds 24-27 ======
    movdqa xmm7, xmm5
    palignr xmm7, xmm4, 4
    paddd  xmm6, xmm7
    sha256msg2 xmm6, xmm5
    movdqa xmm0, xmm5
    paddd  xmm0, [rbx+96]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm4, xmm5

    ; ====== Rounds 28-31 ======
    movdqa xmm7, xmm6
    palignr xmm7, xmm5, 4
    paddd  xmm3, xmm7
    sha256msg2 xmm3, xmm6
    movdqa xmm0, xmm6
    paddd  xmm0, [rbx+112]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm5, xmm6

    ; ====== Rounds 32-35 ======
    movdqa xmm7, xmm3
    palignr xmm7, xmm6, 4
    paddd  xmm4, xmm7
    sha256msg2 xmm4, xmm3
    movdqa xmm0, xmm3
    paddd  xmm0, [rbx+128]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm6, xmm3

    ; ====== Rounds 36-39 ======
    movdqa xmm7, xmm4
    palignr xmm7, xmm3, 4
    paddd  xmm5, xmm7
    sha256msg2 xmm5, xmm4
    movdqa xmm0, xmm4
    paddd  xmm0, [rbx+144]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm3, xmm4

    ; ====== Rounds 40-43 ======
    movdqa xmm7, xmm5
    palignr xmm7, xmm4, 4
    paddd  xmm6, xmm7
    sha256msg2 xmm6, xmm5
    movdqa xmm0, xmm5
    paddd  xmm0, [rbx+160]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm4, xmm5

    ; ====== Rounds 44-47 ======
    movdqa xmm7, xmm6
    palignr xmm7, xmm5, 4
    paddd  xmm3, xmm7
    sha256msg2 xmm3, xmm6
    movdqa xmm0, xmm6
    paddd  xmm0, [rbx+176]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm5, xmm6

    ; ====== Rounds 48-51 ======
    movdqa xmm7, xmm3
    palignr xmm7, xmm6, 4
    paddd  xmm4, xmm7
    sha256msg2 xmm4, xmm3
    movdqa xmm0, xmm3
    paddd  xmm0, [rbx+192]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2

    ; ====== Rounds 52-55 ======
    movdqa xmm7, xmm4
    palignr xmm7, xmm3, 4
    paddd  xmm5, xmm7
    sha256msg2 xmm5, xmm4
    movdqa xmm0, xmm4
    paddd  xmm0, [rbx+208]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2

    ; ====== Rounds 56-59 ======
    movdqa xmm7, xmm5
    palignr xmm7, xmm4, 4
    paddd  xmm6, xmm7
    sha256msg2 xmm6, xmm5
    movdqa xmm0, xmm5
    paddd  xmm0, [rbx+224]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2

    ; ====== Rounds 60-63 ======
    movdqa xmm0, xmm6
    paddd  xmm0, [rbx+240]
    sha256rnds2 xmm2, xmm1
    pshufd xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2

    ; Add saved state
    paddd xmm1, [rsp]            ; STATE0 += saved STATE0
    paddd xmm2, [rsp+16]         ; STATE1 += saved STATE1

    ; Convert STATE0(FEBA)/STATE1(HGDC) back to ABCD/EFGH
    pshufd xmm1, xmm1, 0x1B     ; ABEF
    pshufd xmm2, xmm2, 0xB1     ; GHCD
    movdqa xmm7, xmm1
    punpckhdq xmm1, xmm2        ; ABCD
    punpckldq xmm7, xmm2        ; EFGH

    movdqu [rdi], xmm1
    movdqu [rdi+16], xmm7

    add rsp, 48
    pop rbx
    ret

; ============================================================================
; BIGNUM: 64-BIT MULTIPLY-ACCUMULATE
; ============================================================================
global fast_bn_mul_words
fast_bn_mul_words:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r12, rdi                ; result ptr
    mov r13, rsi                ; a ptr
    mov r14d, edx               ; a_len
    mov r15, rcx                ; b ptr
    mov ebp, r8d                ; b_len

    xor r8d, r8d                ; i = 0
.outer_loop:
    cmp r8d, r14d
    jge .done

    mov eax, [r13 + r8*4]
    test eax, eax
    jz .skip_inner

    mov r9, rax                 ; r9 = a[i] (zero-extended 32-bit)
    xor r10d, r10d              ; j = 0
    xor rbx, rbx                ; carry = 0

.inner_loop:
    cmp r10d, ebp
    jge .flush_carry

    ; prod = a[i] * b[j] + result[k] + carry
    mov rax, r9
    mov r11d, [r15 + r10*4]
    imul r11, rax               ; 64-bit product (unsigned safe for 32-bit inputs)

    lea ecx, [r8d + r10d]       ; k = i + j
    add r11, rbx                ; + carry
    mov ebx, [r12 + rcx*4]
    add r11, rbx                ; + result[k]

    mov [r12 + rcx*4], r11d     ; store low 32
    shr r11, 32
    mov rbx, r11                ; carry = high 32

    inc r10d
    jmp .inner_loop

.flush_carry:
    test rbx, rbx
    jz .skip_inner
    lea ecx, [r8d + r10d]
    add [r12 + rcx*4], ebx
.skip_inner:
    inc r8d
    jmp .outer_loop

.done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
