; ============================================================================
; fast_io.asm — Direct Syscall I/O (bypass libc)
; ============================================================================
; Instead of: your code → libc send() → syscall instruction → kernel
; We do:      your code → syscall instruction → kernel
;
; Saves ~20ns per call by skipping libc's wrapper overhead:
;   - No PLT/GOT indirection
;   - No errno handling
;   - No signal mask checks
;   - Straight to the kernel via the SYSCALL instruction
;
; Linux x86_64 syscall ABI:
;   syscall number in rax
;   args in: rdi, rsi, rdx, r10, r8, r9
;   return in rax (negative = -errno)
;   clobbers: rcx, r11
; ============================================================================

section .text

; Linux x86_64 syscall numbers
%define SYS_READ      0
%define SYS_WRITE     1
%define SYS_CLOSE     3
%define SYS_ACCEPT    43
%define SYS_ACCEPT4   288

; ----------------------------------------------------------------------------
; int64_t fast_recv(int fd, void *buf, size_t len)
; Direct read() syscall — no libc overhead.
; Returns bytes read, 0 = EOF, negative = error
; ----------------------------------------------------------------------------
global fast_recv
fast_recv:
    mov rax, SYS_READ       ; syscall number
    syscall                  ; rdi=fd, rsi=buf, rdx=len already set
    ret

; ----------------------------------------------------------------------------
; int64_t fast_send(int fd, const void *buf, size_t len)
; Direct write() syscall with loop — sends ALL bytes.
; Returns total bytes sent, or negative on error.
; ----------------------------------------------------------------------------
global fast_send
fast_send:
    push rbx
    push r12
    push r13
    mov r12, rsi            ; r12 = buffer pointer
    mov r13, rdx            ; r13 = remaining bytes
    xor ebx, ebx            ; rbx = total sent
    mov rcx, rdi            ; save fd in rcx... wait, syscall clobbers rcx
    push rdi                ; save fd on stack

.send_loop:
    test r13, r13
    jz .send_done

    mov rdi, [rsp]          ; fd
    lea rsi, [r12 + rbx]    ; buf + offset
    mov rdx, r13            ; remaining
    mov rax, SYS_WRITE
    syscall

    test rax, rax
    js .send_err            ; negative = error
    jz .send_done           ; zero = would block

    add rbx, rax            ; total += sent
    sub r13, rax            ; remaining -= sent
    jmp .send_loop

.send_done:
    mov rax, rbx            ; return total sent
    add rsp, 8              ; pop saved fd
    pop r13
    pop r12
    pop rbx
    ret

.send_err:
    ; rax already has negative errno
    add rsp, 8
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; void fast_close(int fd)
; Direct close() syscall.
; ----------------------------------------------------------------------------
global fast_close
fast_close:
    mov rax, SYS_CLOSE      ; rdi = fd already set
    syscall
    ret

; ----------------------------------------------------------------------------
; int fast_accept(int server_fd, struct sockaddr *addr, socklen_t *addrlen)
; Direct accept() syscall — no libc wrapper.
; Returns client fd, or negative on error.
; ----------------------------------------------------------------------------
global fast_accept
fast_accept:
    mov rax, SYS_ACCEPT     ; rdi=sockfd, rsi=addr, rdx=addrlen
    syscall
    ret

; ----------------------------------------------------------------------------
; FAST MEMCHR — find byte in buffer using SIMD
; void* fast_memchr(const void *s, int c, size_t n)
; Uses SSE2 PCMPEQB to scan 16 bytes at a time.
; Returns pointer to first match, or NULL.
; ----------------------------------------------------------------------------
global fast_memchr
fast_memchr:
    ; rdi = buffer, esi = char to find, rdx = length
    test rdx, rdx
    jz .memchr_notfound

    ; Broadcast search byte to all 16 lanes of xmm0
    movd xmm0, esi
    punpcklbw xmm0, xmm0
    punpcklwd xmm0, xmm0
    pshufd xmm0, xmm0, 0

    mov rcx, rdx            ; remaining bytes
    mov rax, rdi            ; current pointer

.memchr_loop16:
    cmp rcx, 16
    jb .memchr_tail

    movdqu xmm1, [rax]      ; load 16 bytes
    pcmpeqb xmm1, xmm0      ; compare each byte
    pmovmskb edx, xmm1      ; extract match bits
    test edx, edx
    jnz .memchr_found16

    add rax, 16
    sub rcx, 16
    jmp .memchr_loop16

.memchr_found16:
    bsf edx, edx            ; find first set bit
    add rax, rdx
    ret

.memchr_tail:
    ; Scan remaining bytes one at a time
    test rcx, rcx
    jz .memchr_notfound
    cmp byte [rax], sil
    je .memchr_ret
    inc rax
    dec rcx
    jmp .memchr_tail

.memchr_ret:
    ret

.memchr_notfound:
    xor eax, eax            ; return NULL
    ret
