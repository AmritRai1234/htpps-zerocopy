; ============================================================================
; cpuid.asm — CPU Feature Detection
; ============================================================================
; Uses CPUID to detect AES-NI / SHA-NI hardware support.
; Called once at startup.
; ============================================================================

section .text

; int fast_has_aesni(void) — returns 1 if AES-NI supported
global fast_has_aesni
fast_has_aesni:
    push rbx
    mov eax, 1
    cpuid
    xor eax, eax
    bt ecx, 25
    setc al
    pop rbx
    ret

; int fast_has_shani(void) — returns 1 if SHA-NI supported
global fast_has_shani
fast_has_shani:
    push rbx
    mov eax, 7
    xor ecx, ecx
    cpuid
    xor eax, eax
    bt ebx, 29
    setc al
    pop rbx
    ret

; int fast_has_sse41(void) — returns 1 if SSE4.1 supported
global fast_has_sse41
fast_has_sse41:
    push rbx
    mov eax, 1
    cpuid
    xor eax, eax
    bt ecx, 19
    setc al
    pop rbx
    ret
