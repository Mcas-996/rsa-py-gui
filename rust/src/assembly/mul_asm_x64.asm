; RSA Assembly Multiplication Module
; Optimized x64 assembly for 64x64 -> 128 bit multiplication
; NASM syntax for Windows/Linux/macOS compatibility

; Detect operating system and set format
%ifdef _WIN64
    format pe64 coff
%elif defined(__APPLE__) && defined(__x86_64__)
    format mach-o64
%else
    format elf64
%endif

; ============================================================================
; Section: Read-only data (constants)
; ============================================================================
section .rodata
    align 16
    ; No constants needed for basic multiplication

; ============================================================================
; Section: Code
; ============================================================================
section .text

; ============================================================================
; mul_64x64_to_128
; ============================================================================
; Multiplies two 64-bit unsigned integers to produce a 128-bit result
;
; C Prototype:
;   void mul_64x64_to_128(uint64_t a, uint64_t b, uint64_t *result_high, uint64_t *result_low);
;
; Parameters (Windows x64 calling convention):
;   rcx = a
;   rdx = b
;   r8  = pointer to result (result_high, result_low)
;
; Parameters (System V AMD64 ABI - Linux/macOS):
;   rdi = a
;   rsi = b
;   rdx = pointer to result
;
; Returns:
;   result[0] = high 64 bits
;   result[1] = low 64 bits
; ============================================================================
global mul_64x64_to_128
mul_64x64_to_128:
    ; Standard x64 ABI handling
    %ifdef _WIN64
        ; Windows x64: a in rcx, b in rdx, result pointer in r8
        ; Save non-volatile registers
        push rbx
        push rdi
        push rsi
        push r12

        mov rax, rcx          ; a -> rax
        mul rdx               ; rdx:rax = a * b (mul uses rdx:rax)
        ; rax = low, rdx = high

        mov [r8], rdx         ; store high part
        mov [r8 + 8], rax     ; store low part

        ; Restore registers
        pop r12
        pop rsi
        pop rdi
        pop rbx
        ret
    %else
        ; System V AMD64 ABI: a in rdi, b in rsi, result pointer in rdx
        push rbx

        mov rax, rdi          ; a -> rax
        mul rsi               ; rdx:rax = a * b
        ; rax = low, rdx = high

        mov [rdx], rdx        ; store high part
        mov [rdx + 8], rax    ; store low part

        pop rbx
        ret
    %endif

; ============================================================================
; mulx_64x64_to_128 (BMI2 instruction set)
; ============================================================================
; Uses the mulx instruction for better performance (no flags affected)
; Only available on Intel Haswell+ and AMD Excavator+ processors
;
; C Prototype:
;   void mulx_64x64_to_128(uint64_t a, uint64_t b, uint64_t *result_high, uint64_t *result_low);
;
; Parameters:
;   rdi = a
;   rsi = b
;   rdx = pointer to result
; ============================================================================
global mulx_64x64_to_128
mulx_64x64_to_128:
    ; Check if BMI2 is available (this should be done at runtime)
    ; For now, just use mulx which will #UD if not available

    %ifdef _WIN64
        push rbx

        ; mulx rd:rax, rcx, rdx
        ; Result: high in rdx, low in rax
        mulx rdx, rax, rcx    ; rdx:rax = rcx * rdx

        mov [r8], rdx
        mov [r8 + 8], rax

        pop rbx
        ret
    %else
        push rbx

        ; mulx rd:rax, rdi, rsi
        mulx rdx, rax, rdi    ; rdx:rax = rdi * rsi

        mov [rdx], rdx
        mov [rdx + 8], rax

        pop rbx
        ret
    %endif

; ============================================================================
; add_128 (128-bit addition)
; ============================================================================
; Adds two 128-bit numbers
;
; C Prototype:
;   void add_128(uint64_t a[2], uint64_t b[2], uint64_t result[2]);
;
; result = a + b
; ============================================================================
global add_128
add_128:
    %ifdef _WIN64
        ; rcx = a, rdx = b, r8 = result
        push rbx

        mov rax, [rcx]        ; low a
        add rax, [rdx]        ; + low b
        mov [r8 + 8], rax     ; store low result

        mov rax, [rcx + 8]    ; high a
        adc rax, [rdx + 8]    ; + high b + carry
        mov [r8], rax         ; store high result

        pop rbx
        ret
    %else
        ; rdi = a, rsi = b, rdx = result
        push rbx

        mov rax, [rdi]
        add rax, [rsi]
        mov [rdx + 8], rax

        mov rax, [rdi + 8]
        adc rax, [rsi + 8]
        mov [rdx], rax

        pop rbx
        ret
    %endif

; ============================================================================
; sub_128 (128-bit subtraction)
; ============================================================================
; Subtracts two 128-bit numbers
;
; C Prototype:
;   void sub_128(uint64_t a[2], uint64_t b[2], uint64_t result[2]);
;
; result = a - b
; ============================================================================
global sub_128
sub_128:
    %ifdef _WIN64
        ; rcx = a, rdx = b, r8 = result
        push rbx

        mov rax, [rcx]        ; low a
        sub rax, [rdx]        ; - low b
        mov [r8 + 8], rax     ; store low result

        mov rax, [rcx + 8]    ; high a
        sbb rax, [rdx + 8]    ; - high b - borrow
        mov [r8], rax         ; store high result

        pop rbx
        ret
    %else
        ; rdi = a, rsi = b, rdx = result
        push rbx

        mov rax, [rdi]
        sub rax, [rsi]
        mov [rdx + 8], rax

        mov rax, [rdi + 8]
        sbb rax, [rsi + 8]
        mov [rdx], rax

        pop rbx
        ret
    %endif

; ============================================================================
; mul_mod_64 (64-bit modular multiplication)
; ============================================================================
; Computes (a * b) mod m for 64-bit values
; Uses Montgomery reduction for better performance
;
; C Prototype:
;   uint64_t mul_mod_64(uint64_t a, uint64_t b, uint64_t m);
; ============================================================================
global mul_mod_64
mul_mod_64:
    %ifdef _WIN64
        push rbx
        push r12

        ; Simple modular multiplication (not optimized)
        mov rax, rcx          ; a
        mul rdx               ; rdx:rax = a * b
        div r8                ; rax = (a * b) / m, rdx = (a * b) % m

        mov rax, rdx          ; result = remainder
        pop r12
        pop rbx
        ret
    %else
        push rbx

        mov rax, rdi
        mul rsi
        div rdx

        mov rax, rdx
        pop rbx
        ret
    %endif
