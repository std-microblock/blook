; Test assembly functions for reassembly tests

.code

; Simple add function: int asm_add_function(int a, int b)
; Windows x64: rcx = a, rdx = b, return in eax
; Windows x86: stack-based
asm_add_function PROC
IFDEF RAX
    ; x64 version
    mov eax, ecx
    add eax, edx
    ret
ELSE
    ; x86 version
    mov eax, dword ptr [esp + 4]
    add eax, dword ptr [esp + 8]
    ret
ENDIF
asm_add_function ENDP

; extern volatile int g_trampoline_counter;
EXTRN g_trampoline_counter:DWORD

; void asm_counter_function(int increment_by)
; Increments g_trampoline_counter by the given amount
asm_counter_function PROC
IFDEF RAX
    ; x64 version: rcx = increment_by
    push rax
    push rdx
    lea rax, g_trampoline_counter
    mov edx, dword ptr [rax]
    add edx, ecx
    mov dword ptr [rax], edx
    pop rdx
    pop rax
    ret
ELSE
    ; x86 version: stack-based
    push eax
    push ecx
    mov eax, offset g_trampoline_counter
    mov ecx, dword ptr [eax]
    add ecx, dword ptr [esp + 12]  ; increment_by parameter
    mov dword ptr [eax], ecx
    pop ecx
    pop eax
    ret
ENDIF
asm_counter_function ENDP

END
