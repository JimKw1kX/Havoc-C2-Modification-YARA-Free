[BITS 64]

DEFAULT REL

GLOBAL Spoof

DummyFunction:
    nop ; No operation (or any other dummy instructions)
    ret

[SECTION .text]
Spoof:
    pop    r11
    add    rsp, 8
    mov    rax, [rsp + 24]
    mov    r10, [rax]
    mov    [rsp], r10
    mov    r10, [rax + 8]
    mov    [rax + 8], r11
    mov    [rax + 16], rbx
    lea    rbx, [fixup]
    mov    [rax], rbx
    mov    rbx, rax
    jmp    r10

fixup:
    sub    rsp, 16
    mov    rcx, rbx
    mov    rbx, [rcx + 16]
    mov    rax, [rcx + 8]  ; Load the target address into an intermediate register (rax)
    jmp    rax             ; Jump to the address in rax
    