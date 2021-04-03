#pragma once

#include <Windows.h>

NTSTATUS __cdecl bh_NtCreateUserProcess(
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK ProcessDesiredAccess,
	_In_ ACCESS_MASK ThreadDesiredAccess,
	_In_opt_ PVOID ProcessObjectAttributes,
	_In_opt_ PVOID ThreadObjectAttributes,
	_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
	_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
	_In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
	_Inout_ PVOID CreateInfo,
	_In_opt_ PVOID AttributeList
);

VOID __cdecl bh_NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

VOID __cdecl bh_HederaHookParamOverride(int id, ...);
VOID __cdecl bh_HederaHook(int id, ...);
DWORD __cdecl ah_HederaHook(int id, ...);