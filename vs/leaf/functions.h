#pragma once

#include <Windows.h>

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

typedef NTSTATUS (__stdcall *TypedefNtCreateUserProcess)(
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
typedef NTSTATUS(__stdcall *TypedefNtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);

extern TypedefNtCreateUserProcess pOrigNtCreateUserProcess;
extern TypedefNtResumeThread pOrigNtResumeThread;