#include "global.h"
#include "hooks.h"
#include "communication.h"
#include "functions.h"
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

#define MYPROC_NUM 100

typedef struct _TARGET_PROCESS {
	DWORD Pid;
	BOOL Injected;
} TARGET_PROCESS;

extern HANDLE hDataPipe;
extern HMODULE hGlobalModule;
extern int hookParamCounts[0x1000];

TARGET_PROCESS pMyProcesses[MYPROC_NUM] = { 0 };
BOOL pHooked = TRUE;

BOOL __forceinline CheckSelfHook() {
	LPVOID pRetAddress, pStackFrame;
	HMODULE hModule;

	HMODULE hMainModule = GetModuleHandleA(NULL);

	__asm {
		mov eax, [ebp]
		mov pStackFrame, eax
	}

	while (TRUE) {
		__asm {
			mov eax, pStackFrame
			mov eax, [eax]
			mov pStackFrame, eax
			mov eax, [eax + 4]
			mov pRetAddress, eax
		}
		if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)pRetAddress, &hModule)) {
			if (hModule == hGlobalModule)
				return TRUE;
			if (hModule == hMainModule)
				return FALSE;
		}
		else
			break;
	}
	return FALSE;
}

VOID InjectProcess(DWORD dwPid, DWORD dwTid) {
	log("dll inject\n");
	for (int i = 0; i < MYPROC_NUM && pMyProcesses[i].Pid; i++) {
		if (dwPid == pMyProcesses[i].Pid && !pMyProcesses[i].Injected) {
			HEDERA_MESSAGE* pMsg = CreateSimpleHMessage(CODE_INJECT);
			pMsg->ArgCount = 2;
			pMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG) * pMsg->ArgCount);
			pMsg->Args[0].Size = sizeof(DWORD);
			pMsg->Args[0].Buf = malloc(sizeof(DWORD));
			*(DWORD*)pMsg->Args[0].Buf = dwPid;
			pMsg->Args[1].Size = sizeof(DWORD);
			pMsg->Args[1].Buf = malloc(sizeof(DWORD));
			*(DWORD*)pMsg->Args[1].Buf = dwTid;
			SendHMessage(pMsg, hDataPipe);
			DestroyHMessage(pMsg);

			HEDERA_MESSAGE* pResponse = ReceiveHMessage(hDataPipe);
			if (!pResponse) {
				pMyProcesses[i].Injected = TRUE;
				pHooked = FALSE;
			}
			else
				DestroyHMessage(pResponse);
		}
	}
}

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
) {
	if (!pHooked)
		return pOrigNtCreateUserProcess(
			ProcessHandle,
			ThreadHandle,
			ProcessDesiredAccess,
			ThreadDesiredAccess,
			ProcessObjectAttributes,
			ThreadObjectAttributes,
			ProcessFlags,
			ThreadFlags,
			ProcessParameters,
			CreateInfo,
			AttributeList
		);

	NTSTATUS status = pOrigNtCreateUserProcess(
		ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
		ProcessParameters,
		CreateInfo,
		AttributeList
	);
	if (!status) {
		for (int i = 0; i < MYPROC_NUM; i++) {
			if (!pMyProcesses[i].Pid) {
				pMyProcesses[i].Pid = GetProcessId(*ProcessHandle);
				break;
			}
		}
		if ((ThreadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) == 0) {
			log("dll not suspended\n");
			DWORD dwPid = GetProcessId(*ProcessHandle);
			DWORD dwTid = GetThreadId(*ThreadHandle);
			InjectProcess(dwPid, dwTid);
			ULONG ulSuspendCount;
			pOrigNtResumeThread(*ThreadHandle, &ulSuspendCount);
		}
	}
	return status;
}

VOID __cdecl bh_NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
	if (!pHooked)
		return;

	DWORD dwPid = GetProcessIdOfThread(ThreadHandle);
	DWORD dwTid = GetThreadId(ThreadHandle);
	for (int i = 0; i < MYPROC_NUM && pMyProcesses[i].Pid; i++) {
		if (pMyProcesses[i].Pid == dwPid) {
			InjectProcess(dwPid, dwTid);
			break;
		}
	}
}

VOID __cdecl bh_HederaHookParamOverride(int id, ...) {
	if (!pHooked)
		return;

	if (CheckSelfHook())
		return;

	HEDERA_MESSAGE* pMsg = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pMsg->Code = CODE_HOOK_DATA;
	pMsg->ArgCount = hookParamCounts[id] + 2;
	pMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG) * pMsg->ArgCount);

	pMsg->Args[0].Buf = malloc(sizeof(int));
	pMsg->Args[0].Size = sizeof(int);
	*(int*)pMsg->Args[0].Buf = id;

	pMsg->Args[1].Buf = malloc(sizeof(int));
	pMsg->Args[1].Size = sizeof(int);
	*(int*)pMsg->Args[1].Buf = HT_BEFORE;

	LPVOID** pParams = (LPVOID**)malloc(sizeof(LPVOID*) * hookParamCounts[id]);
	va_list ap;
	va_start(ap, id);
	for (int i = 0; i < hookParamCounts[id]; i++) {
		pParams[i] = va_arg(ap, LPVOID*);
	}
	va_end(ap);

	for (int i = 2; i < pMsg->ArgCount; i++) {
		pMsg->Args[i].Buf = malloc(sizeof(LPVOID));
		pMsg->Args[i].Size = sizeof(LPVOID);
		*(LPVOID*)pMsg->Args[i].Buf = *pParams[i - 2];
	}

	SendHMessage(pMsg, hDataPipe);
	HEDERA_MESSAGE* pResponse = ReceiveHMessage(hDataPipe);

	for (int i = 0; i < pResponse->ArgCount; i++) {
		*pParams[i] = PTR_PARAM(pResponse, i);
	}

	free(pParams);
	DestroyHMessage(pMsg);
	DestroyHMessage(pResponse);
}

VOID __cdecl bh_HederaHook(int id, ...) {
	if (!pHooked)
		return;

	if (CheckSelfHook())
		return;

	HEDERA_MESSAGE* pMsg = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pMsg->Code = CODE_HOOK_DATA;
	pMsg->ArgCount = hookParamCounts[id] + 2;
	pMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG) * pMsg->ArgCount);

	pMsg->Args[0].Buf = malloc(sizeof(int));
	pMsg->Args[0].Size = sizeof(int);
	*(int*)pMsg->Args[0].Buf = id;

	pMsg->Args[1].Buf = malloc(sizeof(int));
	pMsg->Args[1].Size = sizeof(int);
	*(int*)pMsg->Args[1].Buf = HT_BEFORE;

	va_list ap;
	va_start(ap, id);
	for (int i = 2; i < pMsg->ArgCount; i++) {
		pMsg->Args[i].Buf = malloc(sizeof(LPVOID));
		pMsg->Args[i].Size = sizeof(LPVOID);
		*(LPVOID*)pMsg->Args[i].Buf = va_arg(ap, LPVOID);
	}
	va_end(ap);
	SendHMessage(pMsg, hDataPipe);
	HEDERA_MESSAGE* pResponse = ReceiveHMessage(hDataPipe);

	DestroyHMessage(pMsg);
	DestroyHMessage(pResponse);
}

DWORD __cdecl ah_HederaHook(int id, ...) {
	if (!pHooked)
		return 0;

	if (CheckSelfHook())
		return 0;

	HEDERA_MESSAGE* pMsg = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pMsg->Code = CODE_HOOK_DATA;
	pMsg->ArgCount = hookParamCounts[id] + 3;
	pMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG) * pMsg->ArgCount);

	pMsg->Args[0].Buf = malloc(sizeof(int));
	pMsg->Args[0].Size = sizeof(int);
	*(int*)pMsg->Args[0].Buf = id;

	pMsg->Args[1].Buf = malloc(sizeof(int));
	pMsg->Args[1].Size = sizeof(int);
	*(int*)pMsg->Args[1].Buf = HT_AFTER;

	va_list ap;
	va_start(ap, id);
	for (int i = 2; i < pMsg->ArgCount; i++) {
		pMsg->Args[i].Buf = malloc(sizeof(LPVOID));
		pMsg->Args[i].Size = sizeof(LPVOID);
		*(LPVOID*)pMsg->Args[i].Buf = va_arg(ap, LPVOID);
	}
	va_end(ap);
	SendHMessage(pMsg, hDataPipe);
	HEDERA_MESSAGE* pResponse = ReceiveHMessage(hDataPipe);

	DWORD dwRetValue = DWORD_PARAM(pResponse, 0);

	DestroyHMessage(pMsg);
	DestroyHMessage(pResponse);

	return dwRetValue;
}