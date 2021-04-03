#include <Windows.h>
#include "global.h"
#include "injector.h"
#include "communication.h"
#include "APIhooklib.h"
#include "hooks.h"

#define BUFSIZE 1024

HMODULE hGlobalModule;
HANDLE hDataPipe;
HANDLE hCmdPipe;
INJECT_CONFIG config;

int hookParamCounts[0x1000] = { -1 };

HEDERA_MESSAGE* DoReadMem(HEDERA_MESSAGE* pMsg) {
	PBYTE pAddress = (PBYTE)DWORD_PARAM(pMsg, 0);
	int size = DWORD_PARAM(pMsg, 1);
	
	HEDERA_MESSAGE* pResponse = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pResponse->Code = CODE_OK;
	pResponse->ArgCount = 1;
	pResponse->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG));
	pResponse->Args[0].Size = size;
	pResponse->Args[0].Buf = malloc(size);
	memcpy(pResponse->Args[0].Buf, pAddress, size);
	return pResponse;
}

HEDERA_MESSAGE* DoWriteMem(HEDERA_MESSAGE* pMsg) {
	PBYTE pAddress = (PBYTE)DWORD_PARAM(pMsg, 0);
	memcpy(pAddress, pMsg->Args[1].Buf, pMsg->Args[1].Size);
	HEDERA_MESSAGE* pResponse = CreateSimpleHMessage(CODE_OK);
	return pResponse;
}

HEDERA_MESSAGE* DoSetHookName(HEDERA_MESSAGE* pMsg) {
	int id = DWORD_PARAM(pMsg, 0);
	int paramCount = DWORD_PARAM(pMsg, 3);
	CallConv callConv = (CallConv)DWORD_PARAM(pMsg, 4);
	BOOL bHasBeforeHook = DWORD_PARAM(pMsg, 5);
	BOOL bHasAfterHook = DWORD_PARAM(pMsg, 6);
    BOOL bDoCall = DWORD_PARAM(pMsg, 7);
	BOOL bOverrideRet = DWORD_PARAM(pMsg, 8);
	BOOL bOverrideParams = DWORD_PARAM(pMsg, 9);

	hookParamCounts[id] = paramCount;
	FARPROC pBeforeHook = NULL;
	if (bHasBeforeHook) {
		pBeforeHook = bOverrideParams ? (FARPROC)bh_HederaHookParamOverride : (FARPROC)bh_HederaHook;
	}
	FARPROC pAfterHook = bHasAfterHook ? (FARPROC)ah_HederaHook : NULL;
	SetHookByNameWithId(id, (LPSTR)pMsg->Args[1].Buf, (LPSTR)pMsg->Args[2].Buf, paramCount, callConv, pBeforeHook, pAfterHook, bDoCall, bOverrideRet, bOverrideParams);

	return CreateSimpleHMessage(CODE_OK);
}

HEDERA_MESSAGE* DoSetHookAddr(HEDERA_MESSAGE* pMsg) {
	int id = DWORD_PARAM(pMsg, 0);
	LPVOID pAddress = (LPVOID)DWORD_PARAM(pMsg, 1);
	int paramCount = DWORD_PARAM(pMsg, 2);
	CallConv callConv = (CallConv)DWORD_PARAM(pMsg, 3);
	BOOL bHasBeforeHook = DWORD_PARAM(pMsg, 4);
	BOOL bHasAfterHook = DWORD_PARAM(pMsg, 5);
	BOOL bDoCall = DWORD_PARAM(pMsg, 6);
	BOOL bOverrideRet = DWORD_PARAM(pMsg, 7);
	BOOL bOverrideParams = DWORD_PARAM(pMsg, 8);

	hookParamCounts[id] = paramCount;
	FARPROC pBeforeHook = NULL;
	if (bHasBeforeHook) {
		pBeforeHook = bOverrideParams ? (FARPROC)bh_HederaHookParamOverride : (FARPROC)bh_HederaHook;
	}
	FARPROC pAfterHook = bHasAfterHook ? (FARPROC)ah_HederaHook : NULL;
	SetHookByAddrWithId(id, pAddress, paramCount, callConv, pBeforeHook, pAfterHook, bDoCall, bOverrideRet, bOverrideParams);

	return CreateSimpleHMessage(CODE_OK);
}

HEDERA_MESSAGE* HandleMessage(HEDERA_MESSAGE* pMsg) {
	HEDERA_MESSAGE* pResponse = NULL;
	switch (pMsg->Code) {
	case CODE_READ_MEM:
		pResponse = DoReadMem(pMsg);
		break;
	case CODE_WRITE_MEM:
		pResponse = DoWriteMem(pMsg);
		break;
	case CODE_SET_HOOK_NAME:
		pResponse = DoSetHookName(pMsg);
		break;
	case CODE_SET_HOOK_ADDR:
		pResponse = DoSetHookAddr(pMsg);
		break;
	case CODE_REMOVE_HOOK:
	default:
		pResponse = CreateSimpleHMessage(CODE_ERROR);
		break;
	}

	DestroyHMessage(pMsg);
	return pResponse;
}

DWORD __stdcall CommandThreadRoutine(LPVOID lpParams) {
	while (1) {
		HEDERA_MESSAGE* pMsg = ReceiveHMessage(hCmdPipe);
		if (!pMsg)
			break;

		log("dll message %x\n", pMsg);
		HEDERA_MESSAGE* pResponse = HandleMessage(pMsg);

		if (!pResponse) {
			pResponse = CreateSimpleHMessage(CODE_ERROR);
		}
		SendHMessage(pResponse, hCmdPipe);
		DestroyHMessage(pResponse);
	}
	
	return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	int argc;
	WCHAR **argv;
	WCHAR pPipeName[64];
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		hGlobalModule = hModule;

		argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		wsprintfW(pPipeName, PIPE_TEMPLATE_LEAF_DATA, GetCurrentProcessId(), GetCurrentThreadId());
		wlog(L"open data pipe %s\n", pPipeName);
		hDataPipe = CreateFileW(pPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hDataPipe == INVALID_HANDLE_VALUE) {
			log("dll invalid data_pipe %x\n", GetLastError());
			return TRUE;
		}

		DWORD dwMode = PIPE_READMODE_MESSAGE;
		SetNamedPipeHandleState(
			hDataPipe,    // pipe handle 
			&dwMode,  // new pipe mode 
			NULL,     // don't set maximum bytes 
			NULL);    // don't set maximum time


		HEDERA_MESSAGE* pMsg = CreateSimpleHMessage(CODE_INIT);
		SendHMessage(pMsg, hDataPipe);
		DestroyHMessage(pMsg);
		HEDERA_MESSAGE* pResponse = ReceiveHMessage(hDataPipe);
		int savedCount = DWORD_PARAM(pResponse, 0);
		log("dll saved count %d\n", savedCount);

		SetHooks();

		WCHAR pPipeName[64];
		wsprintfW(pPipeName, PIPE_TEMPLATE_LEAF_CMD, GetCurrentProcessId(), GetCurrentThreadId());
		wlog(L"dll create cmd pipe %s\n", pPipeName);
		hCmdPipe = CreateNamedPipeW(
			pPipeName,
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute

		// Create the cmd handler thread before executing saved commands, so that CreateThread is not a "special" function
		HANDLE hThread = CreateThread(NULL, NULL, CommandThreadRoutine, NULL, CREATE_SUSPENDED, NULL);

		if (ConnectNamedPipe(hCmdPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
			for (int i = 0; i < savedCount; i++) {
				HEDERA_MESSAGE* pMsg = ReceiveHMessage(hCmdPipe);
				log("dll doing saved message %d %x\n", i, pMsg->Code);
				if (!pMsg)
					break;
				HEDERA_MESSAGE* pRes = HandleMessage(pMsg);
				SendHMessage(pRes, hCmdPipe);
				DestroyHMessage(pRes);
			}
		}

		ResumeThread(hThread);

		DestroyHMessage(pResponse);
		break;
	}
		

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

