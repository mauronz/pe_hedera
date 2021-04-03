#include "global.h"
#include "monitor_handlers.h"
#include "communication.h"
#include "monitor.h"
#include <stdio.h>

typedef struct _MESSAGE_LIST_ENTRY {
	LIST_ENTRY List;
	HEDERA_MESSAGE* Message;
} MESSAGE_LIST_ENTRY;

HEDERA_MESSAGE* HandleMessage(HEDERA_MESSAGE* pMsg);

extern HANDLE hCmdPipe;
extern HANDLE hScriptDataPipe;
extern HANDLE hTargetProcess;
extern HANDLE hTargetMainThread;
extern LPVOID pTargetBaseAddress;

HANDLE hScriptPipe = NULL;
MESSAGE_LIST_ENTRY* pSavedMessages = NULL;
int savedCount = 0;

VOID SaveMessage(HEDERA_MESSAGE* pMsg) {
	savedCount++;
	MESSAGE_LIST_ENTRY* pNewEntry = (MESSAGE_LIST_ENTRY*)malloc(sizeof(MESSAGE_LIST_ENTRY));
	pNewEntry->Message = pMsg;
	pNewEntry->List.Flink = NULL;
	if (!pSavedMessages) {
		pSavedMessages = pNewEntry;
		return;
	}
	MESSAGE_LIST_ENTRY* pEntry;
	for (pEntry = pSavedMessages; pEntry->List.Flink; pEntry = (MESSAGE_LIST_ENTRY*)pEntry->List.Flink);
	pEntry->List.Flink = (LIST_ENTRY*)pNewEntry;
}

VOID ExecuteSavedMessages() {
	log("do saved messages\n");
	MESSAGE_LIST_ENTRY* pEntry = pSavedMessages;
	while (pEntry) {
		log("saved message %x\n", pEntry->Message->Code);
		HEDERA_MESSAGE* pResponse = HandleMessage(pEntry->Message);
		DestroyHMessage(pResponse);
		MESSAGE_LIST_ENTRY* pNextEntry = (MESSAGE_LIST_ENTRY*)pEntry->List.Flink;
		free(pEntry);
		pEntry = pNextEntry;
		savedCount--;
	}
	pSavedMessages = NULL;
}

DWORD __stdcall MonitorThreadRoutine(LPVOID lpParams) {
	MonitorCommunicate(hScriptPipe);
	return 0;
}

HANDLE CreateMonitorThread() {
	return CreateThread(NULL, 0, MonitorThreadRoutine, (LPVOID)hScriptPipe, 0, NULL);
}

VOID SetupTargetCommandChannel() {
	WCHAR pPipeName[64];
	wsprintfW(pPipeName, PIPE_TEMPLATE_LEAF_CMD, GetProcessId(hTargetProcess), GetThreadId(hTargetMainThread));
	do {
		Sleep(500);
		wlog(L"monitor try open %s\n", pPipeName);
		hCmdPipe = CreateFileW(pPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	} while (hCmdPipe == INVALID_HANDLE_VALUE);
	wlog(L"monitor done\n", pPipeName);

	DWORD dwMode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(
		hCmdPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time

	ExecuteSavedMessages();
}

HEDERA_MESSAGE* DoReadMem(HEDERA_MESSAGE* pMsg) {
	PBYTE pAddress = (PBYTE)DWORD_PARAM(pMsg, 0);
	int size = DWORD_PARAM(pMsg, 1);

	HEDERA_MESSAGE* pResponse = CreateSimpleHMessage(CODE_ERROR);

	LPVOID pBuf = malloc(size);
	SIZE_T nRead = 0;
	BOOL bRes = ReadProcessMemory(hTargetProcess, pAddress, pBuf, size, &nRead);

	if (!bRes || nRead != size)
		return pResponse;

	pResponse->Code = CODE_OK;
	pResponse->ArgCount = 1;
	pResponse->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG));
	pResponse->Args[0].Size = size;
	pResponse->Args[0].Buf = pBuf;
	return pResponse;
}

HEDERA_MESSAGE* DoWriteMem(HEDERA_MESSAGE* pMsg) {
	PBYTE pAddress = (PBYTE)DWORD_PARAM(pMsg, 0);

	HEDERA_MESSAGE* pResponse = CreateSimpleHMessage(CODE_ERROR);

	SIZE_T nWritten = 0;
	BOOL bRes = WriteProcessMemory(hTargetProcess, pAddress, pMsg->Args[1].Buf, pMsg->Args[1].Size, &nWritten);

	if (!bRes || nWritten != pMsg->Args[1].Size)
		return pResponse;

	pResponse->Code = CODE_OK;
	return pResponse;
}

HEDERA_MESSAGE* DoStart(HEDERA_MESSAGE* pMsg) {
	ResumeThread(hTargetMainThread);
	SetupTargetCommandChannel();
	return CreateSimpleHMessage(CODE_OK);
}

HEDERA_MESSAGE* DoStop(HEDERA_MESSAGE* pMsg) {
	BOOL bRes = TerminateProcess(hTargetProcess, 0);
	MessageCode code = bRes ? CODE_OK : CODE_ERROR;
	return CreateSimpleHMessage(code);
}

HEDERA_MESSAGE* HandleMessage(HEDERA_MESSAGE* pMsg) {
	HEDERA_MESSAGE* pResponse = NULL;
	switch (pMsg->Code) {
	case CODE_INIT:
		hScriptDataPipe = CreateFileA((LPSTR)pMsg->Args[0].Buf, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hScriptDataPipe != INVALID_HANDLE_VALUE) {
			pResponse = CreateSimpleHMessage(CODE_OK);
			pResponse->ArgCount = 1;
			pResponse->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG));
			pResponse->Args[0].Size = sizeof(pTargetBaseAddress);
			pResponse->Args[0].Buf = (LPVOID)malloc(sizeof(pTargetBaseAddress));
			*(LPVOID*)pResponse->Args[0].Buf = pTargetBaseAddress;
		}
		else
			pResponse = CreateSimpleHMessage(CODE_ERROR);
		DestroyHMessage(pMsg);
		break;
	case CODE_SET_HOOK_NAME:
	case CODE_SET_HOOK_ADDR:
	case CODE_REMOVE_HOOK:
		if (hCmdPipe != INVALID_HANDLE_VALUE) {
			SendHMessage(pMsg, hCmdPipe);
			pResponse = ReceiveHMessage(hCmdPipe);
			DestroyHMessage(pMsg);
		}
		else {
			log("cmdpipe not up, save\n");
			SaveMessage(pMsg);
			pResponse = CreateSimpleHMessage(CODE_OK);
		}
		break;
	case CODE_READ_MEM:
		pResponse = DoReadMem(pMsg);
		DestroyHMessage(pMsg);
		break;
	case CODE_WRITE_MEM:
		pResponse = DoWriteMem(pMsg);
		DestroyHMessage(pMsg);
		break;
	case CODE_START:
		pResponse = DoStart(pMsg);
		DestroyHMessage(pMsg);
		break;
	case CODE_STOP:
		pResponse = DoStop(pMsg);
		DestroyHMessage(pMsg);
		break;
	default:
		pResponse = CreateSimpleHMessage(CODE_ERROR);
		break;
	}
	return pResponse;
}

BOOL MonitorCommunicate(HANDLE hPipe) {
	if (hPipe == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	while (TRUE) {
		HEDERA_MESSAGE* pMsg = ReceiveHMessage(hPipe);
		if (!pMsg)
			break;

		log("monitor message %x\n", pMsg->Code);
		HEDERA_MESSAGE* pResponse = HandleMessage(pMsg);
		SendHMessage(pResponse, hPipe);
		DestroyHMessage(pResponse);
	}

	CloseHandle(hPipe);
	return TRUE;
}