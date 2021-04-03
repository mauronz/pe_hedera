#include <stdio.h>

#include "global.h"
#include "target_handlers.h"
#include "communication.h"
#include "monitor.h"
#include "monitor_handlers.h"

extern INJECT_CONFIG config;

extern HANDLE hSemaphore;
extern HANDLE hThreadCountMutex;
extern DWORD dwThreadCount;
extern int savedCount;

HANDLE hCmdPipe = INVALID_HANDLE_VALUE;
HANDLE hTargetDataPipe = INVALID_HANDLE_VALUE;
HANDLE hScriptDataPipe = INVALID_HANDLE_VALUE;

DWORD __stdcall WorkerThreadRoutine(LPVOID lpParams) {
	Communicate();
	return 0;
}

HANDLE CreateWorkerThread(DWORD dwPid, DWORD dwTid) {
	if (hTargetDataPipe == INVALID_HANDLE_VALUE)
		return NULL;
	return CreateThread(NULL, 0, WorkerThreadRoutine, NULL, 0, NULL);
}

HEDERA_MESSAGE* DoInject(HEDERA_MESSAGE* pMsg) {
	DWORD dwPid = DWORD_PARAM(pMsg, 0);
	DWORD dwTid = DWORD_PARAM(pMsg, 1);
	HANDLE hProcess, hThread;
	WCHAR pImageFilename[MAX_PATH];
	BOOL bInject = FALSE;
	MessageCode respCode = CODE_ERROR;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
	if (hProcess && hThread) {
		DWORD dwSize = sizeof(pImageFilename) / sizeof(WCHAR);
		QueryFullProcessImageNameW(hProcess, 0, pImageFilename, &dwSize);
		HEDERA_MESSAGE* pScriptMsg = CreateSimpleHMessage(CODE_INJECT);
		pScriptMsg->ArgCount = 3;
		pScriptMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG) * pScriptMsg->ArgCount);
		pScriptMsg->Args[0].Size = sizeof(DWORD);
		pScriptMsg->Args[0].Buf = malloc(sizeof(DWORD));
		*(DWORD*)pScriptMsg->Args[0].Buf = dwPid;
		pScriptMsg->Args[1].Size = sizeof(DWORD);
		pScriptMsg->Args[1].Buf = malloc(sizeof(DWORD));
		*(DWORD*)pScriptMsg->Args[1].Buf = dwTid;
		pScriptMsg->Args[2].Size = sizeof(WCHAR) * dwSize;
		pScriptMsg->Args[2].Buf = malloc(sizeof(WCHAR) * dwSize);
		memcpy(pScriptMsg->Args[2].Buf, pImageFilename, sizeof(WCHAR) * dwSize);
		SendHMessage(pScriptMsg, hScriptDataPipe);

		HEDERA_MESSAGE* pScriptResponse = ReceiveHMessage(hScriptDataPipe);
		bInject = pScriptResponse->Code == CODE_OK;

		DestroyHMessage(pScriptMsg);
		DestroyHMessage(pScriptResponse);

		if (bInject) {
			log("monitor binject yes\n");
			HANDLE hOldCmdPipe = hCmdPipe;
			HANDLE hOldTargetDataPipe = hTargetDataPipe;
			hCmdPipe = INVALID_HANDLE_VALUE;
			hTargetDataPipe = INVALID_HANDLE_VALUE;

			pScriptMsg = CreateSimpleHMessage(CODE_INIT);
			SendHMessage(pScriptMsg, hScriptDataPipe);
			pScriptResponse = ReceiveHMessage(hScriptDataPipe);
			DestroyHMessage(pScriptMsg);
			DestroyHMessage(pScriptResponse);

			HANDLE hWorkerThread = SetupSession(hProcess, hThread);
			if (hWorkerThread) {
				log("session ok\n");
			}

			CloseHandle(hOldCmdPipe);
			CloseHandle(hOldTargetDataPipe);

			SetupTargetCommandChannel();
			return NULL;
		}
	}
	return CreateSimpleHMessage(respCode);
}

BOOL Communicate() {
	log("monitor target comm\n");
	if (hTargetDataPipe == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	if (ConnectNamedPipe(hTargetDataPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
		while (TRUE) {
			HEDERA_MESSAGE* pMsg = ReceiveHMessage(hTargetDataPipe);
			if (!pMsg)
				break;

			HEDERA_MESSAGE* pResponse = NULL;
			log("monitor target message %x\n", pMsg->Code);
			switch (pMsg->Code) {
			case CODE_INIT:
				pResponse = CreateSimpleHMessage(CODE_OK);
				pResponse->ArgCount = 1;
				pResponse->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG));
				pResponse->Args[0].Buf = malloc(sizeof(int));
				*(int*)pResponse->Args[0].Buf = savedCount;
				pResponse->Args[0].Size = sizeof(int);
				break;
			case CODE_HOOK_DATA:
				SendHMessage(pMsg, hScriptDataPipe);
				pResponse = ReceiveHMessage(hScriptDataPipe);
				break;
			case CODE_INJECT:
				pResponse = DoInject(pMsg);
				break;
			default:
				pResponse = CreateSimpleHMessage(CODE_ERROR);
				break;
			}

			DestroyHMessage(pMsg);
			if (pResponse) {
				SendHMessage(pResponse, hTargetDataPipe);
				DestroyHMessage(pResponse);
			}
			else
				break;
		}
		log("monitor target thread done\n");
	}
	return TRUE;
}