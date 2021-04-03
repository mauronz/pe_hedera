#include "global.h"
#include "communication.h"
#include <stdio.h>

#define BUFSIZE 1024

PBYTE SerializeHMessage(HEDERA_MESSAGE* pMsg, int* serialSize) {
	int size = 4 + 4 + 4;
	for (int i = 0; i < pMsg->ArgCount; i++) {
		size += 4 + pMsg->Args[i].Size;
	}

	PBYTE pResult = (PBYTE)malloc(size);
	PBYTE pPtr = pResult;
	*(int*)pPtr = size - 4;
	pPtr += 4;
	*(MessageCode*)pPtr = pMsg->Code;
	pPtr += 4;
	*(int*)pPtr = pMsg->ArgCount;
	pPtr += 4;

	for (int i = 0; i < pMsg->ArgCount; i++) {
		*(int*)pPtr = pMsg->Args[i].Size;
		pPtr += 4;
		memcpy(pPtr, pMsg->Args[i].Buf, pMsg->Args[i].Size);
		pPtr += pMsg->Args[i].Size;
	}
	*serialSize = size;
	return pResult;
}

MessageCode PeekMessageCode(PBYTE pBuf) {
	return *(MessageCode*)(pBuf + 4);
}

HEDERA_MESSAGE* ParseHMessage(PBYTE pBuf) {
	HEDERA_MESSAGE* pMsg = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pMsg->Code = *(MessageCode*)pBuf;
	pBuf += 4;
	pMsg->ArgCount = *(int*)pBuf;
	pMsg->Args = NULL;
	pBuf += 4;
	if (pMsg->ArgCount > 0) {
		pMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG) * pMsg->ArgCount);
		for (int i = 0; i < pMsg->ArgCount; i++) {
			int argSize = *(int*)pBuf;
			pBuf += 4;
			pMsg->Args[i].Buf = malloc(argSize);
			memcpy(pMsg->Args[i].Buf, pBuf, argSize);
			pMsg->Args[i].Size = argSize;
			pBuf += argSize;
		}
	}
	return pMsg;
}

BOOL SendHMessage(HEDERA_MESSAGE* pMsg, HANDLE hPipe) {
	int size = 0;
	PBYTE pBuf = SerializeHMessage(pMsg, &size);

	DWORD dwWritten = 0;
	BOOL res = WriteFile(hPipe, pBuf, size, &dwWritten, NULL) && dwWritten == size;
	free(pBuf);
	return res;
}

HEDERA_MESSAGE* ReceiveHMessage(HANDLE hPipe) {
	int size = 0;
	DWORD dwRead = 0;
	HEDERA_MESSAGE* pMsg = NULL;
	//BOOL r = ReadFile(hPipe, &size, 4, &dwRead, NULL);
	if (!((ReadFile(hPipe, &size, 4, &dwRead, NULL) || GetLastError() == ERROR_MORE_DATA)  && dwRead == 4)) {
		DWORD err = GetLastError();
		return NULL;
	}
	PBYTE pBuf = (PBYTE)malloc(size);

	if (ReadFile(hPipe, pBuf, size, &dwRead, NULL) && dwRead == size)
		pMsg = ParseHMessage(pBuf);

	free(pBuf);
	return pMsg;
}

HEDERA_MESSAGE* CreateEmptyHMessage() {
	HEDERA_MESSAGE* pMsg = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pMsg->Args = (HEDERA_ARG*)malloc(sizeof(HEDERA_ARG));
	return pMsg;
}

HEDERA_MESSAGE* CreateSimpleHMessage(MessageCode code) {
	HEDERA_MESSAGE* pMsg = (HEDERA_MESSAGE*)malloc(sizeof(HEDERA_MESSAGE));
	pMsg->Code = code;
	pMsg->ArgCount = 0;
	pMsg->Args = NULL;
	return pMsg;
}

VOID DestroyHMessage(HEDERA_MESSAGE* msg) {
	for (int i = 0; i < msg->ArgCount; i++)
		free(msg->Args[i].Buf);
	free(msg->Args);
	free(msg);
}

HANDLE CreateThreadPipe(DWORD dwPid, DWORD dwTid, LPCWSTR pTemplate) {
	WCHAR pPipeName[64];
	wsprintfW(pPipeName, pTemplate, dwPid, dwTid);
	HANDLE hPipe = CreateNamedPipeW(
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

	wlog(L"create pipe %s %x\n", pPipeName, hPipe);
	return hPipe;
}