#pragma once
#include <Windows.h>

#define PIPE_TEMPLATE_LEAF_CMD L"\\\\.\\pipe\\leaf_cmd_%08x%08x"
#define PIPE_TEMPLATE_LEAF_DATA L"\\\\.\\pipe\\leaf_data_%08x%08x"

#define HT_BEFORE 0
#define HT_AFTER 1

enum MessageCode {
	CODE_ERROR=0x2000,
	CODE_OK,
	CODE_INJECT,
	CODE_THREAD,
	CODE_INIT,
	CODE_HOOK_DATA,

	CODE_START=0x4000,
	CODE_SET_HOOK_NAME,
	CODE_SET_HOOK_ADDR,
	CODE_REMOVE_HOOK,
	CODE_READ_MEM,
	CODE_WRITE_MEM,
	CODE_STOP
};

typedef struct _HEDERA_ARG {
	int Size;
	PVOID Buf;
} HEDERA_ARG;

typedef struct _HEDERA_MESSAGE {
	MessageCode Code;
	int ArgCount;
	HEDERA_ARG* Args;
} HEDERA_MESSAGE;

#define DWORD_PARAM(pMsg, num) *(DWORD*)(pMsg->Args[num].Buf)
#define PTR_PARAM(pMsg, num) *(LPVOID*)(pMsg->Args[num].Buf)

typedef struct _inject_config {
	BOOL AllProcesses;
} INJECT_CONFIG;

PBYTE SerializeHMessage(HEDERA_MESSAGE* pMsg, int* serialSize);
MessageCode PeekHMessageCode(PBYTE pBuf);
HEDERA_MESSAGE* ParseHMessage(PBYTE pBuf);
BOOL SendHMessage(HEDERA_MESSAGE* pMsg, HANDLE hPipe);
HEDERA_MESSAGE* ReceiveHMessage(HANDLE hPipe);
HEDERA_MESSAGE* CreateSimpleHMessage(MessageCode code);
HEDERA_MESSAGE* CreateEmptyHMessage();
VOID DestroyHMessage(HEDERA_MESSAGE* msg);
HANDLE CreateThreadPipe(DWORD dwPid, DWORD dwTid, LPCWSTR pTemplate);