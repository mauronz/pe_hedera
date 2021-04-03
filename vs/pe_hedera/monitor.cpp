#include "global.h"
#include "monitor.h"
#include "peb.h"
#include "ntdef.h"
#include "monitor_handlers.h"
#include "target_handlers.h"
#include "communication.h"
#include <stdio.h>

#define SHELLCODE_SIZE 96
#define MAX_THREAD_COUNT 1000

extern HANDLE hScriptPipe;
extern HANDLE hCmdPipe;
extern HANDLE hTargetDataPipe;

HANDLE hTargetProcess;
HANDLE hTargetMainThread;
LPVOID pTargetBaseAddress;

HANDLE hSemaphore;
HANDLE hThreadCountMutex;
DWORD dwThreadCount = 0;

DWORD dwDllPathSize = 0;
WCHAR pDllPath[MAX_PATH];

WCHAR* pScriptPipeName = NULL;

INJECT_CONFIG config;

BOOL SetEntrypointHook(HANDLE hProcess) {
	SIZE_T written;
	TdefNtQueryInformationProcess _NtQueryInformationProcess;
	LPVOID pRemoteAddress;
	PROCESS_BASIC_INFORMATION pbInfo;
	DWORD dwSize;
	PEB peb;
	PIMAGE_NT_HEADERS pNtHeaders;
	BYTE pHeaderBuffer[0x400];
	DWORD dwEntrypoint;
	BYTE pShellcode[0x200];
	DWORD dwOffset = 0;
	DWORD dwOldProtect;
	WCHAR pImageFilename[MAX_PATH];
	dwSize = MAX_PATH;
	QueryFullProcessImageNameW(hProcess, 0, pImageFilename, &dwSize);

	if (dwDllPathSize == 0) {
		GetModuleFileNameW(NULL, pDllPath, MAX_PATH);
		PWCHAR pTmp = wcsrchr(pDllPath, '\\') + 1;
		WCHAR pDllName[] = L"leaf.dll";
		memcpy(pTmp, pDllName, (wcslen(pDllName) + 1) * sizeof(WCHAR));
		dwDllPathSize = wcslen(pDllPath);
	}

	_NtQueryInformationProcess = (TdefNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (_NtQueryInformationProcess(hProcess, 0, &pbInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize)) {
		log("[-] Error NtQueryInformationProcess\n");
		return FALSE;
	}
	ReadProcessMemory(hProcess, pbInfo.PebBaseAddress, &peb, sizeof(PEB), &dwSize);
	pTargetBaseAddress = peb.ImageBaseAddress;
	ReadProcessMemory(hProcess, peb.ImageBaseAddress, pHeaderBuffer, sizeof(pHeaderBuffer), &dwSize);
	pNtHeaders = (PIMAGE_NT_HEADERS)(pHeaderBuffer + ((PIMAGE_DOS_HEADER)pHeaderBuffer)->e_lfanew);
	dwEntrypoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	pRemoteAddress = VirtualAllocEx(hProcess, NULL, 0x200, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pRemoteAddress) {
		log("[-] Error allocating remote memory\n");
		return FALSE;
	}

	/*
	mov eax, dword ptr [XXXX]
	mov ecx, XXXX
	mov [ecx], eax
	mov al, byte ptr [XXXX]
	add ecx, 4
	mov byte ptr [ecx], al
	*/
	BYTE pCustomMemcpy[] = { 0xA1, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x89, 0x01, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC1, 0x04, 0x88, 0x01 };
	*(DWORD *)(pCustomMemcpy + 1) = (DWORD)pRemoteAddress + SHELLCODE_SIZE + 4;
	*(DWORD *)(pCustomMemcpy + 6) = (DWORD)peb.ImageBaseAddress + dwEntrypoint;
	*(DWORD *)(pCustomMemcpy + 13) = (DWORD)pRemoteAddress + SHELLCODE_SIZE + 4 + 4;

	// mov eax, offset oldprotect
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, PAGE_EXECUTE_READWRITE
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = PAGE_EXECUTE_READWRITE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, 5
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = 5;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, entrypoint
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// call VirtualProtect
	pShellcode[dwOffset++] = 0xe8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)VirtualProtect - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	CopyMemory(pShellcode + dwOffset, pCustomMemcpy, sizeof(pCustomMemcpy));
	dwOffset += sizeof(pCustomMemcpy);

	// mov eax, offset oldprotect
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, oldprotect
	// push eax
	pShellcode[dwOffset++] = 0xa1;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, 5
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = 5;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// mov eax, entrypoint
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// call VirtualProtect
	pShellcode[dwOffset++] = 0xe8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)VirtualProtect - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	// mov eax, offset libname
	// push eax
	pShellcode[dwOffset++] = 0xb8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)pRemoteAddress + SHELLCODE_SIZE + 9;
	dwOffset += sizeof(DWORD);
	pShellcode[dwOffset++] = 0x50;

	// call LoadLibraryW
	pShellcode[dwOffset++] = 0xe8;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)LoadLibraryW - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	// jmp entrypoint
	pShellcode[dwOffset++] = 0xe9;
	*(DWORD *)(pShellcode + dwOffset) = (DWORD)peb.ImageBaseAddress + dwEntrypoint - ((DWORD)pRemoteAddress + dwOffset + 4);
	dwOffset += sizeof(DWORD);

	// Leave  space for oldprotect
	dwOffset += 4;

	// Read original first 5 bytes at entrypoint
	ReadProcessMemory(hProcess, (PBYTE)peb.ImageBaseAddress + dwEntrypoint, pShellcode + dwOffset, 5, &written);
	dwOffset += 5;

	CopyMemory(pShellcode + dwOffset, pDllPath, dwDllPathSize * sizeof(WCHAR));

	if (!WriteProcessMemory(hProcess, pRemoteAddress, pShellcode, dwOffset + dwDllPathSize * sizeof(WCHAR), &written)) {
		log("[-] Error writing the shellcode\n");
		return FALSE;
	}

	PVOID pRemoteEntrypoint = (PBYTE)peb.ImageBaseAddress + dwEntrypoint;
	if (!VirtualProtectEx(hProcess, pRemoteEntrypoint, 5, PAGE_READWRITE, &dwOldProtect)) {
		log("[-] Error changing entrypoint protection\n");
		return FALSE;
	}

	// jmp shellcode
	pShellcode[0] = 0xe9;
	*(DWORD *)(pShellcode + 1) = (DWORD)pRemoteAddress - ((DWORD)peb.ImageBaseAddress + dwEntrypoint + 5);
	WriteProcessMemory(hProcess, pRemoteEntrypoint, pShellcode, 5, &written);

	if (!VirtualProtectEx(hProcess, pRemoteEntrypoint, 5, dwOldProtect, &dwOldProtect)) {
		log("[-] Error resetting entrypoint protection\n");
		return FALSE;
	}

	return TRUE;
}

VOID PrintUsage(WCHAR *argv0) {
	wprintf(L"Usage: %s [options] /pipe pipe_name target_command_line\n\n\
Example: %s /all /pipe \\\\.\\pipe\\hederapipe notepad.exe mytextfile.txt\n\n\
Options:\n\
/all:\n\
    Inject into newly created processes without asking for confirmation.", argv0, argv0);
}

HANDLE SetupSession(HANDLE hProcess, HANDLE hThread) {
	if (!SetEntrypointHook(hProcess))
		return NULL;
	hTargetProcess = hProcess;
	hTargetMainThread = hThread;
	hTargetDataPipe = CreateThreadPipe(GetProcessId(hProcess), GetThreadId(hThread), PIPE_TEMPLATE_LEAF_DATA);
	return CreateWorkerThread(GetProcessId(hProcess), GetThreadId(hThread));
}

int wmain(int argc, WCHAR **argv) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	LPWSTR pTargetCmd;
	LPWSTR pCmdline = GetCommandLineW();
	BOOL bRunning = TRUE, bPrintUsage = FALSE;
	int i = 1;

	hSemaphore = CreateSemaphoreW(NULL, 0, MAX_THREAD_COUNT, NULL);
	hThreadCountMutex = CreateMutexW(NULL, FALSE, NULL);

	config.AllProcesses = FALSE;

	if (argc == 1)
		bPrintUsage = TRUE;

	while (i < argc && !bPrintUsage) {
		if (!wcscmp(argv[i], L"/all")) {
			config.AllProcesses = TRUE;
			i += 1;
		} else if (!wcscmp(argv[i], L"/pipe")) {
			pScriptPipeName = argv[i + 1];
			i += 2;
		}
		else
			break;
	}

	if (!pScriptPipeName)
		bPrintUsage = TRUE;

	if (i >= argc)
		bPrintUsage = TRUE;

	if (bPrintUsage) {
		PrintUsage(argv[0]);
	}
	else {
		hScriptPipe = CreateFileW(pScriptPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		//hScriptPipe = CreateThreadPipe(0, 0, pScriptPipeName);
		if (hScriptPipe == INVALID_HANDLE_VALUE) {
			log("[-] Error opening pipe\n");
			return 2;
		}

		pTargetCmd = wcsstr(pCmdline, argv[i]);
		if (*(pTargetCmd - 1) == '"')
			pTargetCmd--;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&si, sizeof(pi));
		if (!CreateProcessW(NULL, pTargetCmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			log("[-] Error creating process\n");
			CloseHandle(hScriptPipe);
			return 1;
		}

		HANDLE hThread = SetupSession(pi.hProcess, pi.hThread);

		HANDLE hMonitorThread = CreateMonitorThread();
		WaitForSingleObject(hMonitorThread, INFINITE);
		if (hTargetDataPipe)
			CloseHandle(hTargetDataPipe);
	}

	return 0;
}