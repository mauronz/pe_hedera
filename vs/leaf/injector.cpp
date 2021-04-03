// injector.cpp : Defines the exported functions for the DLL application.
//

#include "injector.h"
#include "hooks.h"
#include "APIhooklib.h"
#include "communication.h"
#include "functions.h"

extern HMODULE hGlobalModule;
extern INJECT_CONFIG config;

TypedefNtCreateUserProcess pOrigNtCreateUserProcess = NULL;
TypedefNtResumeThread pOrigNtResumeThread = NULL;

BOOL SetHooks() {
	//_NtResumeThread = (TypedefNtResumeThread)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtResumeThread");
	pOrigNtResumeThread = (TypedefNtResumeThread)SetHookByName((LPSTR)"ntdll.dll", (LPSTR)"NtResumeThread", 2, CV_STDCALL, (FARPROC)bh_NtResumeThread, NULL, TRUE, FALSE, FALSE);
	pOrigNtCreateUserProcess = (TypedefNtCreateUserProcess)SetHookByName((LPSTR)"ntdll.dll", (LPSTR)"NtCreateUserProcess", 11, CV_STDCALL, (FARPROC)bh_NtCreateUserProcess, NULL, FALSE, TRUE, FALSE);
	return TRUE;
}