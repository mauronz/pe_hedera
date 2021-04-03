#pragma once

#include <Windows.h>

HANDLE CreateWorkerThread(DWORD dwPid, DWORD dwTid);
BOOL Communicate();