#pragma once

#include <Windows.h>

HANDLE CreateMonitorThread();
BOOL MonitorCommunicate(HANDLE hPipe);
VOID SetupTargetCommandChannel();