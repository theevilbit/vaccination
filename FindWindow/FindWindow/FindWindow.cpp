// FindWindow.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"

int main()
{
	HWND nHwnd_olly = FindWindow((LPCWSTR)L"OLLYDBG", NULL);
	HWND nHwnd_windbg = FindWindow((LPCWSTR)L"WinDbgFrameClass", NULL);

	if (nHwnd_olly == NULL)
	{
		printf("Olly window not found\n");
	}
	else
	{
		printf("Olly window found\n");
	}

	if (nHwnd_windbg == NULL)
	{
		printf("WinDBG window not found\n");
	}
	else
	{
		printf("WinDBG window found\n");
	}
    return 0;
}

