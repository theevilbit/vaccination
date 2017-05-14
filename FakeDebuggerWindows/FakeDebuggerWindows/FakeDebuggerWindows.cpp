// FakeDebuggerWindows.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "FakeDebuggerWindows.h"

#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>

//window program source: https ://msdn.microsoft.com/en-us/library/windows/desktop/ff381409(v=vs.85).aspx
LRESULT CALLBACK OllyWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WindbgWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
	// Register the window class.
	const wchar_t CLASS_NAME_OLLY[] = L"OLLYDBG";
	WNDCLASS wc_olly = {};
	wc_olly.lpfnWndProc = OllyWindowProc;
	wc_olly.hInstance = hInstance;
	wc_olly.lpszClassName = CLASS_NAME_OLLY;
	RegisterClass(&wc_olly);

	const wchar_t CLASS_NAME_WINDBG[] = L"WinDbgFrameClass";
	WNDCLASS wc_windbg = {};
	wc_windbg.lpfnWndProc = WindbgWindowProc;
	wc_windbg.hInstance = hInstance;
	wc_windbg.lpszClassName = CLASS_NAME_WINDBG;
	RegisterClass(&wc_windbg);

	// Create the windows.
	HWND hwnd_Olly = CreateWindowEx(
		0,                              // Optional window styles.
		CLASS_NAME_OLLY,                     // Window class
		L"OllyDBG",    // Window text
		WS_OVERLAPPEDWINDOW,            // Window style
										// Size and position
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL,       // Parent window    
		NULL,       // Menu
		hInstance,  // Instance handle
		NULL        // Additional application data
		);

	HWND hwnd_WinDBG = CreateWindowEx(
		0,                              // Optional window styles.
		CLASS_NAME_WINDBG,                     // Window class
		L"WinDBG",    // Window text
		WS_OVERLAPPEDWINDOW,            // Window style
										// Size and position
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL,       // Parent window    
		NULL,       // Menu
		hInstance,  // Instance handle
		NULL        // Additional application data
		);

	//If either of the windows couldn't be created, exit
	if ((hwnd_Olly == NULL) || (hwnd_WinDBG == NULL))
	{
		return 0;
	}
	//ShowWindow(hwnd, nCmdShow);

	// Run the message loop.
	MSG msg = {};
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

LRESULT CALLBACK OllyWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);

		FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

		EndPaint(hwnd, &ps);
	}
	return 0;

	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WindbgWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);

		FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

		EndPaint(hwnd, &ps);
	}
	return 0;

	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
