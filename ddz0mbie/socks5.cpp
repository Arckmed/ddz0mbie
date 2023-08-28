#include "socks5.h"


bool sendData(SOCKET fd, void* data, int len)
{
	char* ptr = (char*)data;

	while(len > 0)
	{
		int sent = send(fd, ptr, len, 0);
		if(sent <= 0)
		{
			// printf("send() error: %d\n", WSAGetLastError());
			return false;
		}
		ptr += sent;
		len -= sent;
	}

	return true;
}

int recvData(SOCKET fd, void* data, int len, bool disconnectOk)
{
	char* ptr = (char*)data;
	int total = 0;

	while(len > 0)
	{
		int recvd = recv(fd, ptr, len, 0);
		if(recvd < 0)
		{
			// printf("recv() error: %d\n", WSAGetLastError());
			return -1;
		}
		if(recvd == 0)
		{
			if(disconnectOk)
				break;
			// printf("disconnected\n");
			return -1;
		}
		total = recvd;
		ptr += recvd;
		len -= recvd;
		total -= recvd;
	}

	return total;
}

bool sendDataUdpAssociate(SOCKET fd, void* data, int len, sockaddr_in target)
{
	char* ptr = (char*)data;

	socks5_udp_hdr req;
	req.Reserved = 0;
	req.Frag = 0;
	req.AddressType = 1;
	req.IPv4 = target.sin_addr;
	req.DestPort = target.sin_port;
	memcpy(req.data, ptr, len);

	while(len > 0)
	{
		int sent = send(fd, (char*)&req, sizeof(socks5_udp_hdr) - 1400 + len, 0);
		if(sent <= 0)
		{
			// printf("send() udp error: %d\n", WSAGetLastError());
			return false;
		}
		ptr += sent;
		len -= sent;
	}

	return true;
}

int recvDataUdpAssociate(SOCKET fd, void* data, int len, bool disconnectOk)
{
	char* ptr = (char*)data;
	int total = 0;
	int length = len + 10;
	int recvd;

	socks5_udp_hdr req;
	recvd = recv(fd, (char*)&req, length, 0);

	if(recvd < 0)
		return -1;

	if(recvd == 0)
	{
		if(disconnectOk)
			return 0;
		// printf("udp closed\n");
		return -1;
	}

	memcpy(data, req.data, 1400);
	total += recvd - 0xA; // header
	return total;
}

bool sendDataConnless(SOCKET fd, void* data, int len, struct sockaddr_in& sAddr)
{
	socks5_udp_hdr req;
	req.Reserved = 0;
	req.Frag = 0;
	req.AddressType = 1;
	req.IPv4 = sAddr.sin_addr;
	req.DestPort = sAddr.sin_port;
	memcpy(req.data, data, len);

	int size = sizeof(req);

	while(size > 0)
	{
		int sent = sendto(fd, (const char*)&req, sizeof(req), 0, (SOCKADDR*)&sAddr, sizeof(sAddr));
		if(sent <= 0)
		{
			// printf("send() connless error: %d", WSAGetLastError());
			return false;
		}
		size -= sent;
	}
	return true;
}

int recvDataConnless(SOCKET fd, void* data, int len, sockaddr_in from, int fromlen, bool disconnectOk)
{
	socks5_udp_hdr rep;
	char* ptr = (char*)data;
	int total = 0;

	while(len > 0)
	{
		int recvd = recvfrom(fd, (char*)&rep, sizeof(rep), 0, (SOCKADDR*)&from, &fromlen);
		ptr = (char*)rep.data;
		if(recvd < 0)
		{
			// printf("recv() conless error: %d", WSAGetLastError());
			return -1;
		}
		if(recvd == 0)
		{
			if(disconnectOk)
				break;
			// printf("disconnected\n");
			return -1;
		}
		ptr += recvd;
		len -= recvd;
		total -= recvd;
	}

	return total;
}

bool socks5Auth(SOCKET fd)
{
	socks5_ident_req req;
	socks5_ident_rep rep;

	req.Version = 5;
	req.NumberOfMethods = 1;
	req.Methods[0] = 0x00;

	// first request
	if(!sendData(fd, &req, 2 + req.NumberOfMethods))
	{
		// printf("could not send auth data\n");
		return false;
	}

	// first repply
	if(recvData(fd, &rep, sizeof(rep)) == -1)
	{
		// printf("could not receive auth data\n");
		return false;
	}

	if(rep.Version != 5)
	{
		// printf("SOCKS v5 - identification failed - Version != 5\n");
		return false;
	}

	if(rep.Method == 0xFF)
	{
		// printf("SOCKS v5 - no acceptable methods\n");
		return false;
	}

	if(rep.Method == 0x00)
	{
		// printf("SOCKS v5 - no authentication required!\n");
		return true;
	}

	return false;
}

bool socks5Request(SOCKET fd, const socks5_req& req, socks5_rep& rep)
{
	if(!sendData(fd, (void*)&req, sizeof(socks5_rep)))
		return false;

	if(recvData(fd, &rep, sizeof(socks5_rep)) == -1)
		return false;

	return true;
}

bool socks5StartRequest(SOCKET fd, const sockaddr_in addr, socks5_rep& rep)
{
	socks5_req req;
	req.Version = 5;
	req.Cmd = 3; // UDP ASSOCIATE
	req.Reserved = 0;
	req.AddrType = 1;
	req.DstAddr = addr.sin_addr;
	req.DestPort = addr.sin_port;

	if(!socks5Request(fd, req, rep))
	{
		// printf("socks5 request failed\n");
		return false;
	}

	if(rep.Reply != 0x00)
	{
		// printf("SOCKS v5 connect failed, error: 0x%02X\n", rep.Reply);
		return false;
	}

	if(rep.BindAddr.s_net == 127 || rep.BindAddr.s_net == 10 || rep.BindAddr.s_net == 192 ||
		rep.BindAddr.s_net == 172 || rep.BindAddr.s_net == 169 || rep.BindAddr.s_net == 224 ||
		rep.BindAddr.s_net == 0)
	{
		// printf("SOCKS5 rough implementation, copying server IP to the reply - most likely will drop the datagrams)..\n");
		rep.BindAddr = addr.sin_addr;
	}

	// printf("SOCKS5 request succeeded\n");
	return true;
}