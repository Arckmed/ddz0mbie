#pragma once
#include <winsock2.h>
#include <stdio.h>
#include <WS2tcpip.h>
#include <stdlib.h>
#include <iostream>
#pragma comment(lib,"ws2_32.lib") 

// https://www.rfc-editor.org/rfc/rfc1928

/*
	"The DST.ADDR and
	DST.PORT fields contain the address and port that the client expects
	to use to send UDP datagrams on for the association.  The server MAY
	use this information to limit access to the association.  If the
	client is not in possesion of the information at the time of the UDP
	ASSOCIATE, the client MUST use a port number and address of all
	zeros." 

	"Usually, all personal users are NAT,
	 so there is no way to determine the public IP and port they will use before sending.
	 In this case, the client MUST use a port number and address of all zeros.
	 More details read the this method comments,
	 or go to https://tools.ietf.org/html/rfc1928 then search "zeros" keyword."

	 "In the Internet world, a considerable number of SOCKS5 servers have incorrect UDP Associate implementation.
	 According to the description of UDP Association in RFC 1928: 'In the reply to a UDP ASSOCIATE request, the BND.PORT
	 and BND.ADDR fields indicate the port number/address where the client MUST send UDP request messages to be relayed.',
	 the server should respond its public IP address. If the server has multiple public IP
	 addresses, the server should decide which public IP to respond according to its own strategy.
	 However, most SOCKS5 servers implementations are very rough. They often use some private addresses as BND.ADDR
	 respond to the client, such as 10.0.0.1, 172.16.1.1, 192.168.1.1 and so on (even 0.0.0.0). In this case, the UDP packet sent by
	 the client cannot reach the server at all, unless the client and the SOCKS5 server are in the same LAN.
	 Therefore, through this callback, the client can according to the received BND.ADDR to determine whether this
	 address is a private address. If true is returned, the client will send UDP packet to ServerAddress:BND.PORT;
	 If false is returned, it will send UDP packet to BND.ADDR:BND.PORT."


	 https://github.com/ginuerzh/gost/issues/96
*/

struct socks5_ident_req
{
	unsigned char Version;
	unsigned char NumberOfMethods;
	unsigned char Methods[255];
};

struct socks5_ident_rep
{
	unsigned char Version;
	unsigned char Method;
};

struct socks5_req
{
	unsigned char Version;
	unsigned char Cmd;
	unsigned char Reserved;
	unsigned char AddrType;
	in_addr DstAddr;
	unsigned short DestPort; // sent in network byte order
};

#pragma pack(push, 1)
struct socks5_rep
{
	unsigned char Version;
	unsigned char Reply;
	unsigned char Reserved;
	unsigned char AddrType;
	in_addr BindAddr;
	unsigned short BindPort; // arrives in network byte order 
};
#pragma pack(pop)

#pragma pack(push, 1)
struct socks5_udp_hdr
{
	unsigned short Reserved;
	unsigned char Frag;
	unsigned char AddressType;
	in_addr IPv4;
	unsigned short DestPort;
	unsigned char data[1400];
};
#pragma pack(pop)

bool sendData(SOCKET fd, void* data, int len);

int recvData(SOCKET fd, void* data, int len, bool disconnectOk = false);

bool sendDataUdpAssociate(SOCKET fd, void* data, int len, sockaddr_in target);

int recvDataUdpAssociate(SOCKET fd, void* data, int len, bool disconnectOk = false);

bool sendDataConnless(SOCKET fd, void* data, int len, struct sockaddr_in& recvAddr);

int recvDataConnless(SOCKET fd, void* data, int len, sockaddr_in from, int fromlen, bool disconnectOk = false);

bool socks5Auth(SOCKET fd);

bool socks5Request(SOCKET fd, const socks5_req& req, socks5_rep& rep);

bool socks5StartRequest(SOCKET fd, const sockaddr_in addr, socks5_rep& rep);