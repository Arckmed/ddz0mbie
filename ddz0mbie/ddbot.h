#pragma once
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <string>
#include <thread>
#include <chrono>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include "socks5.h"
#include "control.h"

using namespace std::chrono_literals;

#define HUFFMAN_LUTBITS		(10)
#define HUFFMAN_LUTSIZE 	(1<<HUFFMAN_LUTBITS)

static const UCHAR MAGIC[] = { 'T', 'K', 'E', 'N' };

enum
{
	NETSENDFLAG_VITAL = 1,
	NETSENDFLAG_CONNLESS = 2,
	NETSENDFLAG_FLUSH = 4
};

enum
{
	STATE_CONNECTING = 1,
	STATE_LOADING,
	STATE_ONLINE
};

long long time_freq();
const UCHAR* cviUnpack(const UCHAR* pSrc, int* pInOut);
UCHAR* Unpack(UCHAR* pData, int* flag, int* size, int* seq);
UCHAR* cviPack(UCHAR* pDst, int i);
int gen_random_int();

class DDZombie
{
	struct CMsgPacker
	{
		UCHAR m_aBuffer[(1024 * 2)], * mpc, * m_pEnd;
		int Size() const { return (int)(mpc - m_aBuffer); }
		void AddInt(int i) { mpc = cviPack(mpc, i); }
		void AddString(const char* pStr, int Limit)
		{
			for(; *pStr && Limit != 0; Limit--)
				*mpc++ = *pStr++;
			*mpc++ = 0;
		}
		CMsgPacker(int Type)
		{
			mpc = m_aBuffer;
			AddInt(Type);
		}
	};

	struct SnapShotItem
	{
		int typeAndID;
		int* Data() { return (int*)(this + 1); }
		int Type() { return typeAndID >> 16; }
		int ID() { return typeAndID & 0xffff; }
		int Key() { return typeAndID; }
	};

	struct Snapshot
	{
		int d_size, numItems;
		int* Offsets() const { return (int*)(this + 1); }
		char* DataStart() const { return (char*)(Offsets() + numItems); }
	};

	struct ClientData
	{
		char m_aName[16];
		int m_Team;
	};

	struct Holder
	{
		Holder* prev, * next;
		long long tagTime;
		int tick, snapSize;
		Snapshot* snap, * altSnap;
	};

	struct CNode
	{
		unsigned m_Bits, m_NumBits;
		unsigned short m_aLeafs[2];
		UCHAR m_Symbol;
	};

	struct CHuffmanConstructNode
	{
		unsigned short m_NodeId;
	};

	ClientData clients[64];
	Holder* m_pFirst, * m_pLast, * m_ss[2];  /* 0 = current, 1 = previous */
	CNode  m_aNodes[(257 * 2 - 1)], * m_apDecodeLut[HUFFMAN_LUTSIZE], * m_pStartNode;
	UCHAR r_cdata[(1400 - 6)], c_cdata[(1400 - 6)];
	Snapshot emptySnap;
	static std::atomic<int> totalConnected;

	int new_tick = -1;
	int c_flags, c_numc, c_dsize, mstate, astate, ss_parts, s_token, crecv_tick, m_ReceivedSnapshots;
	int d_size, offs[1024], numItems, nnodes, r_cchunk, m_ddsent, r_flags, r_ack, r_numc, r_dsize, bodycolor, feetcolor;
	long long last_stime;
	unsigned short m_seq, m_Ack, m_PeerAck;
	char m_bData[65536], nickname[16], skin[16];
	bool r_Valid;
	char data[4];
	long long last = 0;

	int id = 0;

	sockaddr_in targetAddr;
	SOCKET udpSocket = 0, tcpSocket = 0;

	long long notRecvd;
	bool notRecvdDisconnect;

	long long time_get();
	void* NewItem(int Type, int ID, int Size);
	void Setbits_r(CNode* pNode, int Bits, unsigned Depth);
	void SendPacket(SOCKET Socket, int flags, int ack, int numc, int datasize, UCHAR* data, int SecurityToken);
	void Flush();
	void SendControl(int ControlMsg, const void* pExtra, int ExtraSize);
	int RecvPacket(int* flags, int* datasize, void** data);
	int SendMsgEx(CMsgPacker* pMsg, int Flags, bool sys);
	void handle_snapshot(int parts, int Part, int psize, int GameTick, int DeltaTick, char* pData);
	void GenRandomData();

public:
	int Init(std::string ip, int id);
	void Start();
};

