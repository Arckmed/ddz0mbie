#include "ddbot.h"

long long time_freq()
{
	long long t;
	QueryPerformanceFrequency((PLARGE_INTEGER)&t);
	return t;
}

const UCHAR* cviUnpack(const UCHAR* pSrc, int* pInOut)
{
	int Sign = (*pSrc >> 6) & 1;
	*pInOut = *pSrc & 0x3F;
	for(int i = 6; i <= 27 && *pSrc & 0x80; i += 7)
		*pInOut |= (*++pSrc & (0x7F)) << (i);
	*pInOut ^= -Sign; // if(sign) *i = ~(*i)
	return pSrc + 1;
}

UCHAR* Unpack(UCHAR* pData, int* flag, int* size, int* seq)
{
	*flag = (pData[0] >> 6) & 3;
	*size = ((pData[0] & 0x3f) << 4) | (pData[1] & 0xf);
	*seq = -1;
	if((*flag) & NETSENDFLAG_VITAL)
	{
		*seq = ((pData[1] & 0xf0) << 2) | pData[2];
		return pData + 3;
	}
	return pData + 2;
}

UCHAR* cviPack(UCHAR* pDst, int i)
{
	*pDst = (i >> 25) & 0x40; // set sign bit if i<0
	i = i ^ (i >> 31); // if(i<0) i = ~i
	*pDst |= i & 0x3F; // pack 6bit into dst
	i >>= 6; // discard 6 bits
	if(i)
	{
		*pDst |= 0x80; // set extend bit
		do
		{
			pDst++;
			*pDst = i & (0x7F); // pack 7bit
			i >>= 7; // discard 7 bits
			*pDst |= (i != 0) << 7; // set extend bit (may branch)
		} while(i);
	}
	pDst++;
	return pDst;
}

int gen_random_int()
{
	unsigned long r = 0;

	for(int i = 0; i < 5; ++i)
	{
		r = (r << 15) | (rand() & 0x7FFF);
	}
	return r & 0xFFFFFF;
}

long long DDZombie::time_get()
{
	last = 0;
	if(new_tick == 0)	return last;
	if(new_tick != -1)	new_tick = 0;
	long long t;
	QueryPerformanceCounter((PLARGE_INTEGER)&t);
	if(t < last) /* for some reason, QPC can return values in the past */
		return last;
	last = t;
	return t;
}

void* DDZombie::NewItem(int Type, int ID, int Size)
{
	if(d_size + sizeof(SnapShotItem) + Size >= 65536 || numItems + 1 >= 1024 || Type >= (1 << 16))
		return 0;
	SnapShotItem* pObj = (SnapShotItem*)(m_bData + d_size);
	memset(pObj, 0, sizeof(SnapShotItem) + Size);
	pObj->typeAndID = (Type << 16) | ID;
	offs[numItems++] = d_size;
	d_size += sizeof(SnapShotItem) + Size;
	return pObj->Data();
}

void DDZombie::Setbits_r(CNode* pNode, int Bits, unsigned Depth)
{
	if(pNode->m_aLeafs[1] != 0xffff)
		Setbits_r(&m_aNodes[pNode->m_aLeafs[1]], Bits | (1 << Depth), Depth + 1);
	if(pNode->m_aLeafs[0] != 0xffff)
		Setbits_r(&m_aNodes[pNode->m_aLeafs[0]], Bits, Depth + 1);
	if(pNode->m_NumBits)
	{
		pNode->m_Bits = Bits;
		pNode->m_NumBits = Depth;
	}
}

void DDZombie::SendPacket(SOCKET Socket, int flags, int ack, int numc, int datasize, UCHAR* data, int SecurityToken)
{
	UCHAR aBuffer[1400]; /* max packet size */
	if(SecurityToken != 0)
	{ /* supported, append security token */
	   // if SecurityToken is -1 (unknown) we will still append it hoping to negotiate it
		memcpy(&data[datasize], &SecurityToken, sizeof(SecurityToken));
		datasize += sizeof(SecurityToken);
	}
	memcpy(&aBuffer[3], data, datasize);
	flags &= ~8; /* compression flag */
	aBuffer[0] = ((flags << 4) & 0xf0) | ((ack >> 8) & 0xf);
	aBuffer[1] = ack & 0xff;
	aBuffer[2] = numc;

	sendDataUdpAssociate(udpSocket, &aBuffer, datasize + 3, targetAddr);
}

void DDZombie::Flush()
{
	if(!c_numc && !c_flags)
		return;
	SendPacket(udpSocket, c_flags, m_Ack, c_numc, c_dsize, c_cdata, s_token);
	last_stime = time_get();
	c_flags = c_dsize = c_numc = 0;
	memset(c_cdata, 0, sizeof(c_cdata));
}

void DDZombie::SendControl(int ControlMsg, const void* pExtra, int ExtraSize)
{
	last_stime = time_get();
	UCHAR buf[(1400 - 6)];
	buf[0] = ControlMsg;
	memcpy(&buf[1], pExtra, ExtraSize);
	SendPacket(udpSocket, 1, m_Ack, 0, 1 + ExtraSize, buf, s_token);
}

int DDZombie::RecvPacket(int* flags, int* datasize, void** data)
{

	while(true)
	{
		int hflags, hsize, hseq, Bytes;
		UCHAR* pEnd = r_cdata + r_dsize;

		while(true)
		{
			UCHAR* pData = r_cdata;

			if(!r_Valid || r_cchunk >= r_numc)
			{
				r_Valid = false;
				break;
			}

			for(int i = 0; i < r_cchunk; i++)
			{
				pData = Unpack(pData, &hflags, &hsize, &hseq);
				pData += hsize;
			}
			pData = Unpack(pData, &hflags, &hsize, &hseq);

			r_cchunk++;

			if(pData + hsize > pEnd)
			{
				r_Valid = false;
				break;
			}

			if((hflags & NETSENDFLAG_VITAL))
			{ // anti spoof
				if(hseq == (m_Ack + 1) % (1 << 10))
				{ /* max sequence */
					m_Ack = hseq;
				}
				else
				{ //IsSeqInBackroom (old packet that we already got)
					int Bottom = (m_Ack - (1 << 10) / 2);
					if(Bottom < 0)
					{
						if((hseq <= m_Ack) || (hseq >= (Bottom + (1 << 10))))
							continue;
					}
					else
					{
						if(hseq <= m_Ack && hseq >= Bottom)
							continue;
					}
					c_flags |= 4; /* resend flag */
					continue; // take the next chunk in the packet
				}
			}
			*flags = hflags;
			*datasize = hsize;
			*data = *(void**)&pData;
			return 1;
		}
		UCHAR sbuf[128] = { 0 }, rbuf[1400]; /* max packet size */
		socklen_t fromlen = sizeof(sockaddr_in);

		if((Bytes = recvDataUdpAssociate(udpSocket, (char*)rbuf, 1400)) <= 0)
		{
			long long Now = time_get(), dif = (Now - notRecvd);
			if(dif > time_freq() * 15)
			{
				// printf("didn't receive, disconnecting...\n");
				notRecvdDisconnect = true;
			}
			break;
		}
		else
		{
			notRecvd = time_get();
		}

		if(Bytes < 3 || Bytes > 1400) /* packet header size */
			continue;

		r_flags = rbuf[0] >> 4;
		r_ack = ((rbuf[0] & 0xf) << 8) | rbuf[1];
		r_numc = rbuf[2];
		r_dsize = Bytes - 3; /* packet header size */

		if((r_flags & 2)) /* connless flag */
			continue;

		if(r_flags & 8)
		{ /* compression flag */

			if(r_flags & 1) /* control flag, don't allow compression */
				return -1;

			UCHAR* pDst = (UCHAR*)r_cdata, * pSrc = (UCHAR*)&rbuf[3];
			UCHAR* pDstEnd = pDst + sizeof(r_cdata), * pSrcEnd = pSrc + r_dsize;
			unsigned Bits = 0, Bitcount = 0;
			CNode* pNode = 0, * pEof = &m_aNodes[256];

			while(true)
			{
				pNode = 0; // {A} try to load a node now
				if(Bitcount >= HUFFMAN_LUTBITS)
					pNode = m_apDecodeLut[Bits & (HUFFMAN_LUTSIZE - 1)];

				while(Bitcount < 24 && pSrc != pSrcEnd)
				{ // {B} fill with new bits
					Bits |= (*pSrc++) << Bitcount;
					Bitcount += 8;
				}

				if(!pNode) // {C} load symbol now if we didn't at location {A}
					pNode = m_apDecodeLut[Bits & (HUFFMAN_LUTSIZE - 1)];

				if(!pNode)
				{
					r_dsize = -1;
					break;
				} // {D} check if we hit a symbol already

				if(pNode->m_NumBits)
				{ // remove the bits for that symbol
					Bits >>= pNode->m_NumBits;
					Bitcount -= pNode->m_NumBits;
				}

				else
				{ // remove the bits that the lut checked up for us
					Bits >>= HUFFMAN_LUTBITS;
					Bitcount -= HUFFMAN_LUTBITS;

					while(1)
					{ /* traverse tree */
						pNode = &m_aNodes[pNode->m_aLeafs[Bits & 1]];
						Bitcount--; /* remove bit */
						Bits >>= 1;
						if(pNode->m_NumBits) /* check if hit symbol */
							break;
						if(Bitcount == 0)
						{ /* no more bits, decode error */
							r_dsize = -1;
							break;
						}
					}
				}

				if(pNode == pEof) /* check for eof */
					break;

				if(pDst == pDstEnd)
				{ /* output character */
					r_dsize = -1;
					break;
				}
				*pDst++ = pNode->m_Symbol;
			}
			r_dsize = (int)(pDst - (const UCHAR*)r_cdata);
		}

		else
			memcpy(r_cdata, &rbuf[3], r_dsize);

		if(r_dsize < 0)
			continue;

		if(s_token != -1 && s_token != 0)
		{ /* check security token */
			if(r_dsize < (int)sizeof(s_token))
				continue;
			r_dsize -= sizeof(s_token);
		}

		// check if actual ack value is valid(own sequence..latest peer ack)
		if(((m_seq >= m_PeerAck) && (r_ack < m_PeerAck || r_ack > m_seq)) ||
			((m_seq < m_PeerAck) && (r_ack < m_PeerAck && r_ack > m_seq)))
			continue;
		m_PeerAck = r_ack; /* control message, connectaccept */

		if((r_flags & 1) && (astate == STATE_CONNECTING) && r_cdata[0] == 2)
		{
			if(s_token == -1 && r_dsize >= (int)(1 + sizeof(MAGIC) + sizeof(s_token)) &&
				!memcmp(&r_cdata[1], MAGIC, sizeof(MAGIC)))
			{
				int* pd = (int*)&r_cdata[1 + sizeof(MAGIC)];
				s_token = (int)pd[0] | (pd[1] << 8) | (pd[2] << 16) | (pd[3] << 24);
				// printf( "got connect + accept (token %x)\n", s_token);
			}
			else
			{
				s_token = 0;
				// printf("got connect + accept (token unsupported)\n");
			}
			SendControl(3, 0, 0); /* accept control msg */
			astate = STATE_ONLINE;
		}
		r_cchunk = 0;
		r_Valid = true;
	}
	return 0;
}

int DDZombie::SendMsgEx(CMsgPacker* pMsg, int Flags, bool sys)
{
	UCHAR* pcd, * mpd = (UCHAR*)pMsg->m_aBuffer;
	*mpd = (*mpd << 1) | sys; /* store system flag in msg id */
	if(Flags & NETSENDFLAG_VITAL)
		m_seq = (m_seq + 1) % (1 << 10); /* max sequence */
	if((pMsg->Size() >= (1400 - 6))) /* max payload */
		return -1;
	if(c_dsize + pMsg->Size() + 5 > (int)sizeof(c_cdata) - (int)sizeof(int))
		Flush(); /* if not enough space (chunk header size = 5) */
	pcd = &c_cdata[c_dsize];
	pcd[0] = ((Flags & 3) << 6) | ((pMsg->Size() >> 4) & 0x3f);
	pcd[1] = (pMsg->Size() & 0xf);
	if(Flags & NETSENDFLAG_VITAL)
	{
		pcd[1] |= (m_seq >> 2) & 0xf0;
		pcd[2] = m_seq & 0xff;
		pcd += 3;
	}
	else
	{
		pcd += 2;
	}
	memcpy(pcd, mpd, pMsg->Size());
	pcd += pMsg->Size();
	c_numc++;
	c_dsize = (int)(pcd - c_cdata);
	if(Flags & NETSENDFLAG_FLUSH)
		Flush();
	return 0;
}

int DDZombie::Init(std::string endpoint, int id)
{
	this->id = id;
	std::string socksIp = endpoint.substr(0, endpoint.find(":"));
	int socksPort = stoi(endpoint.substr(endpoint.find(":") + 1));

	tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
	if(tcpSocket == INVALID_SOCKET)
	{
		// printf("socket() error: %d thread id %d\n", WSAGetLastError(), id);
		return 0;
	}

	sockaddr_in socksAddr;
	socksAddr.sin_family = AF_INET;
	InetPtonA(AF_INET, socksIp.c_str(), &socksAddr.sin_addr.s_addr);	// SOCKS5 server host
	socksAddr.sin_port = htons(socksPort);								// SOCKS5 server port

	if(connect(tcpSocket, (struct sockaddr*)&socksAddr, sizeof(socksAddr)) != 0)
	{
		// printf("tcp connect() error: %d thread id %d\n", WSAGetLastError(), id);
		return 0;
	}

	if(!socks5Auth(tcpSocket))
	{
		return 0;
	}

	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if(udpSocket == INVALID_SOCKET)
	{
		// printf("socket() error: %d thread id %d\n", WSAGetLastError(), id);
		return 0;
	}

	sockaddr_in bnd;
	bnd.sin_family = AF_INET;
	bnd.sin_port = 0;
	bnd.sin_addr.s_addr = INADDR_ANY;

	int iptos = 0x10, broadcast = 1, recvsize = 65535, sendsize = 65535;
	
	setsockopt(udpSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&broadcast, sizeof(broadcast));
	setsockopt(udpSocket, SOL_SOCKET, SO_RCVBUF, (char*)&recvsize, sizeof(recvsize));
	setsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, (char*)&sendsize, sizeof(sendsize)); // testing after perfect

	unsigned long mode = 1;
	ioctlsocket(udpSocket, FIONBIO, (unsigned long*)&mode);

	if(bind(udpSocket, (SOCKADDR*)&bnd, sizeof(bnd)) != 0)
	{
		// printf("bind() error: %d", WSAGetLastError());
		return 0;
	}

	sockaddr_in sin;
	socklen_t len = sizeof(sin);
	if(getsockname(udpSocket, (struct sockaddr*)&sin, &len) == -1)
	{
		// printf("getsockname() error: %d thread id %d\n", WSAGetLastError(), id);
		return 0;
	}

	sockaddr_in udpAssocAddr;
	udpAssocAddr.sin_family = AF_INET;
	InetPtonA(AF_INET, socksIp.c_str(), &udpAssocAddr.sin_addr.s_addr);	// SOCKS5 udp associate destination
	udpAssocAddr.sin_port = sin.sin_port;								// CLIENT udp bind port destination

	socks5_rep rep;
	if(!socks5StartRequest(tcpSocket, udpAssocAddr, rep))
	{
		return 0;
	}

	sockaddr_in con;
	con.sin_family = AF_INET;
	con.sin_port = rep.BindPort;
	con.sin_addr = rep.BindAddr;

	if(connect(udpSocket, (SOCKADDR*)&con, sizeof(con)) != 0)
	{
		// printf("udp connect() error: %d thread id %d\n", WSAGetLastError(), id);
		return 0;
	}

	// printf("Survived. Starting\n");

	// target server
	targetAddr.sin_family = AF_INET;
	InetPtonA(AF_INET, host, &targetAddr.sin_addr.s_addr);
	targetAddr.sin_port = htons(port);

	return 1;
}

void DDZombie::handle_snapshot(int parts, int Part, int psize, int GameTick, int DeltaTick, char* pData)
{
	char incomingdata[65536];

	if(psize > (65536 - Part * 900))
		psize = (65536 - Part * 900);

	memcpy((char*)incomingdata + Part * 900, pData, psize); /* max snapshot packsize */
	ss_parts |= 1 << Part;

	if(ss_parts != (unsigned)((1 << parts) - 1))
		return;

	Snapshot* deltas = &emptySnap;
	UCHAR buf2[65536];
	UCHAR buf3[65536];

	ss_parts = 0; // find snapshot that we should use as delta
	emptySnap.numItems = emptySnap.d_size = 0;
	Holder* eHolder = m_pFirst;

	for(; eHolder; eHolder = eHolder->next)
		if(eHolder->tick == DeltaTick)
		{
			deltas = eHolder->snap;
			break;
		}
	if(DeltaTick >= 0 && !eHolder)
	{
		// printf("error, couldn't find the delta snapshot\n");
		return;
	}
	const UCHAR* pSrc = (UCHAR*)incomingdata, * eEnd = pSrc + ((parts - 1) * 900 + psize);
	int d, dsz, isize, * pDst = (int*)buf2;
	while(pSrc < eEnd)
		pSrc = cviUnpack(pSrc, pDst++);
	if((dsz = (long)((UCHAR*)pDst - (UCHAR*)buf2)) < 0)
		return; /* failure during decompression, bail */
	int* mData = (int*)buf2;
	int num_deleted = *mData++;
	int num_update = *mData++;
	int* pEnd = (int*)(((char*)buf2 + dsz));
	short isz[64] = { 0, 40, 24, 20, 16, 12, 32, 16, 60, 88, 20, 68, 12,
				8, 8, 8, 8, 12, 12, 12, 12, 0 };
	d_size = numItems = 0;
	mData += num_deleted + 1; /* unpack deleted stuff */
	if(mData > pEnd)
		return;
	for(int i = 0; i < deltas->numItems; i++)
	{ /* copy non-deleted stuff */
		SnapShotItem* ifrom = (SnapShotItem*)(deltas->DataStart() + deltas->Offsets()[i]);
		isize = (i == deltas->numItems - 1) ? deltas->d_size : deltas->Offsets()[i + 1];
		isize -= (deltas->Offsets()[i] + sizeof(SnapShotItem));
		for(d = 0; d < num_deleted; d++)
			if(mData[d] == ifrom->Key())
				break;
		if(d >= num_deleted)
			memcpy(NewItem(ifrom->Type(), ifrom->ID(), isize), ifrom->Data(), isize);
	}
	for(int i = 0; i < num_update; i++)
	{ /* unpack updated stuff */
		if(mData + 2 > pEnd)
			return;
		int Type = *mData++;
		int ID = *mData++;
		if((unsigned int)Type < sizeof(isz) / sizeof(isz[0]) && isz[Type])
			isize = isz[Type];
		else
		{
			if(mData + 1 > pEnd)
				return;
			isize = (*mData++) * 4;
		}
		if(Type < 0 || Type > 0xFFFF || isize < 0 || (((char*)mData + isize) > (char*)pEnd))
			return;
		int* dnew = 0, Key = (Type << 16) | ID;
		for(int k = 0; k < numItems; k++)
			if(((SnapShotItem*)&(m_bData[offs[k]]))->Key() == Key)
			{
				dnew = (int*)((SnapShotItem*)&(m_bData[offs[k]]))->Data();
				break;
			}
		if(!dnew)
			dnew = (int*)NewItem(Key >> 16, Key & 0xffff, isize);
		for(int i = 0; i < deltas->numItems; i++)
		{ /* get item index */
			SnapShotItem* t = (SnapShotItem*)(deltas->DataStart() + deltas->Offsets()[i]);
			if(t->Key() == Key)
			{
				int* pPast = (int*)t->Data(), * pDiff = mData, * pOut = dnew;
				for(int Size = isize / 4; Size; )
				{
					*pOut = *pPast + *pDiff;
					if(*pDiff != 0)
					{
						UCHAR aBuf[16];
						UCHAR* pEnd = cviPack(aBuf, *pDiff);
					}
					pOut++, pPast++, pDiff++, Size--;
				}
				break;
			}
		}
		if(i >= deltas->numItems) /* no previous, just copy the mData */
			memcpy(dnew, mData, isize);
		mData += isize / 4;
	}
	Snapshot* pSnap = (Snapshot*)buf3;
	pSnap->d_size = d_size;
	pSnap->numItems = numItems;
	memcpy(pSnap->Offsets(), offs, (sizeof(int) * numItems));
	memcpy(pSnap->DataStart(), m_bData, d_size);
	if(m_ss[1] && m_ss[1]->tick < DeltaTick)
		DeltaTick = m_ss[1]->tick;
	if(m_ss[0] && m_ss[0]->tick < DeltaTick)
		DeltaTick = m_ss[0]->tick;
	for(Holder* hld = m_pFirst; hld && hld->tick < DeltaTick; )
	{
		Holder* pNext = hld->next; /* purge old snapshots */
		free(hld);
		if(!pNext)
		{
			m_pFirst = m_pLast = 0;
			break;
		}
		hld = m_pFirst = pNext;
		pNext->prev = 0x0;
	}
	int DataSize = (sizeof(Snapshot) + (sizeof(int) * numItems) + d_size);
	Holder* hld = (Holder*)calloc(sizeof(Holder) + DataSize + DataSize, 1);
	hld->tick = GameTick;
	hld->tagTime = time_get();
	hld->snapSize = DataSize;
	hld->snap = (Snapshot*)(hld + 1);
	memcpy(hld->snap, (void*)buf3, DataSize);
	hld->altSnap = (Snapshot*)(((char*)hld->snap) + DataSize);
	memcpy(hld->altSnap, (void*)buf3, DataSize);
	hld->next = 0;
	hld->prev = m_pLast;
	if(m_pLast)
		m_pLast->next = hld;
	else
		m_pFirst = hld;
	m_pLast = hld;
	if(++m_ReceivedSnapshots == 2)
	{ /* wait for 2 ss before seeing self as connected */
		m_ss[1] = m_pFirst;
		m_ss[0] = m_pLast;
		mstate = STATE_ONLINE;
	}
	crecv_tick = GameTick;
}

void DDZombie::Start()
{
	srand(time(NULL));
	long long tickscount = 0;
	long long LastTime = time_get();
	bool cmdCtrl[2]{ bControl, bControl };

	GenRandomData();

	CHuffmanConstructNode nodestorage[257];
	CHuffmanConstructNode* nodes[257];

	SOCKET sockid = 0;

	for(int i = 0; i < 257; i++)
	{ /* add the symbols */
		m_aNodes[i].m_NumBits = 0xFFFFFFFF;
		m_aNodes[i].m_Symbol = i;
		m_aNodes[i].m_aLeafs[0] = m_aNodes[i].m_aLeafs[1] = 0xffff;
		nodestorage[i].m_NodeId = i;
		nodes[i] = &nodestorage[i];
	}

	nnodes = 257;

	for(int nnl = 257; nnl > 1; nnl--)
	{ /* construct the table */
		m_aNodes[nnodes].m_NumBits = 0;
		m_aNodes[nnodes].m_aLeafs[0] = nodes[nnl - 1]->m_NodeId;
		m_aNodes[nnodes].m_aLeafs[1] = nodes[nnl - 2]->m_NodeId;
		nodes[nnl - 2]->m_NodeId = nnodes;
		nnodes++;
	}

	m_pStartNode = &m_aNodes[nnodes - 1];
	Setbits_r(m_pStartNode, 0, 0);

	for(int i = 0; i < HUFFMAN_LUTSIZE; i++)
	{ /* build decode LUT */
		unsigned Bits = i;
		int k;
		CNode* pNode = m_pStartNode;

		for(k = 0; k < HUFFMAN_LUTBITS; k++)
		{
			pNode = &m_aNodes[pNode->m_aLeafs[Bits & 1]];
			Bits >>= 1;

			if(!pNode)
				break;

			if(pNode->m_NumBits)
			{
				m_apDecodeLut[i] = pNode;
				break;
			}
		}

		if(k == HUFFMAN_LUTBITS)
			m_apDecodeLut[i] = pNode;
	}
	struct timeval tv = { 0, 0 };
	fd_set fds, readfds;

	astate = mstate = STATE_CONNECTING;
	s_token = -1;

	SendControl(1, MAGIC, sizeof(MAGIC)); /* connect control message */

	/* main loop */

	while(true)
	{
		new_tick = 1;

		if(mstate == STATE_ONLINE && m_ReceivedSnapshots >= 3)
		{
			Holder* pNext;
			while((pNext = m_ss[0]->next) != NULL)
			{
				m_ss[1] = m_ss[0];
				m_ss[0] = pNext;
				if(!m_ss[0] || !m_ss[1])
					continue;
				for(int i = 0; i < 64; ++i)
					clients[i].m_Team = -2;
				int Num = m_ss[0]->snap->numItems;
				for(int i = 0; i < Num; i++)
				{ /* read snapshot */
					Snapshot* p = m_ss[0]->altSnap;
					SnapShotItem* d = (SnapShotItem*)(p->DataStart() + p->Offsets()[i]);
					int* pInfo = (int*)d->Data();
					if(d->Type() == 11)
					{ /* client info */
						char* ptr = clients[d->ID()].m_aName;
						for(int i = 0; i < 4; i++, pInfo++)
						{
							ptr[0] = (((*pInfo) >> 24) & 0xff) - 128;
							ptr[1] = (((*pInfo) >> 16) & 0xff) - 128;
							ptr[2] = (((*pInfo) >> 8) & 0xff) - 128;
							ptr[3] = ((*pInfo) & 0xff) - 128;
							ptr += 4;
						}
						ptr[-1] = 0;
					}
					else if(d->Type() == 10)
					{ /* player info */
						clients[pInfo[1]].m_Team = pInfo[2];
						if(pInfo[0] && !m_ddsent)
						{ /* local */
							CMsgPacker Msg(26); /* isddnet */
							Msg.AddInt((int)strtol(data, NULL, 10));
							SendMsgEx(&Msg, NETSENDFLAG_VITAL, false);
							m_ddsent = true;
						}
					}
				}
			}
		}

		long long Now = time_get(), dif = (Now - last_stime);

		if(astate == STATE_ONLINE)
		{
			if(dif > time_freq()) /* flush after 1sec */
				Flush();

			if(dif > time_freq())
				SendControl(0, 0, 0); /* keepalive */
		}

		else if(astate == STATE_CONNECTING)
		{
			if(dif > time_freq()) /* send new connect every 1s */
				SendControl(1, MAGIC, sizeof(MAGIC)); /* connect control msg */
		}

		else
		{
			if(dif > time_freq()) /* send a new connect/accept every 500ms */
				SendControl(2, MAGIC, sizeof(MAGIC));
		}

		if(mstate == STATE_CONNECTING && astate == STATE_ONLINE)
		{
			mstate = STATE_LOADING;
			CMsgPacker Msg(1); /* info */
			Msg.AddString("0.6 626fce9a778df4d4", 128); /* version */
			Msg.AddString("", 128); /* password */
			SendMsgEx(&Msg, NETSENDFLAG_VITAL | NETSENDFLAG_FLUSH, true);
		}
		void* data;
		int flags, datasize, MsgID, mtype, team, id;

		/* receive loop */
		while(udpSocket >= 0 && RecvPacket(&flags, &datasize, &data))
		{

			const UCHAR* mpc = (UCHAR*)data;
			UCHAR* m_pEnd = (UCHAR*)data + datasize;
			mpc = cviUnpack(mpc, &MsgID);
			mtype = MsgID >> 1;

			if(!(MsgID & 1) && ((flags & NETSENDFLAG_VITAL) != 0))
			{

				if(mtype == 8)
				{ /* ready to enter */
					CMsgPacker Msg(15); /* entergame */
					SendMsgEx(&Msg, NETSENDFLAG_VITAL | NETSENDFLAG_FLUSH, true);
					m_ss[0] = m_ss[1] = 0;
					Holder* pNext, * pHolder = m_pFirst;

					while(pHolder)
					{
						pNext = pHolder->next;
						free(pHolder);
						pHolder = pNext;
					}
					m_pFirst = m_pLast = 0;
					m_ReceivedSnapshots = ss_parts = crecv_tick = 0;
					printf("Connected. id: %i, nickname: %s\n", this->id, this->nickname);
				}

				else if(mtype == 3)
				{ /* chat */
					mpc = cviUnpack(mpc, &team);
					mpc = cviUnpack(mpc, &id);
					// if(mpc < m_pEnd)
					// 	printf("%2d %s: %s\n", id, (id >= 0 && id < 64) ? clients[id].m_aName : "***", (char*)mpc);
				}
				continue;
			} /* system message */

			if((flags & NETSENDFLAG_VITAL) != 0 && mtype == 2)
			{ /* map change */
				mstate = STATE_LOADING;
				CMsgPacker Msg(14); /* ready */
				SendMsgEx(&Msg, NETSENDFLAG_VITAL | NETSENDFLAG_FLUSH, true);
			}

			else if((flags & NETSENDFLAG_VITAL) != 0 && mtype == 4)
			{ /* conn ready */
				CMsgPacker Packer(20); /* startinfo */
				Packer.AddString(nickname, 16); /* name */
				Packer.AddString("", 12); /* clan */
				Packer.AddInt(-1); /* country */
				Packer.AddString(skin, 16); /* skin */
				Packer.AddInt(1); /* use custom color */
				Packer.AddInt(bodycolor); /* color body */
				Packer.AddInt(feetcolor); /* color feet */
				SendMsgEx(&Packer, NETSENDFLAG_VITAL, false);
			}

			else if(mtype == 22)
			{ /* ping */
				CMsgPacker Msg(23); /* ping reply */
				SendMsgEx(&Msg, 0, true);
			}

			else if(mstate >= STATE_LOADING && (mtype == 5 || mtype == 7 || mtype == 6))
			{ /* snapshot */
				int np = 1, pt = 0, ps = 0, gt, dt;
				mpc = cviUnpack(mpc, &gt);
				mpc = cviUnpack(mpc, &dt);
				dt = gt - dt;
				if(mtype == 5)
				{ /* snap */
					mpc = cviUnpack(mpc, &np);
					mpc = cviUnpack(mpc, &pt);
				}
				if(mtype != 6)
				{ /* empty snap */
					mpc = cviUnpack(mpc, &ps);
					mpc = cviUnpack(mpc, &ps);
				}
				char* pData = (char*)mpc;
				mpc += ps;
				if(np >= 1 && pt >= 0 && ps >= 0 && gt >= crecv_tick)
				{
					if(gt != crecv_tick)
					{
						ss_parts = 0;
						crecv_tick = gt;
					}
					handle_snapshot(np, pt, ps, gt, dt, pData);
				}
			}
			/*
			else
			{
				// printf("msg %d\n", mtype);
			}
			*/
		}

		if(notRecvdDisconnect)
			break;

	#pragma region select
		long long tm = (1000000 * (LastTime + time_freq() / 120 - Now) / time_freq());
		tm = (tm >= 0) ? tm : 0;
		tv.tv_sec = tm / 1000000;
		tv.tv_usec = tm % 1000000;
		FD_ZERO(&readfds);
		if(udpSocket >= 0)
		{
			FD_SET(udpSocket, &readfds);
			sockid = udpSocket;
		}
		select(sockid + 1, &readfds, NULL, NULL, (tm < 0) ? NULL : &tv);
		LastTime = Now;
	#pragma endregion

		cmdCtrl[0] = bControl;
		if(cmdCtrl[1] == !cmdCtrl[0])
		{
			cmdCtrl[1] = !cmdCtrl[1];

			if(!strncmp(";quit", controlMessage, 5))
			{
				break;
			}

			else
			{
				if(controlMessage[0] != NULL)
				{
					CMsgPacker Packer(17); /* cl_say */
					Packer.AddInt(0); /* team */
					Packer.AddString(controlMessage, 512);
					SendMsgEx(&Packer, NETSENDFLAG_VITAL, false);
				}
			}
		}

	}

	SendControl(4, 0, 0); // close control msg 
}

static const char nicknames[][16] = {
	"Ace",
	"Rogue",
	"Lucky",
	"Shadow",
	"Falcon",
	"Twinkle",
	"Sphinx",
	"Mystic",
	"Cypher",
	"Nova",
	"Phantom",
	"Vortex",
	"Jester",
	"Blaze",
	"Raven",
	"Orbit",
	"Dagger",
	"Zephyr",
	"Hawk",
	"Echo",
	"Spartan",
	"Cosmo",
	"Neptune",
	"Zigzag",
	"Venom",
	"Sizzle",
	"Jinx",
	"Titan",
	"Karma",
	"Whisper",
	"Ripple",
	"Venus"
};

static const char skins[][16] = {
	"pinky",
	"testa",
	"bluestripe",
	"cammostripes",
	"coala",
	"toptri",
	"brownbear",
	"cammo",
	"redbopp",
	"saddo"
};


void DDZombie::GenRandomData()
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for(int i = 0; i < 4; ++i)
		data[i] += rand() % 8;

	for(int i = 0; i < 8; ++i)
		nickname[i] += alphanum[rand() % (sizeof(alphanum) - 1)];


	strcpy_s(skin, skins[rand() % 10]);
	strcpy_s(nickname, nicknames[rand() % 32]);
	bodycolor = gen_random_int();
	feetcolor = gen_random_int();
}