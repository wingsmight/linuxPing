#define _BSD_SOURCE
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Ws2ipdef.h>
#include <windows.h>
#include <crtdbg.h>

#include <iostream>
using std::cout;


#pragma comment (lib,"ws2_32")

typedef struct ip_hdr //заголовок IP 
{
    unsigned char verhlen;
    unsigned char tos : 6;
    unsigned char additional : 2;
    unsigned short totallent;
    unsigned short id;
    unsigned short offset;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checksum;
    unsigned int source;
    unsigned int destination;
}IpHeader;

typedef  struct icmp_hdr //заголовок ICMP
{
    unsigned char i_type;
    unsigned char i_code;
    unsigned short i_crc;
    unsigned short i_seq;
    unsigned short i_id;

}IcmpHeader;

int bytesCount = 32;
int iterationCount = 4;




USHORT crc2(USHORT* addr, int count) //http://www.ietf.org/rfc/rfc1071.txt подсчет CRC
{

    register long sum = 0;

    while (count > 1) {
        /*  This is the inner loop */
        sum += *(unsigned short*)addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
        sum += *(unsigned char*)addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (USHORT)(~sum);

}


unsigned int analize(char* data, SOCKADDR_IN* adr, int icmpIndex, DWORD elapsedTime) //разбор ответа
{
    char* Ip = new char[256];
    IpHeader* pHe = (IpHeader*)data;
    char Name[NI_MAXHOST] = { 0 };
    char servInfo[NI_MAXSERV] = { 0 };
    getnameinfo((struct sockaddr*)adr, sizeof(struct sockaddr), Name, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
    Ip = inet_ntoa(adr->sin_addr);

    int TTL = (int)pHe->ttl;
    data += sizeof(IpHeader);
    IcmpHeader* ic = (IcmpHeader*)data;
    if (GetCurrentProcessId() == ic->i_id)//проверка что это мы слали.
    {
        cout << bytesCount << " bytes from " << Name << " (" << Ip << ") " << ":  icmp_seq=" << icmpIndex + 1 << " ttl=" << TTL << " time= " << elapsedTime << " ms\n";
    }
    else
    {
        cout << "Fake packet\n";
    }
    return pHe->source;

}

int findMin(DWORD a[], int n) {
    DWORD minValue = a[0];

    for (int i = 1; i < n; i++)
        if (a[i] < minValue)
            minValue = a[i];

    return minValue;
}

int findMax(DWORD a[], int n) {
    DWORD maxValue = a[0];

    for (int i = 1; i < n; i++)
        if (a[i] > maxValue)
            maxValue = a[i];

    return maxValue;
}

int findAverage(DWORD a[], int n)
{
    DWORD sum = 0;

    for (int i = 0; i < n; i++)
    {
        sum += a[i];
    }

    return sum / n;
}

void finalAnalize(int lostPacketsCount, DWORD entireTime, DWORD elapsedTimes[])
{
    cout << iterationCount << " packets trtansmitted, " << iterationCount - lostPacketsCount << " received, " << (int)((lostPacketsCount / iterationCount) * 100) << "% packet loss, time "
        << entireTime << "ms\n";

    int minTime = findMin(elapsedTimes, iterationCount);
    int maxTime = findMax(elapsedTimes, iterationCount);
    int averageTime = findAverage(elapsedTimes, iterationCount);
    cout << "rtt min/avg/max = " << minTime << "/" << averageTime << "/" << maxTime << " ms\n";
}


int main()
{
    WSADATA wsd = { 0 };
    WSAStartup(0x202, &wsd);

    printf_s("ping -c 4 ");
    char* dstHostName = new char[64];
    scanf_s("%s", dstHostName, 64);

    char* IpLocalTmp = new char[256];
    gethostname(IpLocalTmp, 256);
    hostent* host_entry_local = gethostbyname(IpLocalTmp);
    in_addr* addressLocal = (in_addr*)host_entry_local->h_addr_list[1];
    IpLocalTmp = inet_ntoa(*addressLocal);
    char* IpLocal = new char[256];
    memcpy(IpLocal, IpLocalTmp, strlen(IpLocalTmp) + 1);

    hostent* host_entry = gethostbyname(dstHostName);
    in_addr* address = (in_addr*)host_entry->h_addr_list[0];
    const char* Ip = inet_ntoa(*address);

    //удаленный адрес
    sockaddr_in list_adr = { 0 };
    list_adr.sin_addr.S_un.S_addr = inet_addr(Ip);
    list_adr.sin_family = AF_INET;
    list_adr.sin_port = htons(0);

    //локальный адрес
    sockaddr_in bnd = { 0 };
    bnd.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    bnd.sin_family = AF_INET;
    bnd.sin_port = htons(0);

    SOCKET listn = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, WSA_FLAG_OVERLAPPED);

    IcmpHeader pac = { 0 };
    int timeout = 1000;
    setsockopt(listn, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)); //таймаут получения
    pac.i_type = 8;
    pac.i_code = 0;
    pac.i_seq = 0x2;
    pac.i_crc = 0;
    pac.i_id = (USHORT)GetCurrentProcessId();//записать в ICMP идентификатор процесса.      
    //создаем довесок из данных в 32 байта
    int size = sizeof(pac) + bytesCount;
    char* Icmp = new char[size];
    memcpy(Icmp, &pac, sizeof(pac));
    memset(Icmp + sizeof(pac), 'Z', bytesCount);

    IcmpHeader* Packet = (IcmpHeader*)Icmp;
    Packet->i_crc = crc2((USHORT*)Packet, size);//считаем контрольную сумму пакета, заголовок+данные
    char bf[256] = { 0 };
    int outlent = sizeof(SOCKADDR_IN);
    SOCKADDR_IN out_ = { 0 };
    out_.sin_family = AF_INET;

    //здесь формируем IP заголовок вручную
    // и собираем пакет наш IP+Icmp+32байта данных 

    int icmp_size = sizeof(pac) + bytesCount;
    size = sizeof(IpHeader) + sizeof(IcmpHeader) + bytesCount;
    int param = 1;
    setsockopt(listn, IPPROTO_IP, IP_HDRINCL, (char*)&param, sizeof(param));//сообщаем что сами слепим заголовок
    IpHeader IpHead = { 0 };
    IpHead.verhlen = 69;
    IpHead.ttl = 200;
    IpHead.source = inet_addr(IpLocal);
    IpHead.destination = inet_addr(Ip);
    IpHead.totallent = size - icmp_size;
    IpHead.proto = 1;
    char* FullPack = new char[size];

    memcpy(FullPack, &IpHead, sizeof(IpHeader));
    memcpy(FullPack + sizeof(IpHeader), Packet, icmp_size);


    cout << "PING " << dstHostName << " (" << Ip << ") " << bytesCount << " bytes of data." << "\n";
    int lostPacketCount = 0;
    DWORD elapsedTimes[10];
    DWORD entireTime = GetTickCount();

    for (int i = 0; i < iterationCount; ++i)
    {
        elapsedTimes[i] = GetTickCount();

        int bytes = sendto(listn, (char*)FullPack, size, 0, (sockaddr*)&list_adr, sizeof(list_adr));

        if (recvfrom(listn, bf, 256, 0, (sockaddr*)&out_, &outlent) == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                lostPacketCount++;

                cout << "Request timeout\n";
                continue;
            }
        }
        elapsedTimes[i] = GetTickCount() - elapsedTimes[i];
        analize(bf, &out_, i, elapsedTimes[i]);
        memset(bf, 0, 0);

        Sleep(timeout);
    }
    entireTime = GetTickCount() - entireTime;

    cout << "\n\n--- " << dstHostName << " ping statistics ---\n";
    finalAnalize(lostPacketCount, entireTime, elapsedTimes);

    delete[] Icmp;
    delete[] FullPack;

    closesocket(listn);
    WSACleanup();

    system("Pause");
    return 0;
}