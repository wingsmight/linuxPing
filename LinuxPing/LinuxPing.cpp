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

#define PACKET_ FullPack

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


unsigned int analize(char* data, SOCKADDR_IN* adr, int icmpIndex) //разбор ответа
{
    int byteCount = 64;
    double pingTime = 24.5;

    const char* Ip = "";
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
        cout << byteCount << " bytes from " << Ip << ": icmp_seq=" << icmpIndex + 1 << " ttl=" << TTL << " time= " << pingTime << " ms\n";
    }
    else
    {
        cout << "Fake packet\n";
    }
    return pHe->source;

}

int main1()
{
    _CrtSetDbgFlag(33);
    const char* Ip = "87.250.250.242"; //сюда вбить пингуемый адрес, сейчас это ya.ru
    const char* IpLocal = "192.168.0.82"; //наш ip

    //удаленный адрес
    SOCKADDR_IN list_adr = { 0 };
    list_adr.sin_addr.S_un.S_addr = inet_addr(Ip);
    list_adr.sin_family = AF_INET;
    list_adr.sin_port = htons(6666);

    //локальный адрес
    SOCKADDR_IN bnd = { 0 };
    bnd.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    bnd.sin_family = AF_INET;
    bnd.sin_port = htons(6666);

    WSADATA wsd = { 0 };
    WSAStartup(0x202, &wsd);

    SOCKET listn = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, WSA_FLAG_OVERLAPPED);
    bind(listn, (sockaddr*)&bnd, sizeof(bnd));
    IcmpHeader pac = { 0 };
    int timeout = 3000;
    setsockopt(listn, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)); //таймаут получения
    pac.i_type = 8;
    pac.i_code = 0;
    pac.i_seq = 0x2;
    pac.i_crc = 0;
    pac.i_id = (USHORT)GetCurrentProcessId();//записать в ICMP идентификатор процесса.      
    //создаем довесок из данных в 32 байта заполненый буквой Z, чтоб было похоже на настоящее
    int size = sizeof(pac) + 32;
    char* Icmp = new char[size];
    memcpy(Icmp, &pac, sizeof(pac));
    memset(Icmp + sizeof(pac), 'Z', 32);

    IcmpHeader* Packet = (IcmpHeader*)Icmp;
    Packet->i_crc = crc2((USHORT*)Packet, size);//считаем контрольную сумму пакета, заголовок+данные
    char bf[256] = { 0 };
    int outlent = sizeof(SOCKADDR_IN);
    SOCKADDR_IN out_ = { 0 };
    out_.sin_family = AF_INET;



    //здесь формируем IP заголовок вручную
    // и собираем пакет наш IP+Icmp+32байта данных 

    int icmp_size = sizeof(pac) + 32;
    size = sizeof(IpHeader) + sizeof(IcmpHeader) + 32;
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


   //ПИНГИ
    cout << "Pinging address >) " << Ip << "\n";

    for (int i = 0; i < 4; ++i)
    {
        int bytes = sendto(listn, (char*)PACKET_, size, 0, (sockaddr*)&list_adr, sizeof(list_adr));
        Sleep(1000);

        if (recvfrom(listn, bf, 256, 0, (sockaddr*)&out_, &outlent) == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                cout << "Request timeout\n";
                continue;
            }
        }
        //dwElapsed = GetTickCount() - echoReply.echoRequest.dwTime;
        analize(bf, &out_, i);
        memset(bf, 0, 0);
    }

    delete[] Icmp;
    delete[] FullPack;

    cout << "COMPLETE\n";
    closesocket(listn);
    WSACleanup();

    system("Pause");
    return 0;
}