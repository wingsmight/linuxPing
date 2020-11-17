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



//эхо-ответ
#define ICMP_ECHOREPLY 0   
//эхо-запрос
#define ICMP_ECHOREQ   8

//заголовок ICMP пакета
typedef struct tagICMPHDR
{
    //тип пакета. В нашем случае это ICMP_ECHOREQ
    u_char Type;
    //не используется в эхо-запросах и должен равняться нулю
    u_char Code;
    //идентификатор. Для эхо-запроса должен быть обнулен
    u_short ID;
    //номер очереди, который должен быть обнулен, если код равен нулю
    u_short Seq;
    //данные
    char Data;
}ICMPHDR, * PICMPHDR;

//ICMP пакет
typedef struct tagECHOREQUEST
{
    //заголовок
    ICMPHDR icmpHdr;
    DWORD dwTime;
    char cData[64];
}ECHOREQUEST, * PECHOREQUEST;

typedef struct tagIPHDR
{
    u_char VIHL;
    u_char TOS;
    short TotLen;
    short ID;
    short FlagOff;
    u_char TTL;
    u_char Protocol;
    struct in_addr iaSrc;
    struct in_addr iaDst;
}IPHDR, * PIPHDR;

typedef struct tagECHOREPLY
{
    IPHDR ipHdr;
    ECHOREQUEST echoRequest;
    char cFiller[256];
}ECHOREPLY, * PECHOREPLY;


int main() {
    SOCKET rawSocket;
    hostent* lpHost;
    struct sockaddr_in sSrc;
    struct sockaddr_in sDest;
    DWORD dwElapsed;
    int iRet = 0;

    WSADATA wsd;
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
    {
        printf("Can't load WinSock");
        return 0;
    }

    // Create socket (Создание сокета)
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rawSocket == SOCKET_ERROR)
    {
        printf("Socket error");
        return 0;
    }

    // Lookup host (Поиск хоста)
    char strHost[255] = "ya.ru";
    lpHost = gethostbyname(strHost);
    if (lpHost == NULL)
    {
        printf("Host not found");
        return 0;
    }

    // Socket address (Адрес сокета)
    sDest.sin_addr.s_addr = ((in_addr*)lpHost->h_addr_list[0])->s_addr;
    sDest.sin_family = AF_INET;
    sDest.sin_port = 0;

    printf("Pinging %s [%s]", strHost, inet_ntoa(sDest.sin_addr));

    // Send ICMP echo request (Посылка эхо-запроса ICMP)
    static ECHOREQUEST echoReq;

    echoReq.icmpHdr.Type = ICMP_ECHOREQ;
    echoReq.icmpHdr.Code = 0;
    echoReq.icmpHdr.ID = 0;
    echoReq.icmpHdr.Seq = 0;
    echoReq.dwTime = GetTickCount();
    FillMemory(echoReq.cData, 64, 80);

    sendto(rawSocket, (LPSTR)&echoReq, sizeof(ECHOREQUEST), 0, (LPSOCKADDR)&sDest, sizeof(SOCKADDR_IN));

    struct timeval tVal;
    fd_set readfds;
    readfds.fd_count = 1;
    readfds.fd_array[0] = rawSocket;
    tVal.tv_sec = 1;
    tVal.tv_usec = 0;

    iRet = select(1, &readfds, NULL, NULL, &tVal);

    if (!iRet)
    {
        printf("\nRequest Timed Out");
    }
    else
    {
        // Receive reply (Получение ответа)
        ECHOREPLY echoReply;
        int nRet;
        int nAddrLen = sizeof(struct sockaddr_in);

        // Receive the echo reply
        iRet = recvfrom(rawSocket, (LPSTR)&echoReply,
            sizeof(ECHOREPLY), 0, (LPSOCKADDR)&sSrc, &nAddrLen);

        if (iRet == SOCKET_ERROR)
            printf("Recvfrom Error");

        // Calculate time (Расчет времени)
        dwElapsed = GetTickCount() - echoReply.echoRequest.dwTime;
        printf("Reply from: %s: bytes=%d time=%ldms TTL=%d",
            inet_ntoa(sSrc.sin_addr), 64, dwElapsed,
            echoReply.ipHdr.TTL);
    }
    iRet = closesocket(rawSocket);
    if (iRet == SOCKET_ERROR)
        printf("Closesocket error");

    WSACleanup();
    getchar();
    return 0;
}