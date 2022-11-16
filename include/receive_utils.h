#ifndef _RECEIVE_UTILS_H_
#define _RECEIVE_UTILS_H_

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <iostream>
#include <vector>
#include "yaml_convert.h"

#include <sstream>

/* send protocol type */
#define PROTOCOLTYPE_IP               0
#define PROTOCOLTYPE_TCP              1
#define PROTOCOLTYPE_UDP              2
#define PROTOCOLTYPE_SCTP             3
#define PROTOCOLTYPE_ESP              4
#define PROTOCOLTYPE_GRE              5
#define PROTOCOLTYPE_GTP              6
#define PROTOCOLTYPE_HTTPREQUEST      7
#define PROTOCOLTYPE_HTTPRESPONSE     8
#define PROTOCOLTYPE_SSL              9
#define PROTOCOLTYPE_BGP              10
#define PROTOCOLTYPE_OSPF             11
#define PROTOCOLTYPE_RIP              12
#define PROTOCOLTYPE_L2TP             13
#define PROTOCOLTYPE_PPP              14
#define PROTOCOLTYPE_AUTHENTICATION   15
#define PROTOCOLTYPE_PAYLOAD          16

#define PROTOCOLTYPE_UNKOWN           -1
 
/********************************************************************************************************************************/
// 消息结构体
struct My_MSG
{
	int     type;                // 类型
	void   *protocol;            // 协议内容
	My_MSG *next = NULL;         // 指针, 初始为空

};

// 负载结构体
struct Payload
{
	int  length;
	char address[100] = {0}; 
	// char rawData[1024*1024] = {0}; 
	void * rawData;
} Payload;

// IP层的结构体
struct IpHeader
{
	int  version;
	int  headerLength; 
	int  totalLength;
	int  id;
	char srcIP[50] = {0};
	char dstIP[50] = {0};
} IpHeader;

// TCP层的结构体
struct TcpHeader
{
	char       flag[10] = {0};
	int        srcPort;
	int        dstPort;
	int        headerLength;
	long long  seqNumber;
	long long  ackNumber;
	
} TcpHeader;

// UDP层的结构体
struct UdpHeader
{
	int srcPort;
	int dstPort;
	int length;
} UdpHeader;

// SCTP层的结构体
struct SctpHeader
{
	int srcPort;
	int dstPort;
	int verifyTag;
	int checksum;
} SctpHeader;

// ESP层的结构体
struct EspHeader
{
	long long spi;
	long long seqNumber;
} EspHeader;

// GRE层的结构体
struct GreHeader
{
	int version;
	int recurControl; 
	int C_Bit;
	int R_Bit;
	int K_Bit;
	int S_Bit;
	int s_Bit;
	int protocol; 
} GreHeader;

// GTP层的结构体
struct GtpHeader
{
	int       version;
	int       teid; 
	int       messageType;
	int       totalLength;
	int       npduNumber;
	long long seqNumber;
} GtpHeader;

// HTTP请求层的结构体
struct HttpRequestHeader
{
	char firstLine[200] = {0};
	char host[200] = {0};
	char userAgent[200] ={0};
	char accept[200] = {0};
	char acceptEncoding[200] = {0};
	char acceptLanguage[200] = {0};
	char cookie[200] = {0};
	char referer[200] = {0};
	char contentType[200] = {0};
	char contentLength[200] = {0};
} HttpRequestHeader;

// HTTP响应层的结构体
struct HttpResponseHeader
{
	char firstLine[200] = {0};
	char server[200] = {0};
	char contentType[200] = {0};
	char contentLength[200] = {0};
} HttpResponseHeader;


// SSL层的结构体
struct SslHeader
{
	char  type[20] = {0};
	char  version[10] = {0};
	char  alertLevel[20] = {0};
	int   length;

} SslHeader;

// BGP层的结构体
struct BgpHeader
{
	long long  marker; 
	int        length;
	char       messageType[20] = {0};
} BgpHeader;

// OSPF层的结构体
struct OspfHeader
{
	int   totalLength;
	char  srcRouter[50]= {0};
	char  areaId[50]= {0};
} OspfHeader;

// RIP层的结构体
struct RipHeader
{
	int command;
	int version;
	int totalLength;

	// 下面为Rip报文中属于RipTableEntry的内容
	int  addrFamilyIdentifier;
	int  routeTag;
	int  metric;
	char ipAddr[50]= {0};
	char netMask[50]= {0};
	char nexThop[50]= {0};
} RipHeader;

// L2TP层的结构体
struct L2tpHeader
{
	int  controlBytes;
	int  tunnelId;
	int  sessionId;
	int  length;
	int  ns;
	int  nr;
	char type[50] = {0};
} L2tpHeader;

// PPP层的结构体
struct PPPHeader
{
	int broadAddr;
	int controlBytes;
	int nextProtocol;
} PPPHeader;

// Authentication层的结构体
struct AuthenticationHeader
{
	long long  spi;
	long long  seqNumber;
	int        icvLength;
	char       icvHexStream[100] = {0};
} AuthenticationHeader;


// 把字符串转换为整型数据，支持二进制、十进制、十六进制
int str_to_integer(std::string str)
{
	std::string value;
	int result = 0;
	int n = str.size();
	int flag = 10;    // 默认为10进制
	
	for(int i = 0;i < n; i++)
	{
        if(value == "0b")    // 2进制
		{
			flag = 2;
			value = "";
		}
		else if(value == "0x")   // 16进制 
		{
			flag = 16;
			value = "";
		}
		value += str[i];
	}
	result = stoi(value, 0, flag);
	return result;
}

// 把字符串转换为long long型数据，支持十进制、十六进制
long long str_to_long_long(std::string str)
{
    std::string value;
	long long result = 0;
	int n = str.size();
	int flag = 10;    // 默认为10进制
     
	for(int i = 0;i < n; i++)
	{
        if(value == "0x")    // 16进制 
		{
		    flag = 16;
			value = "";
		}
		value += str[i];
	}

	if(flag == 16)
	{
		std::istringstream converter{ value };
        converter >> std::hex >> result;
	}
	else
	{
		std::stringstream strIn;
		strIn << value;
        strIn >> result;
	}  
	return result;
}

// 将string转换为char*，可以把str的数据复制到arr中
void str_to_chars(std::string str, char* arr)
{
	int size = str.size();
	// 如果不存在该部分值就不传递
 	if(str != "null")
	{ 
		for(int i = 0; i < size; i++)
		{
			arr[i] = str[i];
		}
	}
}


// 打印My_MSG链表的信息, 输入的头节点为虚拟节点，不包含内容
void print_msg(struct My_MSG *my_msg)
{
	struct My_MSG *msg = my_msg->next;
    
	std::cout << "==================================================" << std::endl;
    std::cout << std::endl;	

	// 循环至链表的结尾
	while(msg != NULL)
	{
		// print IP
		if(msg->type == PROTOCOLTYPE_IP)
		{
			struct IpHeader *ip = (struct IpHeader*)(msg->protocol);

			int   my_version = ip->version;
			int   my_headerLength = ip->headerLength;
			int   my_totalLength = ip->totalLength;
			int   my_id = ip->id;
			char* my_srcIP = ip->srcIP;
			char* my_dstIP = ip->dstIP;

			std::cout << "IP: " << std::endl;
			std::cout << "\tVersion: " << my_version << std::endl;
			std::cout << "\tHeader Length: " << my_headerLength << std::endl;
			std::cout << "\tTotal Length: "  << my_totalLength << std::endl;
			std::cout << "\tIP ID: " << my_id << std::endl;
			std::cout << "\tSource IP: " << my_srcIP << std::endl;
			std::cout << "\tDestination IP: " << my_dstIP << std::endl;
		}
		// print TCP
		else if(msg->type == PROTOCOLTYPE_TCP)
		{
			struct TcpHeader *tcp = (struct TcpHeader*)(msg->protocol);

            char*     my_flag = tcp->flag;
			int       my_srcPort = tcp->srcPort;
			int       my_dstPort = tcp->dstPort;
			int       my_headerLength = tcp->headerLength;
			long long my_seqNumber = tcp->seqNumber;
			long long my_ackNumber = tcp->ackNumber;
			
			std::cout << "TCP: " << std::endl;
			std::cout << "\tFlag: " << my_flag << std::endl;
			std::cout << "\tSource Port: " << my_srcPort << std::endl;
			std::cout << "\tDestination Port: "  << my_dstPort << std::endl;
			std::cout << "\tSequence Number: " << my_seqNumber << std::endl;
			std::cout << "\tAck Number: " << my_ackNumber << std::endl;
			std::cout << "\tHeader Length: " << my_headerLength << std::endl;
		}
		// print UDP
		else if(msg->type == PROTOCOLTYPE_UDP)
        {
			struct UdpHeader *udp = (struct UdpHeader*)(msg->protocol);

			int my_srcPort = udp->srcPort;
			int my_dstPort = udp->dstPort;
			int my_length = udp->length;

			std::cout << "UDP: " << std::endl;
			std::cout << "\tSource Port: " << my_srcPort << std::endl;
			std::cout << "\tDestination Port: "  << my_dstPort << std::endl;
			std::cout << "\tLength: " << my_length << std::endl;
		}
		// print SCTP 
		else if(msg->type == PROTOCOLTYPE_SCTP)
		{
			struct SctpHeader *sctp = (struct SctpHeader*)(msg->protocol);

			int my_srcPort = sctp->srcPort;
			int my_dstPort = sctp->dstPort;
			int my_verifyTag = sctp->verifyTag;
			int my_checksum = sctp->checksum;

			std::cout << "SCTP: " << std::endl;
			std::cout << "\tSource Port: " << my_srcPort << std::endl;
			std::cout << "\tDestination port: "  << my_dstPort << std::endl;
			std::cout << "\tVerification Tag: " << my_verifyTag << std::endl;
			std::cout << "\tChecksum: " << my_checksum << std::endl;
		}
		// print ESP
		else if((msg->type == PROTOCOLTYPE_ESP))
		{
			struct EspHeader *esp = (struct EspHeader*)(msg->protocol);

			long long my_spi = esp->spi;
			long long my_seqNumber = esp->seqNumber;

			std::cout << "ESP: " << std::endl;
			std::cout << "\tSPI: " << my_spi << std::endl;
			std::cout << "\tSequence Number: "  << my_seqNumber << std::endl;
		}
		// print GRE
		else if(msg->type == PROTOCOLTYPE_GRE)
		{
			struct GreHeader *gre = (struct GreHeader*)(msg->protocol);

            int my_version = gre->version;
			int my_recurControl = gre->recurControl;
			int my_Cbit = gre->C_Bit;
			int my_Rbit = gre->R_Bit;
			int my_Kbit = gre->K_Bit;
			int my_Sbit = gre->S_Bit;
			int my_sbit = gre->s_Bit;
			int my_protocol = gre->protocol;

			std::cout << "GRE: " << std::endl;
			std::cout << "\tVersion: " << my_version << std::endl;
			std::cout << "\tRecursion Control: "  << my_recurControl << std::endl;
			std::cout << "\tC bit: " << my_Cbit << std::endl;
			std::cout << "\tR bit: "  << my_Rbit << std::endl;
			std::cout << "\tK bit: " << my_Kbit << std::endl;
			std::cout << "\tS bit: "  << my_Sbit << std::endl;
		    std::cout << "\ts bit: " << my_sbit << std::endl;
			std::cout << "\tProtocol: "  << my_protocol << std::endl;
		}
		// print GRE
		else if(msg->type == PROTOCOLTYPE_GTP)
		{
			struct GtpHeader *gtp = (struct GtpHeader*)(msg->protocol);
            
			int my_version = gtp->version;
			int my_teid = gtp->teid;
			int my_messageType = gtp->messageType;
			int my_totalLength = gtp->totalLength;
			int my_seqNumber = gtp->seqNumber;
			int my_npduNumber = gtp->npduNumber;

			std::cout << "GTP: " << std::endl;
			std::cout << "\tVersion: " << my_version << std::endl;
			std::cout << "\tTeid: "  << my_teid << std::endl;
			std::cout << "\tMessageType: " << my_messageType << std::endl;
			std::cout << "\tTotalLength: "  << my_totalLength << std::endl;
			std::cout << "\tSequenceNumber: " << my_seqNumber << std::endl;
			std::cout << "\tNpduNumber: "  << my_npduNumber << std::endl;
		}
		// print HTTPREQUEST
		else if(msg->type == PROTOCOLTYPE_HTTPREQUEST)
		{
			struct HttpRequestHeader *httpRequest = (struct HttpRequestHeader*)(msg->protocol);

			char* my_firstLine = httpRequest->firstLine;
			char* my_host = httpRequest->host;
			char* my_userAgent = httpRequest->userAgent;
			char* my_accept = httpRequest->accept;
			char* my_acceptEncoding = httpRequest->acceptEncoding;
			char* my_acceptLanguage = httpRequest->acceptLanguage;
			char* my_cookie = httpRequest->cookie;
			char* my_referer = httpRequest->referer;
			char* my_contentType = httpRequest->contentType;
			char* my_contentLength = httpRequest->contentLength;

			std::cout << "HTTP REQUEST: " << std::endl;
			std::cout << "\tFirst Line: " << my_firstLine << std::endl;
			std::cout << "\tHost: "  << my_host << std::endl;
			std::cout << "\tUser-Agent: " << my_userAgent << std::endl;
			std::cout << "\tAccept: "  << my_accept << std::endl;
			std::cout << "\tAccept-Encoding: " << my_acceptEncoding << std::endl;
			std::cout << "\tAccept-Language: "  << my_acceptLanguage << std::endl;
			std::cout << "\tCookie: " << my_cookie << std::endl;
			std::cout << "\tReferer: "  << my_referer << std::endl;
			std::cout << "\tContent-Type: " << my_contentType << std::endl;
			std::cout << "\tContent-Length: "  << my_contentLength << std::endl;
		}
		else if(msg->type == PROTOCOLTYPE_HTTPRESPONSE)
		{
			struct HttpResponseHeader *httpResponse = (struct HttpResponseHeader*)(msg->protocol);

			char* my_firstLine = httpResponse->firstLine;
            char* my_server = httpResponse->server;
			char* my_contentType = httpResponse->contentType;
			char* my_contentLength = httpResponse->contentLength;

			std::cout << "HTTP RESPONSE: " << std::endl;
			std::cout << "\tFirst Line: " << my_firstLine << std::endl;
            std::cout << "\tServer: " << my_server << std::endl;
			std::cout << "\tContent-Type: " << my_contentType << std::endl;
			std::cout << "\tContent-Length: "  << my_contentLength << std::endl;
		}
		// print SSL
		else if(msg->type == PROTOCOLTYPE_SSL)
		{
			struct SslHeader *ssl = (struct SslHeader*)(msg->protocol);

			char* my_type = ssl->type;
			char* my_version = ssl->version;
			char* my_alertLevel = ssl->alertLevel;
			int   my_length = ssl->length;

			std::cout << "SSL: " << std::endl;
            std::cout << "\tType: "  << my_type << std::endl;
			std::cout << "\tVersion: " << my_version << std::endl;
			std::cout << "\tLength: " << my_length << std::endl;
			std::cout << "\tAlert Level: "  << my_alertLevel << std::endl;
		}
		// print BGP
		else if(msg->type == PROTOCOLTYPE_BGP)
		{
			struct BgpHeader *bgp = (struct BgpHeader*)(msg->protocol);

			long long my_marker = bgp->marker;
			int       my_length = bgp->length;
            char*     my_messageType = bgp->messageType;

			std::cout << "BGP: " << std::endl;
            std::cout << "\tMarker: "  << my_marker << std::endl;
			std::cout << "\tLength: " << my_length << std::endl;
			std::cout << "\tMessage Type: " << my_messageType << std::endl;
		}
		// print OSPF
		else if(msg->type == PROTOCOLTYPE_OSPF)
		{
			struct OspfHeader *ospf = (struct OspfHeader*)(msg->protocol);

			int   my_totalLength = ospf->totalLength;
			char* my_srcRouter = ospf->srcRouter;
			char* my_areaId = ospf->areaId;

			std::cout << "OSPF: " << std::endl;
            std::cout << "\tTotal Length: "  << my_totalLength << std::endl;
			std::cout << "\tSource Router: " << my_srcRouter << std::endl;
			std::cout << "\tArea ID: " << my_areaId << std::endl;
		}
		// print RIP
		else if(msg->type == PROTOCOLTYPE_RIP)
		{
			struct RipHeader *rip = (struct RipHeader*)(msg->protocol);

			int   my_command = rip->command;
			int   my_version = rip->version;
			int   my_totalLength = rip->totalLength;
			int   my_addrFamilyIdentifier = rip->addrFamilyIdentifier;
			int   my_routeTag = rip->routeTag;
			int   my_metric = rip->metric;
			char* my_ipAddr = rip->ipAddr;
			char* my_netMask = rip->netMask;
			char* my_nexThop = rip->nexThop;

		    std::cout << "RIP: " << std::endl;
            std::cout << "\tCommand: "  << my_command << std::endl;
			std::cout << "\tVersion: " << my_version << std::endl;
			std::cout << "\tTotal Length: " << my_totalLength << std::endl;

			std::cout << "RipTableEntry:" << std::endl;
			std::cout << "\tAddress Family Identifier: "  << my_addrFamilyIdentifier << std::endl;
			std::cout << "\tRoute Tag: " << my_routeTag << std::endl;
			std::cout << "\tIp Address: " << my_ipAddr << std::endl;
			std::cout << "\tNetmask: "  << my_netMask << std::endl;
			std::cout << "\tNexthop: " << my_nexThop << std::endl;
			std::cout << "\tMetric: " << my_metric << std::endl;
		}
		// prnit L2TP
		else if(msg->type == PROTOCOLTYPE_L2TP)
		{
			struct L2tpHeader *l2tp = (struct L2tpHeader*)(msg->protocol);
            
			int my_controlBytes = l2tp->controlBytes;
			int my_tunnelId = l2tp->tunnelId;
			int my_sessionId = l2tp->sessionId;
			int my_length = l2tp->length;
			int my_ns = l2tp->ns;
			int my_nr = l2tp->nr;

			char* my_type = l2tp->type;

			std::cout << "L2TP: " << std::endl;
            std::cout << "\tControl Bytes: "  << my_controlBytes << std::endl;
			std::cout << "\tTunnel Id: " << my_tunnelId << std::endl;
			std::cout << "\tSession Id: " << my_sessionId << std::endl;
			std::cout << "\tType: "  << my_type << std::endl;
			std::cout << "\tLength: " << my_length << std::endl;
			std::cout << "\tNs: " << my_ns << std::endl;
			std::cout << "\tNr: "  << my_nr << std::endl;
		}
		// print PPP
		else if(msg->type == PROTOCOLTYPE_PPP)
		{
			struct PPPHeader *ppp = (struct PPPHeader*)(msg->protocol);

			int my_broadAddr = ppp->broadAddr;
			int my_controlBytes = ppp->controlBytes;
			int my_nextProtocol = ppp->nextProtocol;

			std::cout << "PPP: " << std::endl;
			std::cout << "\tBroad Address: " << my_broadAddr << std::endl;
            std::cout << "\tControl Bytes: "  << my_controlBytes << std::endl;
			std::cout << "\tNext Layer Protocol: " << my_nextProtocol << std::endl;
		}
		// print AUTHENTICATION
		else if(msg->type == PROTOCOLTYPE_AUTHENTICATION)
		{
			struct AuthenticationHeader *ah = (struct AuthenticationHeader*)(msg->protocol);

			long long my_spi = ah->spi;
			long long my_seqNumber = ah->seqNumber;
			int my_icvLength = ah->icvLength;
			char* my_icvHexStream = ah->icvHexStream;

			std::cout << "AUTHENTICATION: " << std::endl;
			std::cout << "\tSPI: " << my_spi << std::endl;
            std::cout << "\tSequence Number: "  << my_seqNumber << std::endl;
			std::cout << "\tICV Length: " << my_icvLength << std::endl;
			std::cout << "\tICV Hex Stream: " << my_icvHexStream << std::endl;
		}
		// print Payload
		else if(msg->type == PROTOCOLTYPE_PAYLOAD)
		{
			struct Payload *payload = (struct Payload*)(msg->protocol);

			int my_length = payload->length;
			char* my_address = payload->address;
			char* my_rawData = (char *)(payload->rawData);

			std::cout << "PAYLOAD: " << std::endl;
			std::cout << "\tLength: " << my_length << std::endl;
            std::cout << "\tAddress: "  << my_address << std::endl;
			std::cout << "\tRaw Data: " << my_rawData[0] << std::endl; 
		}
		else
		{
			std::cout << "\tUnknown protocol" << std::endl;
		}

		msg = msg->next;
		std::cout << std::endl;
	}
	std::cout << "==================================================" << std::endl;
}

// 释放消息链表
void free_msg(struct My_MSG* my_msg)
{
    struct My_MSG *msg_p = my_msg->next;
    struct My_MSG *msg_q = NULL;

    // 释放头节点
    free(my_msg);
    my_msg = NULL;

    // 释放剩余节点
    while(msg_p)
    {
        msg_q = msg_p;  // p作为前置指针，q作为后置指针
        msg_p = msg_q->next;  // 将p指针移动到下一个结点

        free(msg_q->protocol); // 释放其中的void*指针
        msg_q->protocol = NULL;
        
        free(msg_q);  // 释放q结点所占空间
        msg_q = NULL;
    }
}


// 从string中获取My_MSG链表
struct My_MSG *getMsgFromStr(std::string *str)
{
    struct My_MSG *head = (struct My_MSG*)malloc(sizeof(struct My_MSG));  // 将虚拟节点作为头节点
    struct My_MSG *current = head;    // 当前节点

    std::vector<YAML::Node> nodes;
    nodes = convert_str_to_yaml_vector(str);

    for (std::vector<YAML::Node>::iterator iter = nodes.begin(); iter != nodes.end(); ++iter)
    {
        // cout << nodes.size();
        // std::cout << "PROTOCOLTYPE: " << (*iter)["PROTOCOLTYPE"].as<std::string>() << std::endl;
        std::string protocol_type = (*iter)["PROTOCOLTYPE"].as<std::string>();
        
        // IP Handle
        if(protocol_type == "IP")
        {
            // 定义IP结构体，并从nodes中获取对应值
            struct IpHeader ip;

            ip.version = str_to_integer((*iter)["Version"].as<std::string>());
            ip.headerLength = str_to_integer((*iter)["Header Length"].as<std::string>());
            ip.totalLength = str_to_integer((*iter)["Total Length"].as<std::string>());
            ip.id = str_to_integer((*iter)["IP ID"].as<std::string>());

            std::string temp_srcIP = (*iter)["Source IP"].as<std::string>();
            std::string temp_dstIP = (*iter)["Destination IP"].as<std::string>();
            str_to_chars(temp_srcIP, ip.srcIP);
            str_to_chars(temp_dstIP, ip.dstIP);
            
            // 定义IP结构体的指针
            struct IpHeader *ip_ptr = (struct IpHeader *)malloc(sizeof(struct IpHeader));
            memcpy(ip_ptr, &ip, sizeof(struct IpHeader));
            
            // 定义新的My_MSG结构体,并为其赋值
            struct My_MSG msg0;
            msg0.type = PROTOCOLTYPE_IP;
            msg0.protocol = ip_ptr;
            
            // 定义My_MSG的指针
            struct My_MSG *ip_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(ip_msg, &msg0, sizeof(struct My_MSG));
            
            // 将新的My_MSG结构体添加到链表中，并将current节点后移
            current->next = ip_msg;
            current = current->next;
        }

        // Tcp Handle
        else if(protocol_type == "TCP")
        {
            struct TcpHeader tcp;

            std::string temp_flag = (*iter)["Flag"].as<std::string>();
            str_to_chars(temp_flag, tcp.flag);

            tcp.srcPort = str_to_integer((*iter)["Source Port"].as<std::string>());
            tcp.dstPort = str_to_integer((*iter)["Dest. Port"].as<std::string>());
            tcp.headerLength = str_to_integer((*iter)["Header Length"].as<std::string>());
            tcp.seqNumber = str_to_long_long((*iter)["Sequence Number"].as<std::string>());
            tcp.ackNumber = str_to_long_long((*iter)["Ack Number"].as<std::string>());
            
            struct TcpHeader *tcp_ptr = (struct TcpHeader *)malloc(sizeof(struct TcpHeader));
            memcpy(tcp_ptr, &tcp, sizeof(struct TcpHeader));

            struct My_MSG msg1;
            msg1.type = PROTOCOLTYPE_TCP;
            msg1.protocol = tcp_ptr;

            struct My_MSG *tcp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(tcp_msg, &msg1, sizeof(struct My_MSG));

            current->next = tcp_msg;
            current = current->next;
        }

        // Udp Handle
        else if(protocol_type == "UDP")
        {
            struct UdpHeader udp;

            udp.srcPort = str_to_integer((*iter)["Source Port"].as<std::string>());
            udp.dstPort = str_to_integer((*iter)["Dest. Port"].as<std::string>());
            udp.length = str_to_integer((*iter)["Length"].as<std::string>());

            struct UdpHeader *udp_ptr = (struct UdpHeader *)malloc(sizeof(struct UdpHeader));
            memcpy(udp_ptr, &udp, sizeof(struct UdpHeader));

            struct My_MSG msg2;
            msg2.type = PROTOCOLTYPE_UDP;
            msg2.protocol = udp_ptr;

            struct My_MSG *udp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(udp_msg, &msg2, sizeof(struct My_MSG));

            current->next = udp_msg;
            current = current->next;
        }

        // Sctp Handle
        else if(protocol_type == "SCTP")
        {
            struct SctpHeader sctp;

            sctp.srcPort = str_to_integer((*iter)["Source port"].as<std::string>());
            sctp.dstPort = str_to_integer((*iter)["Destination port"].as<std::string>());
            sctp.verifyTag = str_to_integer((*iter)["Verification Tag"].as<std::string>());
            sctp.checksum = str_to_integer((*iter)["Checksum"].as<std::string>());

            struct SctpHeader *sctp_ptr = (struct SctpHeader *)malloc(sizeof(struct SctpHeader));
            memcpy(sctp_ptr, &sctp, sizeof(struct SctpHeader));

            struct My_MSG msg3;
            msg3.type = PROTOCOLTYPE_SCTP;
            msg3.protocol = sctp_ptr;

            struct My_MSG *sctp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(sctp_msg, &msg3, sizeof(struct My_MSG));

            current->next = sctp_msg;
            current = current->next;
        }

        // Esp Handle
        else if(protocol_type == "ESP")
        {
            struct EspHeader esp;

            esp.spi = str_to_long_long((*iter)["SPI"].as<std::string>());
            esp.seqNumber = str_to_long_long((*iter)["Sequence Number"].as<std::string>());

            struct EspHeader *esp_ptr = (struct EspHeader *)malloc(sizeof(struct EspHeader));
            memcpy(esp_ptr, &esp, sizeof(struct EspHeader));

            struct My_MSG msg4;
            msg4.type = PROTOCOLTYPE_ESP;
            msg4.protocol = esp_ptr;

            struct My_MSG *esp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(esp_msg, &msg4, sizeof(struct My_MSG));

            current->next = esp_msg;
            current = current->next;
        }

        // Gre Handle
        else if(protocol_type == "GRE")
        {
            struct GreHeader gre;

            gre.version = str_to_integer((*iter)["version"].as<std::string>());
            gre.recurControl = str_to_integer((*iter)["Recursion Control"].as<std::string>());
            gre.C_Bit = str_to_integer((*iter)["C bit"].as<std::string>());
            gre.R_Bit = str_to_integer((*iter)["R bit"].as<std::string>());
            gre.K_Bit = str_to_integer((*iter)["K bit"].as<std::string>());
            gre.S_Bit = str_to_integer((*iter)["S bit"].as<std::string>());
            gre.s_Bit = str_to_integer((*iter)["s bit"].as<std::string>());
            gre.protocol = str_to_integer((*iter)["protocol"].as<std::string>());

            struct GreHeader *gre_ptr = (struct GreHeader *)malloc(sizeof(struct GreHeader));
            memcpy(gre_ptr, &gre, sizeof(struct GreHeader));

            struct My_MSG msg5;
            msg5.type = PROTOCOLTYPE_GRE;
            msg5.protocol = gre_ptr;

            struct My_MSG *gre_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(gre_msg, &msg5, sizeof(struct My_MSG));

            current->next = gre_msg;
            current = current->next;
        }

        // Gtp Handle
        else if(protocol_type == "GTP")
        {
            struct GtpHeader gtp;

            gtp.version = str_to_integer((*iter)["Version"].as<std::string>());
            gtp.teid = str_to_integer((*iter)["Teid"].as<std::string>());
            gtp.messageType = str_to_integer((*iter)["MessageType"].as<std::string>());
            gtp.totalLength = str_to_integer((*iter)["TotalLength"].as<std::string>());
            gtp.npduNumber = str_to_integer((*iter)["NpduNumber"].as<std::string>());
            gtp.seqNumber = str_to_long_long((*iter)["SequenceNumber"].as<std::string>());
            
            struct GtpHeader *gtp_ptr = (struct GtpHeader *)malloc(sizeof(struct GtpHeader));
            memcpy(gtp_ptr, &gtp, sizeof(struct GtpHeader));

            struct My_MSG msg6;
            msg6.type = PROTOCOLTYPE_GTP;
            msg6.protocol = gtp_ptr;

            struct My_MSG *gtp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(gtp_msg, &msg6, sizeof(struct My_MSG));

            current->next = gtp_msg;
            current = current->next;
        }

        // HttpRequest Handle
        else if(protocol_type == "HTTP REQUEST")
        {
            struct HttpRequestHeader httpRequest;

            std::string temp_firstLine = (*iter)["First Line"].as<std::string>();
            std::string temp_host = (*iter)["Host"].as<std::string>();
            std::string temp_userAgent = (*iter)["User-Agent"].as<std::string>();
            std::string temp_accept = (*iter)["Accept"].as<std::string>();
            std::string temp_acceptEncoding = (*iter)["Accept-Encoding"].as<std::string>();
            std::string temp_acceptLanguage = (*iter)["Accept-Language"].as<std::string>();
            std::string temp_cookie = (*iter)["Cookie"].as<std::string>();
            std::string temp_referer = (*iter)["Referer"].as<std::string>();
            std::string temp_contentType = (*iter)["Content-Type"].as<std::string>();
            std::string temp_contentLength = (*iter)["Content-Length"].as<std::string>();

            str_to_chars(temp_firstLine, httpRequest.firstLine);
            str_to_chars(temp_host, httpRequest.host);
            str_to_chars(temp_userAgent, httpRequest.userAgent);
            str_to_chars(temp_accept, httpRequest.accept);
            str_to_chars(temp_acceptEncoding, httpRequest.acceptEncoding);
            str_to_chars(temp_acceptLanguage, httpRequest.acceptLanguage);
            str_to_chars(temp_cookie, httpRequest.cookie);
            str_to_chars(temp_referer, httpRequest.referer);
            str_to_chars(temp_contentType, httpRequest.contentType);
            str_to_chars(temp_contentLength, httpRequest.contentLength);

            struct HttpRequestHeader *httpRequest_ptr = (struct HttpRequestHeader *)malloc(sizeof(struct HttpRequestHeader));
            memcpy(httpRequest_ptr, &httpRequest, sizeof(struct HttpRequestHeader));

            struct My_MSG msg7;
            msg7.type = PROTOCOLTYPE_HTTPREQUEST;
            msg7.protocol = httpRequest_ptr;

            struct My_MSG *httpRequest_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(httpRequest_msg, &msg7, sizeof(struct My_MSG));

            current->next = httpRequest_msg;
            current = current->next;
        }

        // HttpResponse Handle
        else if(protocol_type == "HTTP RESPONSE")
        {
            struct HttpResponseHeader httpResponse;

            std::string temp_firstLine = (*iter)["First Line"].as<std::string>();
            std::string temp_server = (*iter)["Server"].as<std::string>();
            std::string temp_contentType = (*iter)["Content-Type"].as<std::string>();
            std::string temp_contentLength = (*iter)["Content-Length"].as<std::string>();

            str_to_chars(temp_firstLine, httpResponse.firstLine);
            str_to_chars(temp_server, httpResponse.server);
            str_to_chars(temp_contentType, httpResponse.contentType);
            str_to_chars(temp_contentLength, httpResponse.contentLength);

            struct HttpResponseHeader *httpResponse_ptr = (struct HttpResponseHeader *)malloc(sizeof(struct HttpResponseHeader));
            memcpy(httpResponse_ptr, &httpResponse, sizeof(struct HttpResponseHeader));

            struct My_MSG msg8;
            msg8.type = PROTOCOLTYPE_HTTPRESPONSE;
            msg8.protocol = httpResponse_ptr;

            struct My_MSG *httphttpResponse_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(httphttpResponse_msg, &msg8, sizeof(struct My_MSG));

            current->next = httphttpResponse_msg;
            current = current->next;
        }

        // Ssl Handle
        else if(protocol_type == "SSL")
        {
            struct SslHeader ssl;
            
            ssl.length = str_to_long_long((*iter)["Length"].as<std::string>());

            std::string temp_type = (*iter)["Type"].as<std::string>();
            std::string temp_version = (*iter)["Version"].as<std::string>();
            std::string temp_alertLevel = (*iter)["Alert Level"].as<std::string>();
            str_to_chars(temp_type, ssl.type);
            str_to_chars(temp_version, ssl.version);
            str_to_chars(temp_alertLevel, ssl.alertLevel);

            struct SslHeader *ssl_ptr = (struct SslHeader *)malloc(sizeof(struct SslHeader));
            memcpy(ssl_ptr, &ssl, sizeof(struct SslHeader));

            struct My_MSG msg9;
            msg9.type = PROTOCOLTYPE_SSL;
            msg9.protocol = ssl_ptr;

            struct My_MSG *ssl_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(ssl_msg, &msg9, sizeof(struct My_MSG));

            current->next = ssl_msg;
            current = current->next;
        }

        // Bgp Handle
        else if(protocol_type == "BGP")
        {
            struct BgpHeader bgp;

            bgp.marker = str_to_long_long((*iter)["Marker"].as<std::string>());
            bgp.length = str_to_integer((*iter)["Length"].as<std::string>());

            std::string temp_messageType = (*iter)["Message Type"].as<std::string>();
            str_to_chars(temp_messageType, bgp.messageType);

            struct BgpHeader *bgp_ptr = (struct BgpHeader *)malloc(sizeof(struct BgpHeader));
            memcpy(bgp_ptr, &bgp, sizeof(struct BgpHeader));

            struct My_MSG msg10;
            msg10.type = PROTOCOLTYPE_BGP;
            msg10.protocol = bgp_ptr;

            struct My_MSG *bgp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(bgp_msg, &msg10, sizeof(struct My_MSG));

            current->next = bgp_msg;
            current = current->next;
        }

        // Ospf Handle
        else if(protocol_type == "OSPF")
        {
            struct OspfHeader ospf;

            ospf.totalLength = str_to_integer((*iter)["total length"].as<std::string>());
            std::string temp_srcRouter = (*iter)["source router"].as<std::string>();
            std::string temp_areaId = (*iter)["area id"].as<std::string>();
            str_to_chars(temp_srcRouter, ospf.srcRouter);
            str_to_chars(temp_areaId, ospf.areaId);

            struct OspfHeader *ospf_ptr = (struct OspfHeader *)malloc(sizeof(struct OspfHeader));
            memcpy(ospf_ptr, &ospf, sizeof(struct OspfHeader));

            struct My_MSG msg11;
            msg11.type = PROTOCOLTYPE_OSPF;
            msg11.protocol = ospf_ptr;

            struct My_MSG *ospf_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(ospf_msg, &msg11, sizeof(struct My_MSG));

            current->next = ospf_msg;
            current = current->next;
        }

        // Rip Handle
        else if(protocol_type == "RIP")
        {
            struct RipHeader rip;

            rip.command = str_to_integer((*iter)["command"].as<std::string>());
            rip.version = str_to_integer((*iter)["version"].as<std::string>());
            rip.totalLength = str_to_integer((*iter)["total length"].as<std::string>());
            rip.addrFamilyIdentifier = str_to_integer((*iter)["address family identifier"].as<std::string>());
            rip.routeTag = str_to_integer((*iter)["route tag"].as<std::string>());
            rip.metric = str_to_integer((*iter)["metric"].as<std::string>());

            std::string temp_ipAddress = (*iter)["ip address"].as<std::string>();
            std::string temp_netMask = (*iter)["netmask"].as<std::string>();
            std::string temp_nexThop = (*iter)["nexthop"].as<std::string>();
            str_to_chars(temp_ipAddress,rip.ipAddr);
            str_to_chars(temp_netMask,rip.netMask);
            str_to_chars(temp_nexThop,rip.nexThop);

            struct RipHeader *rip_ptr = (struct RipHeader *)malloc(sizeof(struct RipHeader));
            memcpy(rip_ptr, &rip, sizeof(struct RipHeader));

            struct My_MSG msg12;
            msg12.type = PROTOCOLTYPE_RIP;
            msg12.protocol = rip_ptr;

            struct My_MSG *rip_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(rip_msg, &msg12, sizeof(struct My_MSG));

            current->next = rip_msg;
            current = current->next;
        }

        // L2tp Handle
        else if(protocol_type == "L2TP")
        {
            struct L2tpHeader l2tp;

            l2tp.controlBytes = str_to_integer((*iter)["control bytes"].as<std::string>());
            l2tp.tunnelId = str_to_integer((*iter)["tunnel id"].as<std::string>());
            l2tp.sessionId = str_to_integer((*iter)["session id"].as<std::string>());
            l2tp.length = str_to_integer((*iter)["length"].as<std::string>());
            l2tp.ns = str_to_integer((*iter)["Ns"].as<std::string>());
            l2tp.nr = str_to_integer((*iter)["Nr"].as<std::string>());

            std::string temp_controlType = (*iter)["type"].as<std::string>();
            str_to_chars(temp_controlType, l2tp.type);

            struct L2tpHeader *l2tp_ptr = (struct L2tpHeader *)malloc(sizeof(struct L2tpHeader));
            memcpy(l2tp_ptr, &l2tp, sizeof(struct L2tpHeader));

            struct My_MSG msg13;
            msg13.type = PROTOCOLTYPE_L2TP;
            msg13.protocol = l2tp_ptr;

            struct My_MSG *l2tp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(l2tp_msg, &msg13, sizeof(struct My_MSG));

            current->next = l2tp_msg;
            current = current->next;
        }

        // PPP Handle
        else if(protocol_type == "PPP")
        {
            struct PPPHeader ppp;

            ppp.broadAddr = str_to_integer((*iter)["Broadcast Address"].as<std::string>());
            ppp.controlBytes = str_to_integer((*iter)["Control bytes"].as<std::string>());
            ppp.nextProtocol = str_to_integer((*iter)["next layer protocol"].as<std::string>());

            struct PPPHeader *ppp_ptr = (struct PPPHeader *)malloc(sizeof(struct PPPHeader));
            memcpy(ppp_ptr, &ppp, sizeof(struct PPPHeader));

            struct My_MSG msg14;
            msg14.type = PROTOCOLTYPE_PPP;
            msg14.protocol = ppp_ptr;

            struct My_MSG *ppp_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(ppp_msg, &msg14, sizeof(struct My_MSG));

            current->next = ppp_msg;
            current = current->next;
        }
        
        // Authentication Handle
        else if(protocol_type == "AUTHENTICATION")
        {
            struct AuthenticationHeader ah;

            ah.spi = str_to_long_long((*iter)["SPI"].as<std::string>());
            ah.seqNumber = str_to_long_long((*iter)["Sequence Number"].as<std::string>());
            ah.icvLength = str_to_integer((*iter)["ICV Length"].as<std::string>());

            std::string temp_icvHexStream = (*iter)["ICV Hex Stream"].as<std::string>();
            str_to_chars(temp_icvHexStream, ah.icvHexStream);
            
            struct AuthenticationHeader *ah_ptr = (struct AuthenticationHeader *)malloc(sizeof(struct AuthenticationHeader));
            memcpy(ah_ptr, &ah, sizeof(struct AuthenticationHeader));

            struct My_MSG msg15;
            msg15.type = PROTOCOLTYPE_AUTHENTICATION;
            msg15.protocol = ah_ptr;

            struct My_MSG *ah_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(ah_msg, &msg15, sizeof(struct My_MSG));

            current->next = ah_msg;
            current = current->next;
        }

        //PayLoad Handle 
        else if(protocol_type == "PAYLOAD")
        {
            struct Payload payload;
            
            payload.length = str_to_integer((*iter)["Length"].as<std::string>());
            std::string temp_address = (*iter)["Address"].as<std::string>();
            std::string temp_rawData = (*iter)["RawData"].as<std::string>();

            str_to_chars(temp_address, payload.address);
            // str_to_chars(temp_rawData, payload.rawData);
			void* p_temp_rawData = calloc(temp_rawData.size(),sizeof(char));
			memcpy(p_temp_rawData, &temp_rawData, temp_rawData.size()*sizeof(char));

			payload.rawData = p_temp_rawData;
			
            struct Payload *payload_ptr = (struct Payload *)malloc(sizeof(struct Payload));

            memcpy(payload_ptr, &payload, sizeof(struct Payload));

            struct My_MSG msg16;
            msg16.type = PROTOCOLTYPE_PAYLOAD;
            msg16.protocol = payload_ptr;

            struct My_MSG *payload_msg = (struct My_MSG *)malloc(sizeof(struct My_MSG));
            memcpy(payload_msg, &msg16, sizeof(struct My_MSG));

            current->next = payload_msg;
            current = current->next;
        }
        else
        {
            std::cout << "error protocol" << std::endl;
        }
    }
    
    return head;    // 返回头节点
}



#endif