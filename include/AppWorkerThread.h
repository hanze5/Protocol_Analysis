#pragma once

#include "Common.h"

#include "PacketUtils.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"
#include "ProtocolAnalysis.h"

#include <iostream>
#include "stdlib.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"

#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

#include "BgpLayer.h"
#include "GreLayer.h"
#include "GtpLayer.h"
#include "HttpLayer.h"
#include "IPReassembly.h"
#include "IPSecLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "IpAddress.h"
#include "L2tpLayer.h"
#include "LRUList.h"
#include "Logger.h"
#include "OspfLayer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PcapPlusPlusVersion.h"
#include "ProtocolType.h"
#include "Reassembly.h"
#include "RipLayer.h"
#include "SSLLayer.h"
#include "SctpLayer.h"
#include "SystemUtils.h"
#include "TcpLayer.h"
#include "TcpReassembly.h"
#include "UdpLayer.h"
#include "getopt.h"
#include <algorithm>
#include <getopt.h>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <unistd.h>

#include <rte_ring.h>
#include <rte_mempool.h>



std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
	switch (protocolType)
	{
	case pcpp::Ethernet:
		return "Ethernet";
	case pcpp::IPv4:
		return "IPv4";
	case pcpp::TCP:
		return "TCP";
	case pcpp::HTTPRequest:
	case pcpp::HTTPResponse:
		return "HTTP";
	default:
		return "Unknown";
	}
}

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
{
	std::string result = "";
	if (tcpLayer->getTcpHeader()->synFlag == 1)
		result += "SYN ";
	if (tcpLayer->getTcpHeader()->ackFlag == 1)
		result += "ACK ";
	if (tcpLayer->getTcpHeader()->pshFlag == 1)
		result += "PSH ";
	if (tcpLayer->getTcpHeader()->cwrFlag == 1)
		result += "CWR ";
	if (tcpLayer->getTcpHeader()->urgFlag == 1)
		result += "URG ";
	if (tcpLayer->getTcpHeader()->eceFlag == 1)
		result += "ECE ";
	if (tcpLayer->getTcpHeader()->rstFlag == 1)
		result += "RST ";
	if (tcpLayer->getTcpHeader()->finFlag == 1)
		result += "FIN ";

	return result;
}

extern struct rte_ring *message_ring;
extern struct rte_mempool *message_pool;
extern bool global_debug;

std::string printTcpOptionType(pcpp::TcpOptionType optionType)
{
	switch (optionType)
	{
	case pcpp::PCPP_TCPOPT_NOP:
		return "NOP";
	case pcpp::PCPP_TCPOPT_TIMESTAMP:
		return "Timestamp";
	default:
		return "Other";
	}
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
	switch (httpMethod)
	{
	case pcpp::HttpRequestLayer::HttpGET:
		return "GET";
	case pcpp::HttpRequestLayer::HttpPOST:
		return "POST";
	default:
		return "Other";
	}
}

//从文件读入到string里
std::string readFileIntoString(char *filename)
{
    std::ifstream ifile(filename);
    //将文件读入到ostringstream对象buf中
    std::ostringstream buf;
    char ch;
    while (buf && ifile.get(ch))
        buf.put(ch);
    //返回与流对象buf关联的字符串
    return buf.str();
}

// // 五元组->数据统计的map
// // typedef representing the manager and its iterator
// typedef std::map<std::string, ReassemblyData> ReassemblyMgr;
// typedef std::map<std::string, ReassemblyData>::iterator ReassemblyMgrIter;

// // typedef representing the connection manager and its iterator
// typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;
// typedef std::map<uint32_t, TcpReassemblyData>::iterator TcpReassemblyConnMgrIter;


// /**
//  * The worker thread class which does all the work. It's initialized with pointers to the RX and TX devices, then it runs in
//  * an endless loop which reads packets from the RX device and sends them to the TX device.
//  * The endless loop is interrupted only when the thread is asked to stop (calling its stop() method)
//  */



static void MyOnMessageReadyCallback(std::string *data, std::string tuplename, void *userCookie)
{
	/* 	1. manager 存 ReassemblyData   									yes
		2. manager 的指定 ReassemblyData 里边fileStream 是否为NULL
			2.1 将当前（指传入的参数）的名称加入opened列表
			2.2 如果打开的文件已达上限，关闭目前的
			2.3 设置文件名
			2.4 打开文件， 模式由之前2.2设置的reopenFileStreams决定
		3. 更改ReassemblyData里的统计值
		4. 将数据写入打开的文件里
	 */

	// 1.

	// extract the manager from the user cookie
	ReassemblyMgr *mgr = (ReassemblyMgr *)userCookie;

	// check if this tuple already appears in the manager. If not add it
	ReassemblyMgrIter iter = mgr->find(tuplename);
	if (iter == mgr->end())
	{
		mgr->insert(std::make_pair(tuplename, ReassemblyData()));
		iter = mgr->find(tuplename);
	}

	// 2.
	if(!global_debug)
	{
		//  if filestream isn't open yet
		if (iter->second.fileStream == NULL)
		{
			// 2.1

			std::string nameToCloseFile;
			int result = GlobalConfig::getInstance().getRecentFilesWithActivity()->put(tuplename, &nameToCloseFile);

			// 2.2

			// 等于1，需要关闭最近未使用
			if (result == 1)
			{
				ReassemblyMgrIter iter2 = mgr->find(nameToCloseFile);
				if (iter2 != mgr->end())
				{
					if (iter2->second.fileStream != NULL)
					{
						// close the file
						GlobalConfig::getInstance().closeFileSteam(iter2->second.fileStream);
						iter2->second.fileStream = NULL;

						// set the reopen flag to true to indicate that next time this file will be opened it will be opened
						// in append mode (and not overwrite mode)
						iter2->second.reopenFileStream = true;
					}
				}
			}

			// 2.3

			// get the file name according to the 5-tuple etc.
			std::string name = tuplename + ".txt";
			std::string fileName = GlobalConfig::getInstance().getFileName(name);

			// 2.4

			// open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was
			// already opened before)
			iter->second.fileStream = GlobalConfig::getInstance().openFileStream(fileName, iter->second.reopenFileStream);
		}
	}
	

	// 3.

	// count number of packets and bytes
	iter->second.numOfDataPackets++;

	// set new processed packet number
	GlobalConfig::getInstance().PacketNum++;

	// 4.
	// *iter->second.fileStream << *data << std::endl;


	// write the new data to the file if debug
	if(global_debug)
	{
		*iter->second.fileStream << *data << std::endl;
	}	
	else{ //write the new data to rte_ring if not debug
		void *msg = NULL;
		printf("共享内存大小%d \n",rte_mempool_avail_count(message_pool));


		if(!rte_mempool_avail_count(message_pool)) return ;
	
		if (rte_mempool_get(message_pool, &msg) < 0){
			printf("Failed to get message buffer\n");  //Buffer full 
			
		}
		

		char *fn = "/home/dawnlake/workspace/dpdk_workspace/yaml_test/input1.txt";
		std::string str;
		str = readFileIntoString(fn);

		// printf("send %s \n %d \n", str.c_str(),strlen(str.c_str()));

		memcpy((char *)msg,str.c_str(),str.size()+1);	
		
		// printf(" %ld==%ld == %d?",strlen((char *)msg),strlen(str.c_str()),str.size());

		// printf("send ===========================================  \n%s\n", (char *)msg);


		// memcpy((char *)msg,(*data).c_str(),data->size()*sizeof(char));

		int res = rte_ring_enqueue(message_ring, msg);

		usleep(500);
		// printf("send %s \n\n", (char *)msg);
		if (res < 0){
			// error
			RTE_LOG(ERR,APPLICATION,"Not enough room in the ring to enqueue\n");    			
		}	
	}
}

/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void MytcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie,
										  pcpp::Packet *tcpPacket, pcpp::Layer *nextLayer, pcpp::IPAddress *IpSrc,
										  pcpp::IPAddress *IpDst, void *UserCookie,
										  std::queue<pcpp::Packet> *quePointer)
{
	// extract the connection manager from the user cookie
	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

	// check if this flow already appears in the connection manager. If not add it
	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
	}

	// if this messages comes on a different side than previous message seen on this connection
	if (sideIndex != iter->second.curSide)
	{
		// count number of message in each side
		iter->second.numOfMessagesFromSide[sideIndex]++;

		// set side index as the current active side
		iter->second.curSide = sideIndex;
	}

	// count number of packets and bytes in each side of the connection
	iter->second.numOfDataPackets[sideIndex]++;
	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

	// handle the tcp packet
	HandleTcpPayload(nextLayer, *IpSrc, *IpDst, tcpPacket, UserCookie, MyOnMessageReadyCallback, quePointer);
}





// /**
//  * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the
//  * connection from the connection manager and writes the metadata file if requested by the user
//  */
// static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData &connectionData,
// 											pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie)
// {
// 	// get a pointer to the connection manager
// 	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

// 	// find the connection in the connection manager by the flow key
// 	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

// 	// connection wasn't found - shouldn't get here
// 	if (iter == connMgr->end())
// 		return;

// 	// remove the connection from the connection manager
// 	connMgr->erase(iter);
// }

// /**
//  * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the
//  * connection to the connection manager
//  */
// static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData &connectionData, void *userCookie)
// {
// 	// get a pointer to the connection manager
// 	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

// 	// look for the connection in the connection manager
// 	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

// 	// assuming it's a new connection
// 	if (iter == connMgr->end())
// 	{
// 		// add it to the connection manager
// 		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
// 	}
// }

// /**
//  * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
//  */
// static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie,
// 										pcpp::Packet *tcpPacket, pcpp::Layer *nextLayer, pcpp::IPAddress *IpSrc,
// 										pcpp::IPAddress *IpDst, void *UserCookie,std::queue<pcpp::RawPacket> *quePointer)
// {
// 	// extract the connection manager from the user cookie
// 	TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *)userCookie;

// 	// check if this flow already appears in the connection manager. If not add it
// 	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
// 	if (iter == connMgr->end())
// 	{
// 		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
// 		iter = connMgr->find(tcpData.getConnectionData().flowKey);
// 	}

// 	// if this messages comes on a different side than previous message seen on this connection
// 	if (sideIndex != iter->second.curSide)
// 	{
// 		// count number of message in each side
// 		iter->second.numOfMessagesFromSide[sideIndex]++;

// 		// set side index as the current active side
// 		iter->second.curSide = sideIndex;
// 	}

// 	// count number of packets and bytes in each side of the connection
// 	iter->second.numOfDataPackets[sideIndex]++;
// 	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

// 	// handle the tcp packet
// 	HandleTcpPayload(nextLayer, *IpSrc, *IpDst, tcpPacket, UserCookie, OnMessageReadyCallback, quePointer);
// }




class AppWorkerThread : public pcpp::DpdkWorkerThread
{
private:
	AppWorkerConfig& m_WorkerConfig;
	bool m_Stop;
	uint32_t m_CoreId;

	

	// run the de-fragmentation process
	pcpp::DefragStats stats;

	// queue to cache ip packets
	std::queue<pcpp::Packet> q;
	std::queue<pcpp::Packet> *quePointer = &q;

	// create the object which manages info
	ReassemblyMgr mgr;

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;

	pcpp::IPReassembly::ReassemblyStatus status;

	bool m_isdebug;



public:
	AppWorkerThread(AppWorkerConfig& workerConfig) :
		m_WorkerConfig(workerConfig), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1)
	{
			dz_set_local_packets_num(0);
			dz_set_local_Bytes_num(0);	
	}

	virtual ~AppWorkerThread()
	{
		// do nothing
	}
	// implement abstract methods

	bool run(uint32_t coreId)
	{
		m_CoreId = coreId;
		m_Stop = false;
		pcpp::DpdkDevice* rxDevice = m_WorkerConfig.RxDevice;
		// m_WorkerConfig.maxPacketsToStore;

		pcpp::TcpReassembly tcpReassembly(q,MytcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback,
									  tcpReassemblyConnectionEndCallback);

		// set the info manager for tcpReassembly
		tcpReassembly.SetHandleCookie(&mgr);

		// create an instance of IPReassembly
		std::cout<<"ipReassembly needs"<<m_WorkerConfig.maxPacketsToStore<<std::endl;
		pcpp::IPReassembly ipReassembly(NULL, NULL, m_WorkerConfig.maxPacketsToStore);
		pcpp::IPReassembly::ReassemblyStatus status;

		// if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
		if (!rxDevice)
		{
			return true;
		} 

		#define MAX_RECEIVE_BURST 128
		pcpp::MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};
		// std::cout<<"core "<<m_CoreId<<"RxQueues_begin = "<<m_WorkerConfig.RxQueues_begin<<" RxQueues_end = "<<m_WorkerConfig.RxQueues_end<<std::endl;
		// main loop, runs until be told to stop
		while (!m_Stop)
		{
			for(uint16_t i =0 ; i < m_WorkerConfig.dz_RxQueues.size(); i++)
			{
				pcpp::RawPacket* p_rawPacket;
				pcpp::RawPacket rawPacket;

				// receive packets from network on the specified DPDK device
				uint16_t packetsReceived = rxDevice->receivePackets(packetArr, MAX_RECEIVE_BURST, m_WorkerConfig.dz_RxQueues[i]);
				
				if (packetsReceived > 0)
				{
					for(int j = 0 ;j<packetsReceived;j++)
					{
						pcpp::Packet *parsedPacket;
						// rawPacket=packetArr[j];
						p_rawPacket =static_cast<pcpp::RawPacket *>(packetArr[j]);
						// // pcpp::Packet parsedPacket(packetArr[j]);
						// if (!quePointer->empty())
						// {
						// 	rawPacket = quePointer->front();
						// 	quePointer->pop();
						// 	j--;

						// }
						// else rawPacket = * p_rawPacket;

						if (!quePointer->empty())
						{
							pcpp::Packet tempPacket = quePointer->front();
							parsedPacket = &tempPacket;
							quePointer->pop();
						}
						else
						{
							// rawPacket = * p_rawPacket;
							parsedPacket = new pcpp::Packet(p_rawPacket);
						}

						bool defragPacket = true;
						stats.totalPacketsRead++;

						// // check if packet is of type IPv4 or IPv6
						// pcpp::Packet parsedPacket(&rawPacket);
						if (parsedPacket->isPacketOfType(pcpp::IPv4))
						{
							stats.ipv4Packets++;
						}
						else if (parsedPacket->isPacketOfType(pcpp::IPv6))
						{
							stats.ipv6Packets++;
						}
						else // if not - set the packet as not marked for de-fragmentation
						{
							defragPacket = false;
						}

						// if fragment is marked for de-fragmentation
						if (defragPacket)
						{
							stats.totalPacketsWritten++;

							// pcpp::ReassemblyStatus reassemblePacketStatus = Reassemble(
							// 	&ipReassembly, &status, quePointer, &parsedPacket, &mgr, OnMessageReadyCallback, tcpReassembly);
							Reassemble(
								&ipReassembly, &status, quePointer, parsedPacket, &mgr, MyOnMessageReadyCallback, tcpReassembly);

							// // TODO(ycyaoxdu): handle status
							// PCPP_LOG_DEBUG("got reassemble status: " << reassemblePacketStatus);
						}
						// if packet isn't marked for de-fragmentation but the user asked to write all packets to output file
						else
						{
							stats.totalPacketsWritten++;
						}

						if (!parsedPacket->ShouldNotDelete())
						{
							delete parsedPacket;
						}
						
						dz_change_local_packets_num(1);
						dz_change_local_Bytes_num(packetArr[j]->getRawDataLen());
						//std::cout<<"core "<<m_CoreId<<" queue "<<i <<" 正在处理第 "<<dz_get_local_packets_num()<<" 个数据包"<<std::endl;

					}
				// std::cout<<"core "<< m_CoreId << " queue " << i<<" received "<<dz_get_local_packets_num() <<" packets!"<<std::endl;
				}
				
			}
		}

		// free packet array (frees all mbufs as well)
		for (int i = 0; i < MAX_RECEIVE_BURST; i++)
		{
			if (packetArr[i] != NULL)
				delete packetArr[i];
		}

		return true;
	}

	void stop()
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	uint32_t getCoreId() const
	{
		return m_CoreId;
	}

};
