

#include "../include/Common.h"
#include "../include/AppWorkerThread.h"
#include "../include/ConfigReader.h"

#include<bits/stdc++.h>

#include "DpdkDeviceList.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "TablePrinter.h"
#include <rte_ring.h>
#include <rte_mempool.h>

#include <vector>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <string>
#include <sstream>
#include <unistd.h>
#include <ctime>
#include <time.h>
#include <rte_log.h>

#include <math.h>

#include <arpa/inet.h>
#include <bitset>






// #define DEFAULT_MBUF_POOL_SIZE 16383
// #define DEFAULT_QUEUE_QUANTITY 16
// #define DEFAULT_CORE_MASK_TO_USE 131071

#define DEFAULT_MBUF_POOL_SIZE 1023
#define DEFAULT_QUEUE_QUANTITY 1
#define DEFAULT_CORE_TO_USE 1

/* size of a parsed string */
#define STR_TOKEN_SIZE 512*1024

static const char *_MSG_POOL = "MSG_POOL";
static const char *_MSG_RING = "MSG_RING";

struct rte_ring *message_ring;
struct rte_mempool *message_pool;
std::ofstream status_output;

bool global_debug = false;


/**
 * Print to console all available DPDK ports. Used by the -l switch
 */
void listDpdkPorts()
{
	std::cout << "DPDK port list:" << std::endl;

	// go over all available DPDK devices and print info for each one
	std::vector<pcpp::DpdkDevice*> deviceList = pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList();
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
	{
		pcpp::DpdkDevice* dev = *iter;
		std::cout << "   "
			<< " Port #" << dev->getDeviceId() << ":"
			<< " MAC address='" << dev->getMacAddress() << "';"
			<< " PCI address='" << dev->getPciAddress() << "';"
			<< " PMD='" << dev->getPMDName() << "'"
			<< std::endl;
	}
}


struct Protocol_Analysis
{
	bool shouldStop;
	std::vector<pcpp::DpdkWorkerThread*>* workerThreadsVector;

	Protocol_Analysis() : shouldStop(false), workerThreadsVector(NULL) {}
};


/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void* cookie)
{
	Protocol_Analysis* args = (Protocol_Analysis*)cookie;

	std::cout
		<< std::endl << std::endl
		<< "Application stopped"
		<< std::endl;

	// stop worker threads
	pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
	pcpp::Logger::getInstance().closeOutputFile();
	status_output.close();

	args->shouldStop = true;
}


/**
 * main method of the application. Responsible for parsing user args, preparing worker thread configuration, creating the worker threads and activate them.
 * At program termination worker threads are stopped, statistics are collected from them and printed to console
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::vector<int> dpdkPortVec;

	// time_t dz_start_time,dz_end_time;
	// dz_start_time = time(NULL);


	// if core mask is not provided, use the 3 first cores
	pcpp::CoreMask coreMaskToUse = (pcpp::getCoreMaskForAllMachineCores() & 0xff);

	uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;
	uint16_t queueQuantity = DEFAULT_QUEUE_QUANTITY;
	coreMaskToUse =  DEFAULT_CORE_TO_USE;
	
	dpdkPortVec.push_back(0);
	// dpdkPortVec.push_back(1);

	// extract core vector from core mask
	std::vector<pcpp::SystemCore> coresToUse;
	createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// // need minimum of 3 cores to start - 1 management core + 1 (or more) worker thread(s)
	// if (coresToUse.size() < 3)
	// {
	// 	EXIT_WITH_ERROR("Needed minimum of 3 cores to start the application");
	// }

	//将dpdk日志写入文件中
	// FILE * f = fopen("/var/log/dpdk/dpdk_output.log","w+");
	FILE * f = fopen("../debug_log_output/dpdk_output.log","w+");
	
	if(rte_openlog_stream(f))
	{
		RTE_LOG(ERR,APPLICATION,"无法打开日志文件");
		exit(1);
	}
	//设置PcapPlusPlus日志输出文件
	pcpp::Logger::getInstance().setMyLogPrinter();
	pcpp::Logger::getInstance().setOutputFile("../debug_log_output/PcapPlusPlus_output.log");



	//读取配置文件信息================================================
	ini::ConfigReader config;
	bool ret = config.ReadConfig("../config.ini");
	if (ret == false) 
    {
		RTE_LOG(ERR,APPLICATION,"ReadConfig is Error,Cfg=%s", "config.ini");
		return 1;
	}
	//判断debug模式
	bool isdebug = config.ReadBool("dpdk_config", "isdebug", false);
	if(isdebug) std::cout<<"yes debug"<<std::endl;
	else std::cout<<"no "<<std::endl;
	//获取工作线程数
	int num_of_cores = config.ReadInt("dpdk_config", "num_of_cores", DEFAULT_CORE_TO_USE);
	coreMaskToUse = pow(2,num_of_cores+1)-1;
	//获取每个工作线程分配的缓冲池大小
	mBufPoolSize = config.ReadInt("dpdk_config", "mempoolsize_per_core",DEFAULT_MBUF_POOL_SIZE);
	//获取要开启的dpdk队列数
	queueQuantity = config.ReadInt("dpdk_config", "queues_to_use",DEFAULT_QUEUE_QUANTITY);
	if(num_of_cores>queueQuantity)
	{
		RTE_LOG(ERR,APPLICATION,"工作线程数不得大于队列数 %d\n",num_of_cores);
	}
 

	if(isdebug)
	{
		pcpp::Logger::getInstance().setAllModlesToLogLevel(pcpp::Logger::Debug);
		rte_log_set_level(RTE_LOGTYPE_EAL,RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_MALLOC,RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_MEMPOOL,RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_PMD,RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_HASH,RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_MBUF,RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_EVENTDEV,RTE_LOG_DEBUG);
		// rte_log_set_level(RTE_LOGTYPE_APPLICATION,RTE_LOG_DEBUG);

		global_debug = true;
	}
	RTE_LOG(INFO,APPLICATION,"将要设置的工作线程数为 %d\n",num_of_cores);
	RTE_LOG(INFO,APPLICATION,"将要设置的缓冲池大小 %d\n",mBufPoolSize);
	RTE_LOG(INFO,APPLICATION,"将要设置开启dpdk队列数 %d\n",queueQuantity);
	


	//配置文件信息读取结束============================================

	// initialize DPDK
	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize))
	{
		// EXIT_WITH_ERROR("Couldn't initialize DPDK");
		RTE_LOG(ERR,APPLICATION,"Couldn't initialize DPDK");
		exit(1);
	}

	const unsigned flags = 0;
	const unsigned ring_size = 64*1024;
	const unsigned pool_size = pow(2,10)-1;
	const unsigned pool_cache = 32;
	const unsigned priv_data_sz = 0;

	
	message_ring = rte_ring_create(_MSG_RING, ring_size, rte_socket_id(), flags);
    message_pool = rte_mempool_create(_MSG_POOL, pool_size,
            STR_TOKEN_SIZE, pool_cache, priv_data_sz,
            NULL, NULL, NULL, NULL,
            rte_socket_id(), flags);

	//如果没有创建成功或者没找到就直接退出
	// error
	if (message_ring == NULL)
	{
        RTE_LOG(ERR,APPLICATION,"Problem getting message_ring\n");
		rte_exit(EXIT_FAILURE, "Problem getting message_ring\n");
	}

	if (message_pool == NULL)
	{
		RTE_LOG(ERR,APPLICATION,"Problem getting message pool\n");
		rte_exit(EXIT_FAILURE, "Problem getting message pool\n");
	}


	
	std::cout<<"coreMaskToUse = "<<  coreMaskToUse <<std::endl;
	// removing DPDK master core from core mask because DPDK worker threads cannot run on master core
	coreMaskToUse = coreMaskToUse & ~(pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

	std::cout<<"coreMaskToUse = "  <<coreMaskToUse <<std::endl;
	std::cout<<"CPU mask: "<< pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore().Mask<<"  "<< pcpp::getCoreMaskForAllMachineCores()<<std::endl;

	// re-calculate cores to use after removing master core
	coresToUse.clear();
	createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

	// collect the list of DPDK devices
	std::vector<pcpp::DpdkDevice*> dpdkDevicesToUse;
	for (std::vector<int>::iterator iter = dpdkPortVec.begin(); iter != dpdkPortVec.end(); iter++)
	{
		pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(*iter);
		if (dev == NULL)
		{
			EXIT_WITH_ERROR("DPDK device for port " << *iter << " doesn't exist");
		}
		dpdkDevicesToUse.push_back(dev);
		PCPP_LOG_INFO("DpdkDevice  Name=" << dev->getDeviceName() << "', PMD='" << dev->getPMDName() << "', MAC Addr='" << dev->getMacAddress() << "', RX num = " << dev->getTotalNumOfRxQueues());
	}

	// go over all devices and open them
	for (std::vector<pcpp::DpdkDevice*>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
	{
		if (!(*iter)->openMultiQueues(queueQuantity, 1))
		{
			EXIT_WITH_ERROR("Couldn't open DPDK device #" << (*iter)->getDeviceId() << ", PMD '" << (*iter)->getPMDName() << "'");
		}
	}

	// prepare configuration for every core
	AppWorkerConfig workerConfigArr[num_of_cores];


	
	for(int i = 0;i<queueQuantity;i++ )
	{
		if(queueQuantity<num_of_cores)
		{
			workerConfigArr[queueQuantity%num_of_cores].CoreId = coresToUse.at(queueQuantity%num_of_cores).Id;
			workerConfigArr[queueQuantity%num_of_cores].RxDevice = dpdkDevicesToUse.at(0);
			workerConfigArr[queueQuantity%num_of_cores].dz_RxQueues.push_back(i);
		}
		workerConfigArr[queueQuantity%num_of_cores].dz_RxQueues.push_back(i);
		
	}


 
 
	// create worker thread for every core
	std::vector<pcpp::DpdkWorkerThread*> workerThreadVec;
	for(int i = 0 ; i < num_of_cores ; i++ )
	{
		workerThreadVec.push_back(new AppWorkerThread(workerConfigArr[i]));
	}


	// start all worker threads
	if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
	{
		EXIT_WITH_ERROR("Couldn't start worker threads");
	}

	// register the on app close event to print summary stats on app termination
	Protocol_Analysis args;
	args.workerThreadsVector = &workerThreadVec;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// infinite loop (until program is terminated)
	uint64_t counter = 0;
	uint64_t dz_global_packets_num;
	uint128_t dz_global_Bytes_num;
	

	char tmp[32] ;
	//状态日志
	
	status_output.open("../debug_log_output/status_output.log");
	std::ostringstream sstream;
	// Keep running while flag is on
	while (!args.shouldStop)
	{
		// Sleep for 1 second
		sleep(1);
		//时间戳用到的
		time_t t = time(0);
		
		// dz_end_time = time(NULL);
		strftime(tmp, sizeof(tmp), "%Y-%m-%d_%H:%M:%S", localtime(&t));
		std::string date(tmp);

		pcpp::DpdkDeviceList::getInstance().Collect_Application_status();
		dz_global_packets_num = pcpp::DpdkDeviceList::getInstance().dz_get_global_packets_num();
		dz_global_Bytes_num = pcpp::DpdkDeviceList::getInstance().dz_get_global_Bytes_num();

		


		status_output << std::left
		<< "APPLICATION:"
		<< std::setprecision(10)
		<< "["<< date.c_str() <<"]  共处理数据包"<<dz_global_packets_num<< " 个 ,共 " << (float)(dz_global_Bytes_num*1.0/(1024*1024*1024)) << " GB" <<std::endl;


		
		// RTE_LOG(INFO,APPLICATION,"[%s]  共处理数据包 %ld 个 ,共 %f GB\n",date.c_str(),dz_global_packets_num,(float)(dz_global_Bytes_num*1.0/(1024*1024*1024)));

		pcpp::DpdkDeviceList::getInstance().Reset_Application_status();
		
		
		

		counter++;
	}

	// int dz_global_packets_num = pcpp::DpdkDeviceList::getInstance().dz_get_global_packets_num();
	// long long dz_global_Bytes_num = pcpp::DpdkDeviceList::getInstance().dz_get_global_Bytes_num();
	// dz_end_time = time(NULL);
	// std::cout<<"程序运行时间 "<<dz_end_time - dz_start_time<<"秒"<<std::endl;
	// std::cout<<"其间共处理数据包 "<< dz_global_packets_num<<"个"<<std::endl;
	// std::cout<<"共计大小" <<dz_global_Bytes_num<<" Bytes," <<(float)(dz_global_Bytes_num*1.0/1024)<<" KB, "<<(float)(dz_global_Bytes_num*1.0/(1024*1024)) << " MB, "<<(float)(dz_global_Bytes_num*1.0/(1024*1024*1024)) << " GB"<<std::endl;
	// std::cout<<"吞吐率" << (float) (dz_global_Bytes_num*8.0/(1024*1024*1024)/(dz_end_time - dz_start_time))<<"Gbps"<<std::endl;

}
