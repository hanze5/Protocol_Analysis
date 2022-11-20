

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
#include <rte_ethdev.h>

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
#define PER_ELEMENT_SIZE 512*1024

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

/*判断是不是2的整数次幂*/
bool isPowerOfTwo(int num)
{
	int r;

	do
	{
		r = num%2;
		num/=2;
	} while (r == 0 && num > 0);
	if( num>0 ) return false;
	else return true;
}

//判断奇偶数
bool isTimeofTwo(int num)
{
	int r = num%2;
	if(r == 0) return true;
	else return false;
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

	

	// time_t dz_start_time,dz_end_time;
	// dz_start_time = time(NULL);


	// if core mask is not provided, use the 3 first cores
	pcpp::CoreMask coreMaskToUse = (pcpp::getCoreMaskForAllMachineCores() & 0xff);

	uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;
	uint16_t queueQuantity = DEFAULT_QUEUE_QUANTITY;
	coreMaskToUse =  DEFAULT_CORE_TO_USE;
	



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



	//读取配置文件信息===========================================================================================
	ini::ConfigReader config;
	bool ret = config.ReadConfig("../config.ini");
	if (ret == false) 
    {
		RTE_LOG(ERR,APPLICATION,"ReadConfig is Error,Cfg=%s", "config.ini");
		return 1;
	}
	// 1. 判断debug模式
	bool isdebug = config.ReadBool("dpdk_config", "isdebug", false);
	if(isdebug) std::cout<<"yes debug"<<std::endl;
	else std::cout<<"no "<<std::endl;
	// 2. 获取工作线程数
	int num_of_cores = config.ReadInt("dpdk_config", "num_of_cores", DEFAULT_CORE_TO_USE);
	coreMaskToUse = pow(2,num_of_cores+1)-1;
	if(!isPowerOfTwo(num_of_cores)) 
	{
		RTE_LOG(ERR,APPLICATION,"工作线程个数必须是 (2^n) \n");
		exit(1);
	}
	//3. 获取每个工作线程分配的缓冲池大小
	mBufPoolSize = config.ReadInt("dpdk_config", "mempoolsize_per_core",DEFAULT_MBUF_POOL_SIZE);
	if(!isPowerOfTwo(mBufPoolSize+1)) 
	{
		RTE_LOG(ERR,APPLICATION,"工作线程的缓冲池大小必须是 (2^n)-1 \n");
		exit(1);
	}
	//4. 获取要开启的dpdk队列数
	queueQuantity = config.ReadInt("dpdk_config", "queues_to_use",DEFAULT_QUEUE_QUANTITY);
	if(num_of_cores>queueQuantity)
	{
		RTE_LOG(ERR,APPLICATION,"工作线程数不得大于队列数 %d\n",num_of_cores);
	}
	
	//5. 获取共享内存的缓冲池大小
	int per_element_size = config.ReadInt("dpdk_config", "per_element_size",512*1024);
	if(!isPowerOfTwo(per_element_size))
	{
		RTE_LOG(ERR,APPLICATION,"共享内存的元素大小必须是 (2^n) \n");
		exit(1);
	}
	// 6. 获取共享内存缓冲池内元素大小
	int share_mem_pool_size = config.ReadInt("dpdk_config", "share_mem_pool_size",1023);
	if(!isPowerOfTwo(share_mem_pool_size+1))
	{
		RTE_LOG(ERR,APPLICATION,"共享内存缓冲池内元素大小 (2^n)-1 \n");
		exit(1);
	}

	// 7. 获取打印状态信息的时间间隔
	int time_interval = config.ReadInt("dpdk_config", "time_interval",0);

	
	int maxPacketsToStore = config.ReadInt("pcap++_config", "maxPacketsToStore", DEFAULT_MAX_PACKETS_TO_STORE);

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

	std::cout<<"将要设置的工作线程数为"<<num_of_cores<<std::endl
			 <<"将要设置的缓冲池大小"<<mBufPoolSize<<std::endl
			 <<"将要开启对列数"<<queueQuantity<<std::endl
			 <<"将要设置共享内存缓冲池元素大小 "<<per_element_size<<std::endl
			 <<"将要设置共享内存缓冲池大小为"<<share_mem_pool_size<<std::endl
			 <<"将要设置间隔时间为"<<time_interval<<std::endl
			 <<"maxPacketsToStore"<<maxPacketsToStore<<std::endl
	         <<std::endl;
	


	//配置文件信息读取结束======================================================================================

	// initialize DPDK
	if (!pcpp::DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize))
	{
		// EXIT_WITH_ERROR("Couldn't initialize DPDK");
		RTE_LOG(ERR,APPLICATION,"Couldn't initialize DPDK");
		exit(1);
	}

	const unsigned flags = 0;
	const unsigned ring_size = 64*1024;
	const unsigned pool_size = share_mem_pool_size;
	const unsigned pool_cache = 32;
	const unsigned priv_data_sz = 0;

	
	message_ring = rte_ring_create(_MSG_RING, ring_size, rte_socket_id(), flags);
    message_pool = rte_mempool_create(_MSG_POOL, pool_size,
            per_element_size, pool_cache, priv_data_sz,
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
	std::vector<int> dpdkPortVec;
	
	for(int i = 0;i<(int)rte_eth_dev_count_avail();i++)
	{
		dpdkPortVec.push_back(i);
	}
	PCPP_LOG_INFO("共有可用dpdkport " << dpdkPortVec.size());
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


	// prepare configuration for every core==================================================
	AppWorkerConfig workerConfigArr[num_of_cores];
	//先为端口分配工作线程
	PortConfig portConfigs[dpdkPortVec.size()];
	for(int i  = 0; i< num_of_cores;i++)
	{
		workerConfigArr[i].CoreId = coresToUse.at(i).Id;
		workerConfigArr[i].maxPacketsToStore=maxPacketsToStore;
		workerConfigArr[i].RxDevice = dpdkDevicesToUse.at(i%dpdkPortVec.size());
		portConfigs[i%dpdkPortVec.size()].dz_Cores.push_back(i);
	}
	//然后给每个端口的工作线程分配队列
	for(int i = 0 ; i < (int)dpdkPortVec.size();i++)
	{
		//dz_Cores存的是core的
		int temp = portConfigs[i].dz_Cores.size();

		for(int j = 0 ;j< queueQuantity;j++)
		{
			workerConfigArr[portConfigs[i].dz_Cores[j%temp]].dz_RxQueues.push_back(j);
		}
	}
	//=========================================================================================
  
 
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
	while (!args.shouldStop )
	{		
		if(time_interval==0)
		{
			continue;
		}
		else
		{
			//时间戳用到的
			sleep(time_interval);
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

			pcpp::DpdkDeviceList::getInstance().Reset_Application_status();
		}
			
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
