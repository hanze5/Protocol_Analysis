#pragma once

#include "Packet.h"
#include "DpdkDevice.h"

#include <SystemUtils.h>

#include <string>
#include <map>
#include <vector>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdlib.h>



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


#include <queue>

#include <stdio.h>

#include <string.h>

#include <thread>
#include <unistd.h>

#define LOG_MODULE pcpp::ProtocolAnalysis

#define DEFAULT_MAX_PACKETS_TO_STORE 10000
// unless the user chooses otherwise - default number of concurrent used file descl2tptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 500

/**
 * Macros for exiting the application with error
 */

#define EXIT_WITH_ERROR(reason) do { \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)


#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason) do { \
	printUsage(); \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

#if defined(_WIN32)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif
/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK port to receive packets from
 * - Which DPDK port to send packets to
 */
struct AppWorkerConfig
{
	uint32_t CoreId;
	pcpp::DpdkDevice* RxDevice;
	// uint16_t RxQueues_begin;
	// uint16_t RxQueues_end;
	std::vector<uint16_t> dz_RxQueues;
	int maxPacketsToStore;

	pcpp::DpdkDevice* TxDevice;

	// AppWorkerConfig() : CoreId(MAX_NUM_OF_CORES+1), RxDevice(NULL), RxQueues_begin(0),RxQueues_end(1), TxDevice(NULL)
	// {
	// }
	AppWorkerConfig() : CoreId(MAX_NUM_OF_CORES+1), RxDevice(NULL), TxDevice(NULL) ,  maxPacketsToStore(DEFAULT_MAX_PACKETS_TO_STORE)
	{
	}
};

struct PortConfig
{
	std::vector<uint16_t> dz_Cores;
};

// class GlobalConfig
// {
//   private:
// 	/**
// 	 * A private c'tor (as this is a singleton)
// 	 */
// 	GlobalConfig()
// 	{
// 		writeMetadata = false;
// 		writeToConsole = false;
// 		maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
// 		m_RecentFilesWithActivity = NULL;
// 		outputDir = "../debug_data_output";
// 	}

// 	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key.
// 	// This LRU list is used to decide which connection was seen least recently in case we reached max number of open
// 	// file descl2tptors and we need to decide which files to close
// 	pcpp::LRUList<std::string> *m_RecentFilesWithActivity;

//   public:
// 	// calculate processed packet numbers
// 	int PacketNum;

// 	// a flag indicating whether to write a metadata file for each connection (containing several stats)
// 	bool writeMetadata;

// 	// the directory to write files to (default is current directory)
// 	std::string outputDir;

// 	// a flag indicating whether to write L2TP data to actual files or to console
// 	bool writeToConsole;

// 	// max number of allowed open files in each point in time
// 	size_t maxOpenFiles;

// 	std::string getFileName(std::string name)
// 	{
// 		std::stringstream stream;

// 		// if user chooses to write to a directory other than the current directory - add the dir path to the return
// 		// value
// 		if (!outputDir.empty())
// 			stream << outputDir << SEPARATOR;

// 		stream << name;

// 		// return the file path
// 		return stream.str();
// 	}

// 	/**
// 	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file
// 	 * or overwrite it. Return value is a pointer to the new file stream
// 	 */
// 	std::ostream *openFileStream(std::string fileName, bool reopen)
// 	{
// 		// if the user chooses to write only to console, don't open anything and return std::cout
// 		if (writeToConsole)
// 			return &std::cout;

// 		// open the file on the disk (with append or overwrite mode)
// 		if (reopen)
// 			return new std::ofstream(fileName.c_str(), std::ios_base::binary | std::ios_base::app);
// 		else
// 			return new std::ofstream(fileName.c_str(), std::ios_base::binary);
// 	}

// 	/**
// 	 * Close a file stream
// 	 */
// 	void closeFileSteam(std::ostream *fileStream)
// 	{
// 		// if the user chooses to write only to console - do nothing and return
// 		if (!writeToConsole)
// 		{
// 			// close the file stream
// 			std::ofstream *fstream = (std::ofstream *)fileStream;
// 			fstream->close();

// 			// free the memory of the file stream
// 			delete fstream;
// 		}
// 	}

// 	pcpp::LRUList<std::string> *getRecentFilesWithActivity()
// 	{
// 		// This is a lazy implementation - the instance isn't created until the user requests it for the first time.
// 		// the side of the LRU list is determined by the max number of allowed open files at any point in time. Default
// 		// is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES but the user can choose another number
// 		if (m_RecentFilesWithActivity == NULL)
// 			m_RecentFilesWithActivity = new pcpp::LRUList<std::string>(maxOpenFiles);

// 		// return the pointer
// 		return m_RecentFilesWithActivity;
// 	}

// 	/**
// 	 * The singleton implementation of this class
// 	 */
// 	static GlobalConfig &getInstance()
// 	{
// 		static GlobalConfig instance;
// 		return instance;
// 	}
// };


// // 存储某一五元组的数据包
// /**
//  * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats
//  * data on the connection
//  */
// struct ReassemblyData
// {
// 	std::ostream *fileStream;

// 	// flags indicating whether the file was already opened before. If the answer is yes, next time it'll
// 	// be opened in append mode (and not in overwrite mode)
// 	bool reopenFileStream;

// 	// stats data: num of data packets, bytes
// 	int numOfDataPackets;
// 	int bytes;

// 	/**
// 	 * the default c'tor
// 	 */
// 	ReassemblyData()
// 	{
// 		fileStream = NULL;
// 		clear();
// 	}

// 	/**
// 	 * The default d'tor
// 	 */
// 	~ReassemblyData()
// 	{
// 		// close files on both sides if open
// 		if (fileStream != NULL)
// 			GlobalConfig::getInstance().closeFileSteam(fileStream);
// 	}

// 	/**
// 	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
// 	 */
// 	void clear()
// 	{
// 		// for the file stream - close them if they're not null
// 		if (fileStream != NULL)
// 		{
// 			GlobalConfig::getInstance().closeFileSteam(fileStream);
// 			fileStream = NULL;
// 		}

// 		reopenFileStream = false;
// 		numOfDataPackets = 0;
// 		bytes = 0;
// 	}
// };

// /**
//  * A struct to contain all data save on a specific connection.
//  */
// struct TcpReassemblyData
// {
// 	// a flag indicating on which side was the latest message on this connection
// 	int8_t curSide;

// 	// stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
// 	int numOfDataPackets[2];
// 	int numOfMessagesFromSide[2];
// 	int bytesFromSide[2];

// 	/**
// 	 * the default c'tor
// 	 */
// 	TcpReassemblyData()
// 	{
// 		clear();
// 	}

// 	/**
// 	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
// 	 */
// 	void clear()
// 	{
// 		numOfDataPackets[0] = 0;
// 		numOfDataPackets[1] = 0;
// 		numOfMessagesFromSide[0] = 0;
// 		numOfMessagesFromSide[1] = 0;
// 		bytesFromSide[0] = 0;
// 		bytesFromSide[1] = 0;
// 		curSide = -1;
// 	}
// };
