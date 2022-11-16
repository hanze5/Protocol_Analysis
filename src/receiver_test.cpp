/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

/*
 * This sample application is a simple multi-process application which
 * demostrates sharing of queues and memory pools between processes, and
 * using those queues/pools for communication between the processes.
 *
 * Application is designed to run with two processes, a primary and a
 * secondary, and each accepts commands on the commandline, the most
 * important of which is "send", which just sends a string to the other
 * process.
 */

#include "../include/receive_utils.h"
#include <yaml-cpp/yaml.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/queue.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <cmdline.h>

// #include "common.h"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

static const char *_MSG_POOL = "MSG_POOL";
static const char *_MSG_RING = "MSG_RING";

struct rte_ring *message_ring;
struct rte_mempool *message_pool;
volatile int quit = 0;

//线程每间隔5个时间单位取一次msg

static int
lcore_recv(__rte_unused void *arg)
{
	unsigned lcore_id = rte_lcore_id();

	printf("Starting core %u  entries:%d\n", lcore_id, rte_ring_count(message_ring));

	while (1)
	{
		void *msg;
		if (rte_ring_dequeue(message_ring, &msg) < 0)
		{    
			usleep(500);
			continue;
		}

		// /*具体处理及相关接口示例*/
		// printf("core %u: Received '%s'\n", lcore_id, (char *)msg);

		std::string s(static_cast<const char*>(msg), strlen((char *)msg)*sizeof(char));

		std::cout<< s <<std::endl;

    
		struct My_MSG *my_msg = getMsgFromStr(&s);

		print_msg(my_msg);
		free_msg(my_msg);


	
		/*end of 具体处理及相关接口示例*/
		rte_mempool_put(message_pool, msg);
	}
}

int main(int argc, char **argv)
{
	// const unsigned flags = 0;
	// const unsigned ring_size = 64;
	// const unsigned pool_size = 1024;
	// const unsigned pool_cache = 32;
	// const unsigned priv_data_sz = 0;

	int ret;
	unsigned lcore_id;


	ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		// error
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");
	}
		 

	/*主进程复测创建 发送队列、接收队列和 缓冲池
	 从进程负责根据队列id以及缓冲池id查找查找*/

	message_ring = rte_ring_lookup(_MSG_RING);
	// send_ring = rte_ring_lookup(_SEC_2_PRI);
	message_pool = rte_mempool_lookup(_MSG_POOL);

	//如果这三个没有创建成功或者没找到就直接退出

	// error
	if (message_ring == NULL)
	{
		rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");
	}
		
	if (message_pool == NULL)
	{
		rte_exit(EXIT_FAILURE, "Problem getting message pool\n");
	}
		

	RTE_LOG(INFO, APP, "Finished Process Init.\n");

	//开启接收线程
	/* call lcore_recv() on every worker lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rte_eal_remote_launch(lcore_recv, NULL, lcore_id);
	}

	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
