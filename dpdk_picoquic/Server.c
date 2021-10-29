/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256

static int
lcore_hello(__rte_unused void *arg)
{

	int sent;
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	struct rte_eth_dev_rx_buffer *buffer;
	struct rte_mbuf *m;
	struct rte_eth_txconf txq_conf;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];

    rte_mempool mb_pool = rte_pktmbuf_pool_create("mbuf_pool", 15,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	int err = rte_eth_dev_configure(0,1,1,1,&txq_conf);
    if(ret != 0){
		printf("error\n");
	}
	ret = rte_eth_rx_queue_setup(0,0,1,rte_eth_dev_socket_id(0),NULL,mb_pool)
	if(ret != 0){
		printf("error\n");
	}
    nb_rx = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
	rte_eth_tx_buffer_init(buffer, MAX_PKT_BURST);
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	/* call lcore_hello() on every worker lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	/* call it on main lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
