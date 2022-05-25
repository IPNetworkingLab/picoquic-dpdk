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
#include <unistd.h>
#include <rte_pdump.h>

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};
static int
lcore_hello(__rte_unused void *arg)
{

	int ret;
	uint16_t portid = 0;

	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	unsigned int nb_mbufs = RTE_MAX(1 * (1 + 1 + MAX_PKT_BURST + 2 * MEMPOOL_CACHE_SIZE), 8192U);
	struct rte_mempool *mb_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
														  MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
														  rte_socket_id());
	if (mb_pool == NULL)
	{
		printf("fail to init mb_pool\n");
	}

	ret = rte_eth_dev_info_get(0, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				 "Error during getting device (port %u) info: %s\n",
				 0, strerror(-ret));

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	ret = rte_eth_dev_configure(0, 1, 1, &local_port_conf);
	if (ret != 0)
	{
		printf("error dev_configure\n");
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(0, &nb_rxd,
										   &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, 0);
	//init rx queue
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(0, 0, nb_rxd, rte_eth_dev_socket_id(0), &rxq_conf, mb_pool);
	if (ret != 0)
	{
		printf("failed to init rx_queue\n");
	}
	ret = rte_eth_tx_queue_setup(0, 0, nb_txd, rte_eth_dev_socket_id(0),
								 NULL);
	if (ret != 0)
	{
		printf("failed to init tx_queue\n");
		return 0;
	}
	printf("before start \n");

	ret = rte_eth_dev_start(0);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				 ret, 0);
	printf("loop start\n");
	static struct rte_ether_addr eth_addr;
	ret = rte_eth_macaddr_get(portid, &eth_addr);

	char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", eth_addr.addr_bytes[0], 
                                                                    eth_addr.addr_bytes[1], 
                                                                    eth_addr.addr_bytes[2], 
                                                                    eth_addr.addr_bytes[3], 
                                                                    eth_addr.addr_bytes[4], 
                                                                    eth_addr.addr_bytes[5]);

    printf("mac : %s\n",macStr);
	int packet_counter = 0;
	uint64_t goodput = 0;
	struct timeval start_time;
    struct timeval current_time;
	gettimeofday(&start_time, NULL);
	while (true)
	{
		ret = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
		struct rte_ether_hdr *eth_hdr;
		struct vlan_hdr *vh;
		uint16_t *proto;
		struct rte_ipv4_hdr *ip_hdr;
		for (int j = 0; j < ret; j++)
		{
			
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkts_burst[j], char *) + sizeof(struct rte_ether_hdr));

			struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr +
															 sizeof(struct rte_ipv4_hdr));
			unsigned char *payload = (unsigned char *)(udp_hdr + 1);
			rte_be16_t length = udp_hdr->dgram_len;
            uint64_t payload_length = htons(length) - sizeof(struct rte_udp_hdr);
			goodput += payload_length;
			packet_counter++;

			// printf("payload : %s\n",payload);
			rte_pktmbuf_free(pkts_burst[j]);
			

		}
		gettimeofday(&current_time, NULL);
		double elapsed = 0.0;
		elapsed = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
		if(elapsed > 2){
			printf("goodput : %lf\n", ((goodput*8)/1000000)/elapsed);
			printf("number of packets : %lu\n",packet_counter);
			goodput = 0;
			packet_counter = 0;
			gettimeofday(&start_time, NULL);
		}
		
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	ret = rte_eal_init(argc, argv);
	rte_pdump_init();
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	/* call lcore_hello() on every worker lcore */

	/* call it on main lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
