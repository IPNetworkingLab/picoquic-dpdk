/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <netinet/if_ether.h>

#include <stdint.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <inttypes.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>

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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_spinlock.h>
#include <rte_devargs.h>

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
uint32_t tx_ip_src_addr = (198U << 24) | (18 << 16) | (0 << 8) | 1;
uint32_t tx_ip_dst_addr = (198U << 24) | (18 << 16) | (0 << 8) | 2;

uint16_t tx_udp_src_port = 9;
uint16_t tx_udp_dst_port = 9;

#define IP_DEFTTL 64
struct rte_mempool *mb_pool;

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static struct rte_ether_addr eth_addr;
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

void setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr,
							  struct rte_udp_hdr *udp_hdr,
							  uint16_t pkt_data_len)
{
	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	/*
	 * Initialize UDP header.
	 */
	pkt_len = (uint16_t)(pkt_data_len + sizeof(struct rte_udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(tx_udp_src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(tx_udp_dst_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
	udp_hdr->dgram_cksum = 0; /* No UDP checksum. */

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t)(pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ip_hdr->type_of_service = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(tx_ip_src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(tx_ip_dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (unaligned_uint16_t *)ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0];
	ip_cksum += ptr16[1];
	ip_cksum += ptr16[2];
	ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6];
	ip_cksum += ptr16[7];
	ip_cksum += ptr16[8];
	ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
			   (ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t)ip_cksum;
}

void copy_buf_to_pkt_segs(void *buf, unsigned len, struct rte_mbuf *pkt,
						  unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len)
	{
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len)
	{
		rte_memcpy(seg_buf, buf, (size_t)copy_len);
		len -= copy_len;
		buf = ((char *)buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, char *);
		copy_len = seg->data_len;
	}
	rte_memcpy(seg_buf, buf, (size_t)len);
}

void copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{

	rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),
			   buf, (size_t)len);
	return;
}

static int
lcore_hello(__rte_unused void *arg)
{
	uint16_t portid = 0;
	int ret;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_dev_tx_buffer *tx_buffer;
	struct rte_mbuf *m;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_ether_hdr *eth;
	void *tmp;

	tx_buffer = rte_zmalloc_socket("tx_buffer",
								   RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
								   rte_eth_dev_socket_id(0));
	if (tx_buffer == NULL)
	{
		printf("fail to init buffer\n");
		return 0;
	}

	if (mb_pool == NULL)
	{
		printf("fail to init mb_pool\n");
		return 0;
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
		printf("error in dev_configure\n");
		return 0;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
										   &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

	ret = rte_eth_macaddr_get(portid, &eth_addr);

	//init tx queue
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
								 rte_eth_dev_socket_id(portid),
								 &txq_conf);
	if (ret != 0)
	{
		printf("failed to init queue\n");
		return 0;
	}

	//init rx queue
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(0, 0, nb_rxd, rte_eth_dev_socket_id(0), &rxq_conf, mb_pool);
	if (ret != 0)
	{
		printf("failed to init rx_queue\n");
	}

	//changing mac addr and ether type
	// eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	// eth->ether_type = htons(2048);
	// rte_ether_addr_copy(&eth_addr, &eth->src_addr);
	// tmp = &eth->d_addr.addr_bytes[0];
	// *((uint64_t *)tmp) = 0;

	printf("before start \n");
	ret = rte_eth_dev_start(0);
	if (ret != 0)
	{
		printf("failed to start device\n");
	}

	size_t pkt_size;
	m = rte_pktmbuf_alloc(mb_pool);
	if (m == NULL)
	// printf("hello\n");
	{
		printf("fail to init pktmbuf\n");
		return 0;
	}
	int offset = 0;
	struct rte_ipv4_hdr ip_hdr;
	struct rte_udp_hdr rte_udp_hdr;
	struct rte_ether_hdr eth_hdr;
	m = rte_pktmbuf_alloc(mb_pool);

	if (m == NULL)
	{
		printf("fail to init pktmbuf\n");
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
		return 0;
	}
	
	// rte_pktmbuf_reset_headroom(m);
	// m->l2_len = sizeof(struct rte_ether_hdr);
	// m->l3_len = sizeof(struct rte_ipv4_hdr);
	setup_pkt_udp_ip_headers(&ip_hdr, &rte_udp_hdr, 5);
	(&eth_hdr)->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	copy_buf_to_pkt(&eth_hdr, sizeof(struct rte_ether_hdr), m, offset);
	offset += sizeof(struct rte_ether_hdr);
	copy_buf_to_pkt(&ip_hdr, sizeof(struct rte_ipv4_hdr), m, offset);
	offset += sizeof(struct rte_ipv4_hdr);
	copy_buf_to_pkt(&rte_udp_hdr, sizeof(struct rte_udp_hdr), m, offset);
	offset += sizeof(struct rte_udp_hdr);
	copy_buf_to_pkt("test", 5, m, offset);
	offset += 5;
	//inchallah ca marche
	m->data_len = offset;
	m->pkt_len = offset;
	rte_eth_tx_burst(0, 0, &m, 1);
	printf("after transmit\n");

	return 0;
}

int main(int argc, char **argv)
{

	int ret;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	unsigned int nb_mbufs = RTE_MAX(1 * (1 + 1 + MAX_PKT_BURST + 2 * MEMPOOL_CACHE_SIZE), 8192U);
	mb_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
									  MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
									  rte_socket_id());
	/* call lcore_hello() on every worker lcore */
	// RTE_LCORE_FOREACH_WORKER(lcore_id)
	// {
	// 	rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	// }

	/* call it on main lcore too */
	lcore_hello(NULL);
	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
