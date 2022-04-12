#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

#else /* Linux */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"
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
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_errno.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_timer.h>
#include <rte_power.h>
#include <rte_eal.h>
#include <rte_spinlock.h>

// DPDK
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define MAX_NB_OF_PORTS_AND_LCORES 32
#define _DPDK
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define IP_DEFTTL 64
#define IP_MAC_ARRAYS_LENGTH 20

struct rte_mempool *mb_pools[MAX_NB_OF_PORTS_AND_LCORES];
struct rte_eth_dev_tx_buffer *tx_buffers[MAX_NB_OF_PORTS_AND_LCORES];
struct rte_eth_rxconf rxq_conf;
struct rte_eth_txconf txq_conf;

struct rte_ether_addr eth_addr;
uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;


int init_mbuf_txbuffer(uint16_t portid, int index)
{

    char mbuf_pool_name[20] = "mbuf_pool_X";
    char tx_buffer_name[20] = "tx_buffer_X";
    int index_of_X;
    char char_i = portid;
    index_of_X = strlen(mbuf_pool_name) - 1;
    mbuf_pool_name[index_of_X] = char_i;
    unsigned nb_mbufs = 8192U;
    int ret = 0;
    mb_pools[index] = rte_pktmbuf_pool_create(mbuf_pool_name, nb_mbufs,
                                              MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                              rte_socket_id());
    if (mb_pools[index] == NULL)
    {
        printf("fail to init mb_pool\n");
        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        return 0;
    }
    ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, mb_pools[index]);
    if (ret != 0)
    {
        printf("failed to init rx_queue\n");
    }

    index_of_X = strlen(tx_buffer_name) - 1;
    tx_buffer_name[index_of_X] = char_i;
    tx_buffers[index] = rte_zmalloc_socket(tx_buffer_name,
                                           RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                           rte_eth_dev_socket_id(portid));
    if (tx_buffers[index] == NULL)
    {
        printf("fail to init buffer\n");
        return 0;
    }
}

int init_port(uint16_t portid)
{
    int ret = 0;
    int queueid = 0;
    struct rte_eth_dev_info dev_info;

    static struct rte_eth_conf local_port_conf = {
        .rxmode = {
            .split_hdr_size = 0,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf = ETH_RSS_IP,
            },
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    };
    ret = rte_eth_dev_info_get(portid, &dev_info);
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "Error during getting device (port %u) info: %s\n",
                 0, strerror(-ret));

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
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

    // init tx queue
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                                 rte_eth_dev_socket_id(portid),
                                 &txq_conf);
    if (ret != 0)
    {
        printf("failed to init queue\n");
        return 0;
    }
}

int main(int argc, char *argv[])
{
    int ret;
    init_mbuf_txbuffer(0, 0);
    init_port(0);
    ret = rte_eth_dev_start(0);
    if (ret != 0)
    {
        printf("failed to start device\n");
    }
    int pkts_recv;
    int MAX_PKT_BURST = 32;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    while (1)
    {
        pkts_recv = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
    }
}
