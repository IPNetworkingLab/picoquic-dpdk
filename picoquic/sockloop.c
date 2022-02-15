/*
 * Author: Christian Huitema
 * Copyright (c) 2020, Private Octopus, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Socket loop implements the "wait for messages" loop common to most servers
 * and many clients.
 *
 * Second step: support simple servers and simple client.
 *
 * The "call loop back" function is called: when ready, after receiving, and after sending. The
 * loop will terminate if the callback return code is not zero -- except for special processing
 * of the migration testing code.
 * TODO: in Windows, use WSA asynchronous calls instead of sendmsg, allowing for multiple parallel sends.
 * TODO: in Linux, use multiple send per call API
 * TDOO: trim the #define list.
 * TODO: support the QuicDoq scenario, manage extra socket.
 */

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
#define _DPDK
#define MAX_PKT_BURST 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define IP_DEFTTL 64
#define IP_MAC_ARRAYS_LENGTH 20

struct lcore_queue_conf
{
    unsigned n_rx_port;
    unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

#if defined(_WINDOWS)
static int udp_gso_available = 0;
#else
#if defined(UDP_SEGMENT)
static int udp_gso_available = 1;
#else
static int udp_gso_available = 0;
#endif
#endif

int picoquic_packet_loop_open_sockets(int local_port, int local_af, SOCKET_TYPE *s_socket, int *sock_af,
                                      uint16_t *sock_ports, int socket_buffer_size, int nb_sockets_max)
{
    int nb_sockets = (local_af == AF_UNSPEC) ? 2 : 1;

    /* Compute how many sockets are necessary */
    if (nb_sockets > nb_sockets_max)
    {
        DBG_PRINTF("Cannot open %d sockets, max set to %d\n", nb_sockets, nb_sockets_max);
        nb_sockets = 0;
    }
    else if (local_af == AF_UNSPEC)
    {
        sock_af[0] = AF_INET;
        sock_af[1] = AF_INET6;
    }
    else if (local_af == AF_INET || local_af == AF_INET6)
    {
        sock_af[0] = local_af;
    }
    else
    {
        DBG_PRINTF("Cannot open socket(AF=%d), unsupported AF\n", local_af);
        nb_sockets = 0;
    }

    for (int i = 0; i < nb_sockets; i++)
    {
        struct sockaddr_storage local_address;
        int recv_set = 0;
        int send_set = 0;

        if ((s_socket[i] = socket(sock_af[i], SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET ||
            picoquic_socket_set_ecn_options(s_socket[i], sock_af[i], &recv_set, &send_set) != 0 ||
            picoquic_socket_set_pkt_info(s_socket[i], sock_af[i]) != 0 ||
            picoquic_bind_to_port(s_socket[i], sock_af[i], local_port) != 0 ||
            picoquic_get_local_address(s_socket[i], &local_address) != 0)
        {
            DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", sock_af[i], local_port);
            for (int j = 0; j < i; j++)
            {
                if (s_socket[i] != INVALID_SOCKET)
                {
                    SOCKET_CLOSE(s_socket[i]);
                    s_socket[i] = INVALID_SOCKET;
                }
            }
            nb_sockets = 0;
            break;
        }
        else
        {
            if (local_address.ss_family == AF_INET6)
            {
                sock_ports[i] = ntohs(((struct sockaddr_in6 *)&local_address)->sin6_port);
            }
            else if (local_address.ss_family == AF_INET)
            {
                sock_ports[i] = ntohs(((struct sockaddr_in *)&local_address)->sin_port);
            }

            if (socket_buffer_size > 0)
            {
                socklen_t opt_len;
                int opt_ret;
                int so_sndbuf;
                int so_rcvbuf;

                opt_len = sizeof(int);
                so_sndbuf = socket_buffer_size;
                opt_ret = setsockopt(s_socket[i], SOL_SOCKET, SO_SNDBUF, (const char *)&so_sndbuf, opt_len);
                if (opt_ret != 0)
                {
#ifdef _WINDOWS
                    int sock_error = WSAGetLastError();
#else
                    int sock_error = errno;
#endif
                    opt_ret = getsockopt(s_socket[i], SOL_SOCKET, SO_SNDBUF, (char *)&so_sndbuf, &opt_len);
                    DBG_PRINTF("Cannot set SO_SNDBUF to %d, err=%d, so_sndbuf=%d (%d)",
                               socket_buffer_size, sock_error, so_sndbuf, opt_ret);
                }
                opt_len = sizeof(int);
                so_rcvbuf = socket_buffer_size;
                opt_ret = setsockopt(s_socket[i], SOL_SOCKET, SO_RCVBUF, (const char *)&so_rcvbuf, opt_len);
                if (opt_ret != 0)
                {
#ifdef _WINDOWS
                    int sock_error = WSAGetLastError();
#else
                    int sock_error = errno;
#endif
                    opt_ret = getsockopt(s_socket[i], SOL_SOCKET, SO_RCVBUF, (char *)&so_rcvbuf, &opt_len);
                    DBG_PRINTF("Cannot set SO_RCVBUF to %d, err=%d, so_rcvbuf=%d (%d)",
                               socket_buffer_size, sock_error, so_rcvbuf, opt_ret);
                }
            }
        }
    }

    return nb_sockets;
}

void setup_pkt_udp_ip_headers_test(struct rte_ipv4_hdr *ip_hdr,
                                   struct rte_udp_hdr *udp_hdr,
                                   uint16_t pkt_data_len)
{

    uint32_t tx_ip_src_addr = (198U << 24) | (18 << 16) | (0 << 8) | 1;
    uint32_t tx_ip_dst_addr = (198U << 24) | (18 << 16) | (0 << 8) | 2;

    uint16_t tx_udp_src_port = 55;
    uint16_t tx_udp_dst_port = 55;

    uint16_t *ptr16;
    uint32_t ip_cksum;
    uint16_t pkt_len;

    // printf("====================clean===============\n");
    // printf("src_adr %u\n",rte_cpu_to_be_32(tx_ip_src_addr));
    // printf("dst_adr %u\n",rte_cpu_to_be_32(tx_ip_dst_addr));
    // printf("src_port %zu\n",rte_cpu_to_be_16(tx_udp_src_port));
    // printf("dst_port %zu\n",rte_cpu_to_be_16(tx_udp_dst_port));
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

struct rte_ether_addr find_mac_from_ip(uint32_t ip_addr, uint32_t *ip_addresses,struct rte_ether_addr *mac_addresses,int length){
    for(int i = 0;i < length;i++){
        if(ip_addresses[i] == ip_addr){
            return mac_addresses[i];
        }
    }
}

int add_mac_ip_pair(uint32_t ip_addr, struct rte_ether_addr mac_addr, uint32_t *ip_addresses,struct rte_ether_addr *mac_addresses,int length){
    for(int i = 0;i < length;i++){
        if(ip_addresses[i] = ip_addr){
            return 0;
        }
        if(ip_addresses[i] == 0){
            printf("added\n");
            ip_addresses[i] = ip_addr;
            mac_addresses[i] = mac_addr;
            return 0;
        }
    }
    return -1;
}

int picoquic_packet_loop_dpdk(picoquic_quic_t *quic,
                              int local_port,
                              int local_af,
                              int dest_if,
                              int socket_buffer_size,
                              int do_not_use_gso,
                              picoquic_packet_loop_cb_fn loop_callback,
                              void *loop_callback_ctx,
                              struct sockaddr_storage addr_my_addr,
                              struct rte_ether_addr *mac_dst,
                              struct rte_mempool *mb_pool,
                              struct rte_eth_dev_tx_buffer *tx_buffer)
{
    //===================DPDK==========================//

    static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
    static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
    static struct rte_ether_addr eth_addr;

    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id = 1;
    struct lcore_queue_conf *qconf;
    uint16_t portid = 0;
    int ret;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_dev_info dev_info;
    void *tmp;

    ret = rte_eth_macaddr_get(portid, &eth_addr);

    //===================DPDK==========================//
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;

    // handling packets
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct rte_mbuf *m;
    int udp_payload_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
    // addresses
    rte_be32_t src_addr;
    rte_be32_t dst_addr;
    rte_be16_t src_port;
    rte_be16_t dst_port;

    int if_index_to;
    uint8_t buffer[1536];
    uint8_t *send_buffer = NULL;
    size_t send_length = 0;
    size_t send_msg_size = 0;
    size_t send_buffer_size = 1536;
    size_t *send_msg_ptr = NULL;
    int bytes_recv;
    picoquic_connection_id_t log_cid;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    uint16_t sock_ports[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0;    /* Data for the migration test */
    picoquic_cnx_t *last_cnx = NULL;
    int loop_immediate = 0;
    int pkts_recv;
    // debugging
    FILE *fptr_send;
    FILE *fptr_rcv;
    int receiv_counter = 0;
    int send_counter = 0;
    fptr_send = fopen("send.txt", "w");
    fptr_rcv = fopen("rcv.txt", "w");

    uint32_t ip_addresses[20];
    struct rte_ether_addr mac_addresses[20];


#ifdef _WINDOWS
    WSADATA wsaData = {0};
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    send_msg_ptr = &send_msg_size;
    send_buffer = malloc(send_buffer_size);
    if (send_buffer == NULL)
    {
        ret = -1;
        return -1;
    }
    while (ret == 0)
    {
        int64_t delta_t = 0;
        unsigned char received_ecn;

        if_index_to = 0;
        /* TODO: rewrite the code and avoid using the "loop_immediate" state variable */
        // printf("receiving\n");
        pkts_recv = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);

        current_time = picoquic_current_time();

        if (pkts_recv < 0)
        {
            ret = -1;
        }
        else
        {
            uint64_t loop_time = current_time;
            uint16_t len;
            for (int i = 0; i < pkts_recv; i++)
            {
                receiv_counter++;
                // printf("received packets : %d\n",receiv_counter);

                /* access ethernet header of rcv'd pkt */
                eth_hdr = rte_pktmbuf_mtod(pkts_burst[i], struct rte_ether_hdr *);
                if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
                {
                    printf("received packet\n");
                    ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkts_burst[i], char *) + sizeof(struct rte_ether_hdr));
                    udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + sizeof(struct rte_ipv4_hdr));

                    src_addr = ip_hdr->src_addr;
                    dst_addr = ip_hdr->dst_addr;
                    src_port = udp_hdr->src_port;
                    dst_port = udp_hdr->dst_port;

                    if(mac_dst == NULL){
                        add_mac_ip_pair(src_addr,eth_hdr->src_addr, ip_addresses, mac_addresses,IP_MAC_ARRAYS_LENGTH);
                    }

                    char *addr_val = inet_ntoa(*(struct in_addr *)&src_addr);
                    // printf("src_addr_received : %s\n",addr_val);
                    // printf("src_port %u\n",htons(src_port));

                    addr_val = inet_ntoa(*(struct in_addr *)&dst_addr);
                    // printf("dst_addr_received : %s\n",addr_val);
                    // printf("src_port %u\n",htons(dst_port));

                    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
                    (*(struct sockaddr_in *)(&addr_from)).sin_port = src_port;
                    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = src_addr;

                    (*(struct sockaddr_in *)(&addr_to)).sin_family = AF_INET;
                    (*(struct sockaddr_in *)(&addr_to)).sin_port = dst_port;
                    (*(struct sockaddr_in *)(&addr_to)).sin_addr.s_addr = dst_addr;

                    unsigned char *payload = (unsigned char *)(udp_hdr + 1);
                    rte_be16_t length = udp_hdr->dgram_len;
                    size_t payload_length = htons(length) - sizeof(struct rte_udp_hdr);
                    (void)picoquic_incoming_packet_ex(quic, payload,
                                                      payload_length, (struct sockaddr *)&addr_from,
                                                      (struct sockaddr *)&addr_to, if_index_to, received_ecn,
                                                      &last_cnx, current_time);

                    if (loop_callback != NULL)
                    {
                        size_t b_recvd = (size_t)payload_length;
                        ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx, &b_recvd);
                    }
                    rte_pktmbuf_free(pkts_burst[i]);
                    if (ret == 0)
                    {
                        continue;
                    }
                }
                else
                {
                    rte_pktmbuf_free(pkts_burst[i]);
                }
            }
            if (ret != PICOQUIC_NO_ERROR_SIMULATE_NAT && ret != PICOQUIC_NO_ERROR_SIMULATE_MIGRATION)
            {
                size_t bytes_sent = 0;
                while (ret == 0)
                {
                    int if_index = dest_if;
                    send_length = 0;
                    struct sockaddr_storage peer_addr;
                    struct sockaddr_storage local_addr;
                    m = rte_pktmbuf_alloc(mb_pool);
                    // printf("alloced\n");
                    if (m == NULL)
                    {
                        printf("fail to init pktmbuf\n");
                        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
                        return 0;
                    }
                    
                    uint8_t *payload_ptr = rte_pktmbuf_mtod_offset(m, char *, (size_t) udp_payload_offset);

                    ret = picoquic_prepare_next_packet_ex(quic, loop_time,
                                                          payload_ptr, send_buffer_size, &send_length,
                                                          &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
                                                          send_msg_ptr);
                    if (ret == 0 && send_length > 0)
                    {
                        bytes_sent += send_length;
                        int offset = 0;
                        struct rte_ipv4_hdr ip_hdr_struct;
                        struct rte_udp_hdr udp_hdr_struct;
                        struct rte_ether_hdr eth_hdr_struct;
                        struct rte_ether_hdr *eth_ptr = &eth_hdr_struct;
                        rte_ether_addr_copy(&eth_addr, &eth_ptr->src_addr);

                        if(mac_dst != NULL){
                            rte_ether_addr_copy(mac_dst,&eth_ptr->dst_addr);
                            // printf("%x\n", mac_dst->addr_bytes[0]);
                            // printf("%x\n", mac_dst->addr_bytes[1]);
                            // printf("%x\n", mac_dst->addr_bytes[2]);
                            // printf("%x\n", mac_dst->addr_bytes[3]);
                            // printf("%x\n", mac_dst->addr_bytes[4]);
                            // printf("%x\n", mac_dst->addr_bytes[5]);
                        }
                        else{
                            struct rte_ether_addr mac_addr = find_mac_from_ip((*(struct sockaddr_in *)(&peer_addr)).sin_addr.s_addr, ip_addresses,mac_addresses,IP_MAC_ARRAYS_LENGTH);  
                            rte_ether_addr_copy(&mac_addr,&eth_ptr->dst_addr);
                            // printf("%x\n", mac_addr.addr_bytes[0]);
                            // printf("%x\n", mac_addr.addr_bytes[1]);
                            // printf("%x\n", mac_addr.addr_bytes[2]);
                            // printf("%x\n", mac_addr.addr_bytes[3]);
                            // printf("%x\n", mac_addr.addr_bytes[4]);
                            // printf("%x\n", mac_addr.addr_bytes[5]);  
                        }
                        tmp = &eth_ptr->dst_addr.addr_bytes[0];
                        *((uint64_t *)tmp) = 0;
                        setup_pkt_udp_ip_headers(&ip_hdr_struct, &udp_hdr_struct, send_length, addr_my_addr, peer_addr);
                        // setup_pkt_udp_ip_headers_test(&ip_hdr_struct, &udp_hdr_struct, send_length);

                        char *src_addr = inet_ntoa((*(struct sockaddr_in *)(&addr_from)).sin_addr);
                        // printf("src_addr : %s\n",src_addr);

                        char *dst_addr = inet_ntoa((*(struct sockaddr_in *)(&addr_to)).sin_addr);
                        // printf("dst_addr : %s\n",dst_addr);

                        (&eth_hdr_struct)->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
                        copy_buf_to_pkt(&eth_hdr_struct, sizeof(struct rte_ether_hdr), m, offset);
                        offset += sizeof(struct rte_ether_hdr);
                        copy_buf_to_pkt(&ip_hdr_struct, sizeof(struct rte_ipv4_hdr), m, offset);
                        offset += sizeof(struct rte_ipv4_hdr);
                        copy_buf_to_pkt(&udp_hdr_struct, sizeof(struct rte_udp_hdr), m, offset);
                        offset += sizeof(struct rte_udp_hdr);
                        // printf("offset : %d\n",offset);
                        //payload already set

                        offset += send_length;
                        // printf("offset : %d\n",offset);

                        m->data_len = offset;
                        m->pkt_len = offset;
                        int sent = rte_eth_tx_buffer(0, 0, tx_buffer, m);
                        // printf("sending\n");
                        send_counter += sent;
                        // fprintf(fptr_send, "%d\n", send_counter);
                    }

                    else
                    {
                        rte_pktmbuf_free(m);
                        int sent = rte_eth_tx_buffer_flush(0, 0, tx_buffer);
                        send_counter += sent;
                        // fprintf(fptr_send, "%d\n", send_counter);
                        break;
                    }
                }

                if (ret == 0 && loop_callback != NULL)
                {
                    ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx, &bytes_sent);
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP)
    {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    if (send_buffer != NULL)
    {
        free(send_buffer);
    }
    return ret;
}

int picoquic_packet_loop(picoquic_quic_t *quic,
                         int local_port,
                         int local_af,
                         int dest_if,
                         int socket_buffer_size,
                         int do_not_use_gso,
                         picoquic_packet_loop_cb_fn loop_callback,
                         void *loop_callback_ctx)
{
    return 0;
}
