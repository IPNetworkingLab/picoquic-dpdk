/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "picoquic_internal.h"
#include "proxy.h"

#define SIDUCK_ONLY_QUACKS_ECHO 0x101



int rcv_encapsulate_send(picoquic_cnx_t* cnx,proxy_ctx_t * ctx) {
    int length = 0;
    int pkt_recv = 0;
    int udp_dgram_offset = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
    int MAX_PKT_BURST = 32;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_ether_addr eth_addr;
    // printf("portid : %d\n",ctx->portid);
    int ret = rte_eth_macaddr_get(ctx->portid, &eth_addr);


    char macStr[18];

    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", eth_addr.addr_bytes[0], 
                                                                    eth_addr.addr_bytes[1], 
                                                                    eth_addr.addr_bytes[2], 
                                                                    eth_addr.addr_bytes[3], 
                                                                    eth_addr.addr_bytes[4], 
                                                                    eth_addr.addr_bytes[5]);
    
    // printf("ret : %d\n",ret);
    // printf("mac : %s\n",macStr);
    
    pkt_recv = rte_eth_rx_burst(ctx->portid, ctx->queueid, pkts_burst, MAX_PKT_BURST);
    if(pkt_recv > 0){
        for (int j = 0; j < pkt_recv; j++)
		{
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr *);
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
                int ret = 0;
                struct rte_ipv4_hdr *ip_hdr;
                struct rte_udp_hdr *udp_hdr;
                ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkts_burst[j], char *) + sizeof(struct rte_ether_hdr));
                udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + sizeof(struct rte_ipv4_hdr));
                uint16_t dgram_length = htons(udp_hdr->dgram_len);
                length = sizeof(struct rte_ipv4_hdr)+ dgram_length;
                printf("dgram_length : %d \n",dgram_length);
                ret = picoquic_queue_datagram_frame(cnx, length, ip_hdr);
                rte_pktmbuf_free(pkts_burst[j]);
            }
		}
        
    }
    else{
        sleep(0.5);
        return picoquic_queue_datagram_frame(cnx, 5, "test");
    }
    return 0; 
}

int send_received_dgram(proxy_ctx_t *ctx, uint8_t *udp_packet) {

    struct rte_mbuf *m;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct rte_ether_addr eth_addr;
    int length = 0;
    int udp_dgram_offset = sizeof(struct rte_ipv4_hdr);

    int ret = rte_eth_macaddr_get(ctx->portid, &eth_addr);
    
    m = rte_pktmbuf_alloc(ctx->mb_pool);
    if (m == NULL)
    {
        printf("fail to init pktmbuf\n");
        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        return 0;
    }
    eth_hdr = (struct rte_ether_hdr *)(rte_pktmbuf_mtod(m, char *));
    eth_hdr -> ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&eth_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(ctx->client_addr, &eth_hdr->dst_addr);

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", ctx->client_addr->addr_bytes[0], 
                                                                    ctx->client_addr->addr_bytes[1], 
                                                                    ctx->client_addr->addr_bytes[2], 
                                                                    ctx->client_addr->addr_bytes[3], 
                                                                    ctx->client_addr->addr_bytes[4], 
                                                                    ctx->client_addr->addr_bytes[5]);

    // printf("mac : %s\n",macStr);
    ip_hdr = (struct rte_ipv4_hdr *) udp_packet;
    udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + sizeof(struct rte_ipv4_hdr));
    uint16_t dgram_length = htons(udp_hdr->dgram_len);
    length = dgram_length + udp_dgram_offset;
    printf("dgram_length : %zu\n",dgram_length);

    copy_buf_to_pkt(udp_packet, length, m, sizeof(struct rte_ether_hdr));
    
    m->data_len = length+sizeof(struct rte_ether_hdr);
    m->pkt_len = length+sizeof(struct rte_ether_hdr);
    ret = rte_eth_tx_burst(ctx->portid, ctx->queueid, &m,1);
    printf("ret : %d\n",ret);
}

uint8_t *receive_packet(proxy_ctx_t ctx){


}




proxy_ctx_t* proxy_create_ctx(int portid,int queueid, struct rte_mempool *mb_pool,struct rte_ether_addr *eth_client_proxy_addr)
{
    proxy_ctx_t* ctx = (proxy_ctx_t*)malloc(sizeof(proxy_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(proxy_ctx_t));
        ctx->portid = portid;
        ctx-> queueid = queueid;
        ctx-> mb_pool = mb_pool;
        ctx-> client_addr = eth_client_proxy_addr;
    }
    return ctx;
}

/*
 * proxy call back.
 */
int proxy_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    proxy_ctx_t * ctx = (proxy_ctx_t*)callback_ctx;
    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
        case picoquic_callback_stream_gap:
        case picoquic_callback_prepare_to_send:
           printf("Unexpected callback, code %d, length = %zu", fin_or_event, length);
           break;
        case picoquic_callback_prepare_datagram:
            rcv_encapsulate_send(cnx,ctx);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            printf("app closed\n");
            if (ctx != NULL) {
                free(ctx);
                ctx = NULL;
            }
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            break;
        case picoquic_callback_almost_ready:
            break;
        case picoquic_callback_ready:
            if (cnx->client_mode) {
                rcv_encapsulate_send(cnx,ctx);
            }
            else{
                printf("server\n");
            }
            break;
        case picoquic_callback_datagram:
            if(!strcmp(bytes,"test")==0){
                send_received_dgram(ctx,bytes);
            }
            
            /* Process the datagram, which contains an address and a QUIC packet */
            
            break;
        case picoquic_callback_datagram_acked:
            // printf("acked datagram\n");
            break;
        default:
            printf("even : %d\n",fin_or_event);
            printf("inside default\n");
            /* unexpected */
            break;
        }
    }

    return ret;
}