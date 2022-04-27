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


int rcv_encapsulate_send(proxy_ctx_t *cnx,proxy_ctx_t * ctx) {
    int length = 0;
    int pkt_recv = 0;
    struct rte_mbuf *m;
    int udp_dgram_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
    int MAX_PKT_BURST = 1;
    m = rte_pktmbuf_alloc(ctx->mb_pool);
    if (m == NULL)
    {
        printf("fail to init pktmbuf\n");
        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        return 0;
    }
    pkt_recv = rte_eth_rx_burst(ctx->portid, ctx->queueid, m, MAX_PKT_BURST);
    if(pkt_recv > 0){
        struct rte_ipv4_hdr *ip_hdr;
        struct rte_udp_hdr *udp_hdr;
        ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + sizeof(struct rte_ether_hdr));
        udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + sizeof(struct rte_ipv4_hdr));
        uint16_t dgram_length = htons(udp_hdr->dgram_len);
        length += udp_dgram_offset + dgram_length;
        return picoquic_queue_datagram_frame(cnx, length, ip_hdr);
    }
    return 0; 
}

int send_received_dgram(proxy_ctx_t *ctx, uint8_t *udp_packet) {

    struct rte_mbuf *m;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    int length = 0;
    int udp_dgram_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

    m = rte_pktmbuf_alloc(ctx->mb_pool);
    if (m == NULL)
    {
        printf("fail to init pktmbuf\n");
        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        return 0;
    }
    ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + sizeof(struct rte_ether_hdr));
    udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ip_hdr + sizeof(struct rte_ipv4_hdr));
    uint16_t dgram_length = htons(udp_hdr->dgram_len);
    length = udp_dgram_offset + dgram_length;

    copy_buf_to_pkt(udp_packet, length, m, 0);
    m->data_len = length;
    m->pkt_len = length;
    rte_eth_tx_burst(ctx->portid, ctx->queueid, &m,1);

}

uint8_t *receive_packet(proxy_ctx_t ctx){


}




proxy_ctx_t* proxy_create_ctx(int portid,int queueid, struct rte_mempool *mb_pool)
{
    proxy_ctx_t* ctx = (proxy_ctx_t*)malloc(sizeof(proxy_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(proxy_ctx_t));
        ctx->portid = portid;
        ctx-> queueid = queueid;
        ctx-> mb_pool = mb_pool;
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
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
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

                if (ctx != NULL && ctx->F != NULL) {
                    fprintf(ctx->F, "Sent: quack\n");
                }
                ret = do_quack_proxy(cnx);
            }
            break;
        case picoquic_callback_datagram:
            decapsulate_and_send(ctx,bytes);
            /* Process the datagram, which contains an address and a QUIC packet */
            
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}