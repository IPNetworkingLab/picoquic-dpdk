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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "picoquic_internal.h"
#include "proxy.h"

#define SIDUCK_ONLY_QUACKS_ECHO 0x101


int encapsulate_and_send(picoquic_cnx_t* cnx,uint8_t *udp_packet,int length) {
    return picoquic_queue_datagram_frame(cnx, length, udp_packet);
}

int decapsulate_and_send(picoquic_cnx_t* cnx, uint8_t *udp_packet, int length) {
    return picoquic_queue_datagram_frame(cnx, sizeof(quack_ack), quack_ack);
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
            /* Process the datagram, which contains an address and a QUIC packet */
            if (cnx->client_mode) {
                if ((ret = check_quack_proxy_ack(bytes, length)) == 0) {
                    if (ctx != NULL && ctx->F != NULL) {
                        fprintf(ctx->F, "Received: quack-ack\n");
                    }
                    picoquic_set_callback(cnx, NULL, NULL);
                    if (ctx != NULL) {
                        if (ctx->is_auto_alloc) {
                            free(ctx);
                            ctx = NULL;
                        }
                        else {
                            ctx->nb_quack_ack_received++;
                        }
                    }
                    ret = picoquic_close(cnx, 0);
                }
                else {
                    if (ctx != NULL && ctx->F != NULL) {
                        fprintf(ctx->F, "Received: datagram, but not a quack-ack\n");
                    }
                    else {
                        DBG_PRINTF("Received a datagram, but not a quack ack, length = %zu", length);
                    }

                    if (ctx != NULL) {
                        if (ctx->is_auto_alloc) {
                            free(ctx);
                            ctx = NULL;
                        }
                        else {
                            ctx->nb_bad_quacks++;
                        }
                    }

                    picoquic_set_callback(cnx, NULL, NULL);
                    ret = picoquic_close(cnx, SIDUCK_ONLY_QUACKS_ECHO);
                }
            } else {
                if ((ret = check_quack_proxy(bytes, length)) == 0) {
                    if (ctx != NULL) {
                        ctx->nb_quack_ack_sent++;
                    }
                    ret = do_quack_proxy_ack(cnx);
                }
                else {
                    DBG_PRINTF("Received a datagram, but not a quack, length = %zu", length);

                    if (ctx != NULL) {
                        if (ctx->is_auto_alloc) {
                            free(ctx);
                            ctx = NULL;
                        }
                        else {
                            ctx->nb_bad_quacks++;
                        }
                    }

                    picoquic_set_callback(cnx, NULL, NULL);
                    ret = picoquic_close(cnx, SIDUCK_ONLY_QUACKS_ECHO);
                }
            }
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}