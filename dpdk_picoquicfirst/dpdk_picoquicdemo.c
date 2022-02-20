/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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




#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

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

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";


#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "autoqlog.h"
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"
#include "siduck.h"
#include "quicperf.h"
#include "picoquic_unified_log.h"
#include "picoquic_logger.h"
#include "picoquic_binlog.h"
#include "performance_log.h"
#include "picoquic_config.h"
#include "picoquic_lb.h"

//dpdk
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
#include <rte_ether.h>


#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define MAX_NB_OF_PORTS_AND_LCORES 32

#define PICOQUIC_SAMPLE_ALPN "picoquic_sample"
#define PICOQUIC_SAMPLE_SNI "test.example.com"

#define PICOQUIC_SAMPLE_NO_ERROR 0
#define PICOQUIC_SAMPLE_INTERNAL_ERROR 0x101
#define PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR 0x102
#define PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR 0x103
#define PICOQUIC_SAMPLE_FILE_READ_ERROR 0x104
#define PICOQUIC_SAMPLE_FILE_CANCEL_ERROR 0x105

#define PICOQUIC_SAMPLE_CLIENT_TICKET_STORE "sample_ticket_store.bin";
#define PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE "sample_token_store.bin";
#define PICOQUIC_SAMPLE_CLIENT_QLOG_DIR ".";
#define PICOQUIC_SAMPLE_SERVER_QLOG_DIR ".";

struct rte_mempool *mb_pools[MAX_NB_OF_PORTS_AND_LCORES];
struct rte_eth_dev_tx_buffer *tx_buffers[MAX_NB_OF_PORTS_AND_LCORES];
struct rte_eth_rxconf rxq_conf;
struct rte_eth_txconf txq_conf;

// hardcoded server mac
struct rte_ether_addr eth_addr;
uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

// global variables for threads
char* server_name;
int server_port = default_server_port;
int force_migration = 0;
int nb_packets_before_update = 0;
char* client_scenario = NULL;
picoquic_quic_config_t config;
int just_once = 0;

/*
 * SIDUCK datagram demo call back.
 */
int siduck_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

void print_address(FILE* F_log, struct sockaddr* address, char* label, picoquic_connection_id_t cnx_id)
{
    char hostname[256];

    const char* x = inet_ntop(address->sa_family,
        (address->sa_family == AF_INET) ? (void*)&(((struct sockaddr_in*)address)->sin_addr) : (void*)&(((struct sockaddr_in6*)address)->sin6_addr),
        hostname, sizeof(hostname));

    fprintf(F_log, "%016llx : ", (unsigned long long)picoquic_val64_connection_id(cnx_id));

    if (x != NULL) {
        fprintf(F_log, "%s %s, port %d\n", label, x,
            (address->sa_family == AF_INET) ? ((struct sockaddr_in*)address)->sin_port : ((struct sockaddr_in6*)address)->sin6_port);
    } else {
        fprintf(F_log, "%s: inet_ntop failed with error # %ld\n", label, WSA_LAST_ERROR(errno));
    }
}

/* server loop call back management */
typedef struct st_server_loop_cb_t {
    int just_once;
    int first_connection_seen;
    int connection_done;
} server_loop_cb_t;

static int server_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    server_loop_cb_t* cb_ctx = (server_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }

        if (ret == 0 && cb_ctx->just_once){
            if (!cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) != NULL) {
                cb_ctx->first_connection_seen = 1;
                fprintf(stdout, "First connection noticed.\n");
            } else if (cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) == NULL) {
                fprintf(stdout, "No more active connections.\n");
                cb_ctx->connection_done = 1;
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
    }
    return ret;
}

int quic_server(const char* server_name, 
                        picoquic_quic_config_t * config, 
                        int just_once, 
                        unsigned portid,
                        unsigned queueid,
                        struct sockaddr_storage addr_from,
                        struct rte_ether_addr *mac_dst,
                        struct rte_mempool *mb_pool,
                        struct rte_eth_dev_tx_buffer *tx_buffer)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    uint64_t current_time = 0;
    picohttp_server_parameters_t picoquic_file_param;
    server_loop_cb_t loop_cb_ctx;

    memset(&picoquic_file_param, 0, sizeof(picohttp_server_parameters_t));
    picoquic_file_param.web_folder = config->www_dir;
    memset(&loop_cb_ctx, 0, sizeof(server_loop_cb_t));
    loop_cb_ctx.just_once = just_once;

    /* Setup the server context */
    if (ret == 0) {
        current_time = picoquic_current_time();
        /* Create QUIC context */

        if (config->ticket_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Ticket_File_Name, ticket_store_filename);
        }
        if (ret == 0 && config->token_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Token_File_Name, token_store_filename);
        }
        if (ret == 0) {
            qserver = picoquic_create_and_configure(config, picoquic_demo_server_callback, &picoquic_file_param, current_time, NULL);
            if (qserver == NULL) {
                ret = -1;
            }
            else {
                picoquic_set_key_log_file_from_env(qserver);

                picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn);

                picoquic_set_mtu_max(qserver, config->mtu_max);
                if (config->qlog_dir != NULL)
                {
                    picoquic_set_qlog(qserver, config->qlog_dir);
                }
                if (config->performance_log != NULL)
                {
                    ret = picoquic_perflog_setup(qserver, config->performance_log);
                }
                if (ret == 0 && config->cnx_id_cbdata != NULL) {
                    picoquic_load_balancer_config_t lb_config;
                    ret = picoquic_lb_compat_cid_config_parse(&lb_config, config->cnx_id_cbdata, strlen(config->cnx_id_cbdata));
                    if (ret != 0) {
                        fprintf(stdout, "Cannot parse the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                    }
                    else {
                        ret = picoquic_lb_compat_cid_config(qserver, &lb_config);
                        if (ret != 0) {
                            fprintf(stdout, "Cannot set the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                        }
                    }
                }
            }
        }
    }

    if (ret == 0) {
        /* Wait for packets */
#if _WINDOWS
        ret = picoquic_packet_loop_win(qserver, config->server_port, 0, config->dest_if, 
            config->socket_buffer_size, server_loop_cb, &loop_cb_ctx);
#else
        ret = picoquic_packet_loop_dpdk(qserver, config->server_port, 0, config->dest_if,
            config->socket_buffer_size, config->do_not_use_gso, server_loop_cb, &loop_cb_ctx,portid,queueid, addr_from,NULL,mb_pool, tx_buffer);
#endif
    }

    /* And exit */
    printf("Server exit, ret = 0x%x\n", ret);

    /* Clean up */
    if (config->cnx_id_cbdata != NULL) {
        picoquic_lb_compat_cid_config_free(qserver);
    }
    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

static const char * test_scenario_default = "0:index.html;4:test.html;8:/1234567;12:main.jpg;16:war-and-peace.txt;20:en/latest/;24:/file-123K";

/* Client loop call back management.
 * This is pretty complex, because the demo client is used to test a variety of interop
 * scenarios, for example:
 *
 * Variants of migration:
 * - Basic NAT traversal (1)
 * - Simple CID swap (2)
 * - Organized migration (3)
 * Encryption key rotation, after some number of packets have been sent.
 *
 * The client loop terminates when the client connection is closed.
 */

typedef struct st_client_loop_cb_t {
    picoquic_cnx_t* cnx_client;
    picoquic_demo_callback_ctx_t* demo_callback_ctx;
    siduck_ctx_t* siduck_ctx;
    int notified_ready;
    int established;
    int migration_to_preferred_started;
    int migration_to_preferred_finished;
    int migration_started;
    int address_updated;
    int force_migration;
    int nb_packets_before_key_update;
    int key_update_done;
    int zero_rtt_available;
    int is_siduck;
    int is_quicperf;
    int socket_buffer_size;
    char const* saved_alpn;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
} client_loop_cb_t;

int client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    client_loop_cb_t* cb_ctx = (client_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            if ((!cb_ctx->is_siduck && !cb_ctx->is_quicperf && cb_ctx->demo_callback_ctx->connection_closed) ||
                cb_ctx->cnx_client->cnx_state == picoquic_state_disconnected) {
                fprintf(stdout, "The connection is closed!\n");
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                break;
            }
            /* Keeping track of the addresses and ports, as we
             * need them to verify the migration behavior */
            if (!cb_ctx->address_updated && cb_ctx->cnx_client->path[0]->local_addr.ss_family != 0) {
                uint16_t updated_port = (cb_ctx->cnx_client->path[0]->local_addr.ss_family == AF_INET) ?
                    ((struct sockaddr_in*) & cb_ctx->cnx_client->path[0]->local_addr)->sin_port :
                    ((struct sockaddr_in6*) & cb_ctx->cnx_client->path[0]->local_addr)->sin6_port;
                if (updated_port != 0) {
                    cb_ctx->address_updated = 1;
                    picoquic_store_addr(&cb_ctx->client_address, (struct sockaddr*) & cb_ctx->cnx_client->path[0]->local_addr);
                    fprintf(stdout, "Client port (AF=%d): %d.\n", cb_ctx->client_address.ss_family, updated_port);
                }
            }
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_almost_ready && cb_ctx->notified_ready == 0) {
                /* if almost ready, display results of negotiation */
                if (picoquic_tls_is_psk_handshake(cb_ctx->cnx_client)) {
                    fprintf(stdout, "The session was properly resumed!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "The session was properly resumed!");
                }

                if (cb_ctx->cnx_client->zero_rtt_data_accepted) {
                    fprintf(stdout, "Zero RTT data is accepted!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "Zero RTT data is accepted!");
                }

                if (cb_ctx->cnx_client->alpn != NULL) {
                    fprintf(stdout, "Negotiated ALPN: %s\n", cb_ctx->cnx_client->alpn);
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "Negotiated ALPN: %s", cb_ctx->cnx_client->alpn);
                    cb_ctx->saved_alpn = picoquic_string_duplicate(cb_ctx->cnx_client->alpn);
                }
                fprintf(stdout, "Almost ready!\n\n");
                cb_ctx->notified_ready = 1;
            }
            else if (ret == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                /* Track the migration to server preferred address */
                if (cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined && !cb_ctx->migration_to_preferred_finished) {
                    if (picoquic_compare_addr(
                        (struct sockaddr*) & cb_ctx->server_address, (struct sockaddr*) & cb_ctx->cnx_client->path[0]->peer_addr) != 0) {
                        fprintf(stdout, "Migrated to server preferred address!\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Migrated to server preferred address!");
                        cb_ctx->migration_to_preferred_finished = 1;
                    }
                    else if (cb_ctx->cnx_client->nb_paths > 1 && !cb_ctx->migration_to_preferred_started) {
                        cb_ctx->migration_to_preferred_started = 1;
                        fprintf(stdout, "Attempting migration to server preferred address.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Attempting migration to server preferred address.");

                    }
                    else if (cb_ctx->cnx_client->nb_paths == 1 && cb_ctx->migration_to_preferred_started) {
                        fprintf(stdout, "Could not migrate to server preferred address!\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Could not migrate to server preferred address!");
                        cb_ctx->migration_to_preferred_finished = 1;
                    }
                }

                /* Execute the migration trials
                 * The actual change of sockets is delegated to the packet loop function,
                 * so it can be integrated with other aspects of socket management.
                 * If a new socket is needed, two special error codes will be used.
                 */
                if (cb_ctx->force_migration && cb_ctx->migration_started == 0 && cb_ctx->address_updated &&
                    picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready &&
                    (cb_ctx->cnx_client->cnxid_stash_first != NULL || cb_ctx->force_migration == 1) &&
                    (!cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined ||
                        cb_ctx->migration_to_preferred_finished)) {
                    int mig_ret = 0;
                    cb_ctx->migration_started = 1;
                    cb_ctx->server_cid_before_migration = cb_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id;
                    if (cb_ctx->cnx_client->path[0]->p_local_cnxid != NULL) {
                        cb_ctx->client_cid_before_migration = cb_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id;
                    }
                    else {
                        /* Special case of forced migration after preferred address migration */
                        memset(&cb_ctx->client_cid_before_migration, 0, sizeof(picoquic_connection_id_t));
                    }
                    switch (cb_ctx->force_migration) {
                    case 1:
                        fprintf(stdout, "Switch to new port. Will test NAT rebinding support.\n");
                        ret = PICOQUIC_NO_ERROR_SIMULATE_NAT;
                        break;
                    case 2:
                        mig_ret = picoquic_renew_connection_id(cb_ctx->cnx_client, 0);
                        if (mig_ret != 0) {
                            if (mig_ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                                fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                            }
                            else {
                                fprintf(stdout, "Renew CNXID failed, error: %x.\n", mig_ret);
                            }
                            cb_ctx->migration_started = -1;
                        }
                        else {
                            fprintf(stdout, "Switching to new CNXID.\n");
                        }
                        break;
                    case 3:
                        fprintf(stdout, "Will test migration to new port.\n");
                        ret = PICOQUIC_NO_ERROR_SIMULATE_MIGRATION;
                        break;
                    default:
                        cb_ctx->migration_started = -1;
                        fprintf(stdout, "Invalid migration code: %d!\n", cb_ctx->force_migration);
                        break;
                    }
                }

                /* Track key update */
                if (cb_ctx->nb_packets_before_key_update > 0 &&
                    !cb_ctx->key_update_done &&
                    picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready &&
                    cb_ctx->cnx_client->nb_packets_received > (uint64_t)cb_ctx->nb_packets_before_key_update) {
                    int key_rot_ret = picoquic_start_key_rotation(cb_ctx->cnx_client);
                    if (key_rot_ret != 0) {
                        fprintf(stdout, "Will not test key rotation.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Will not test key rotation.");
                        cb_ctx->key_update_done = -1;
                    }
                    else {
                        fprintf(stdout, "Key rotation started.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Key rotation started.");
                        cb_ctx->key_update_done = 1;
                    }
                }

                if (!cb_ctx->is_siduck && !cb_ctx->is_quicperf && cb_ctx->demo_callback_ctx->nb_open_streams == 0) {
                    fprintf(stdout, "All done, Closing the connection.\n");
                    picoquic_log_app_message(cb_ctx->cnx_client, "%s", "All done, Closing the connection.");

                    ret = picoquic_close(cb_ctx->cnx_client, 0);
                }
            }
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            else if (ret == 0 && cb_ctx->established == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                printf("Connection established. Version = %x, I-CID: %llx, verified: %d\n",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);

                picoquic_log_app_message(cb_ctx->cnx_client,
                    "Connection established. Version = %x, I-CID: %llx, verified: %d",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);
                cb_ctx->established = 1;

                if (!cb_ctx->zero_rtt_available && !cb_ctx->is_siduck && !cb_ctx->is_quicperf) {
                    /* Start the download scenario */
                    picoquic_demo_client_start_streams(cb_ctx->cnx_client, cb_ctx->demo_callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

/* Quic Client */
int quic_client(const char* ip_address_text, int server_port, 
    picoquic_quic_config_t * config, int force_migration,
    int nb_packets_before_key_update, char const * client_scenario_text, unsigned portid,
    unsigned queueid,
                           struct sockaddr_storage addr_from,
                           struct rte_ether_addr *mac_dst,
                           struct rte_mempool *mb_pool,
                           struct rte_eth_dev_tx_buffer *tx_buffer)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    uint64_t current_time = 0;
    int is_name = 0;
    size_t client_sc_nb = 0;
    picoquic_demo_stream_desc_t * client_sc = NULL;
    int is_siduck = 0;
    siduck_ctx_t* siduck_ctx = NULL;
    int is_quicperf = 0;
    quicperf_ctx_t* quicperf_ctx = NULL;
    client_loop_cb_t loop_cb;
    const char* sni = config->sni;

    struct sockaddr_storage server_address;
    (*(struct sockaddr_in *)(&server_address)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&server_address)).sin_port = htons(4443);
    (*(struct sockaddr_in *)(&server_address)).sin_addr.s_addr = inet_addr("198.18.0.2");
    
    memset(&loop_cb, 0, sizeof(client_loop_cb_t));
    loop_cb.server_address = server_address;
    
    /* Create QUIC context */
    current_time = picoquic_current_time();
    callback_ctx.last_interaction_time = current_time;

    if (ret == 0) {
        if (config->ticket_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Ticket_File_Name, ticket_store_filename);
        }
        if (ret == 0 && config->token_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Token_File_Name, token_store_filename);
        }
        if (ret == 0) {
            qclient = picoquic_create_and_configure(config, NULL, NULL, current_time, NULL);
            if (qclient == NULL) {
                ret = -1;
            }
            else {
                picoquic_set_key_log_file_from_env(qclient);

                if (config->qlog_dir != NULL)
                {
                    picoquic_set_qlog(qclient, config->qlog_dir);
                }

                if (config->performance_log != NULL)
                {
                    ret = picoquic_perflog_setup(qclient, config->performance_log);
                }
            }
        }
    }

    /* If needed, set ALPN and proposed version from tickets */
    if (config->alpn == NULL || config->proposed_version == 0) {
        char const* ticket_alpn;
        uint32_t ticket_version;

        if (picoquic_demo_client_get_alpn_and_version_from_tickets(qclient,  sni, config->alpn,
            config->proposed_version, current_time, &ticket_alpn, &ticket_version) == 0) {
            if (ticket_alpn != NULL) {
                fprintf(stdout, "Set ALPN to %s based on stored ticket\n", ticket_alpn);
                picoquic_config_set_option(config, picoquic_option_ALPN, ticket_alpn);
            }
            
            if (ticket_version != 0) {
                fprintf(stdout, "Set version to 0x%08x based on stored ticket\n", ticket_version);
                config->proposed_version = ticket_version;
            }
        }
    }

    if (ret == 0) {
        if (config->alpn != NULL && (strcmp(config->alpn, "siduck") == 0 || strcmp(config->alpn, "siduck-00") == 0)) {
            /* Set a siduck client */
            is_siduck = 1;
            siduck_ctx = siduck_create_ctx(stdout);
            if (siduck_ctx == NULL) {
                fprintf(stdout, "Could not get ready to quack\n");
                return -1;
            }
            fprintf(stdout, "Getting ready to quack\n");
        }
        else if (config->alpn != NULL && strcmp(config->alpn, QUICPERF_ALPN) == 0) {
            /* Set a QUICPERF client */
            is_quicperf = 1;
            quicperf_ctx = quicperf_create_ctx(client_scenario_text);
            if (quicperf_ctx == NULL) {
                fprintf(stdout, "Could not get ready to run QUICPERF\n");
                return -1;
            }
            fprintf(stdout, "Getting ready to run QUICPERF\n");
        }
        else {
            if (config->no_disk) {
                fprintf(stdout, "Files not saved to disk (-D, no_disk)\n");
            }

            if (client_scenario_text == NULL) {
                client_scenario_text = test_scenario_default;
            }

            fprintf(stdout, "Testing scenario: <%s>\n", client_scenario_text);
            ret = demo_client_parse_scenario_desc(client_scenario_text, &client_sc_nb, &client_sc);
            if (ret != 0) {
                fprintf(stdout, "Cannot parse the specified scenario.\n");
                return -1;
            }
            else {
                ret = picoquic_demo_client_initialize_context(&callback_ctx, client_sc, client_sc_nb, config->alpn, config->no_disk, 0);
                callback_ctx.out_dir = config->out_dir;
            }
        }
    }

    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&server_address, current_time,
            config->proposed_version, sni, config->alpn, 1);

        if (cnx_client == NULL) {
            ret = -1;
        }
        else {
            if (is_siduck) {
                picoquic_set_callback(cnx_client, siduck_callback, siduck_ctx);
                cnx_client->local_parameters.max_datagram_frame_size = 128;
            }
            else if (is_quicperf) {
                picoquic_set_callback(cnx_client, quicperf_callback, quicperf_ctx);
            }
            else {
                picoquic_set_callback(cnx_client, picoquic_demo_client_callback, &callback_ctx);

                /* Requires TP grease, for interop tests */
                cnx_client->grease_transport_parameters = 1;
                cnx_client->local_parameters.enable_time_stamp = 3;
                cnx_client->local_parameters.do_grease_quic_bit = 1;

                if (callback_ctx.tp != NULL) {
                    picoquic_set_transport_parameters(cnx_client, callback_ctx.tp);
                }
            }

            if (config->large_client_hello) {
                cnx_client->test_large_chello = 1;
            }

            if (config->esni_rr_file != NULL) {
                ret = picoquic_esni_client_from_file(cnx_client, config->esni_rr_file);
            }

            if (config->desired_version != 0) {
                picoquic_set_desired_version(cnx_client, config->desired_version);
            }

            fprintf(stdout, "Max stream id bidir remote before start = %d (%d)\n",
                (int)cnx_client->max_stream_id_bidir_remote,
                (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

            if (ret == 0) {
                ret = picoquic_start_client_cnx(cnx_client);

                printf("Starting client connection. Version = %x, I-CID: %llx\n",
                    picoquic_supported_versions[cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)));

                fprintf(stdout, "Max stream id bidir remote after start = %d (%d)\n",
                    (int)cnx_client->max_stream_id_bidir_remote,
                    (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);
            }

            if (ret == 0 && !is_siduck && !is_quicperf) {
                if (picoquic_is_0rtt_available(cnx_client) && (config->proposed_version & 0x0a0a0a0a) != 0x0a0a0a0a) {
                    loop_cb.zero_rtt_available = 1;

                    fprintf(stdout, "Max stream id bidir remote after 0rtt = %d (%d)\n",
                        (int)cnx_client->max_stream_id_bidir_remote,
                        (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

                    /* Queue a simple frame to perform 0-RTT test */
                    /* Start the download scenario */

                    ret = picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
        }
    }

    /* Wait for packets */
    if (ret == 0) {
        loop_cb.cnx_client = cnx_client;
        loop_cb.force_migration = force_migration;
        loop_cb.nb_packets_before_key_update = nb_packets_before_key_update;
        loop_cb.is_siduck = is_siduck;
        loop_cb.is_quicperf = is_quicperf;
        loop_cb.socket_buffer_size = config->socket_buffer_size;
        if (is_siduck) {
            loop_cb.siduck_ctx = siduck_ctx;
        }
        else if (!is_quicperf) {
            loop_cb.demo_callback_ctx = &callback_ctx;
        }

#ifdef _WINDOWS
        ret = picoquic_packet_loop_win(qclient, 0, loop_cb.server_address.ss_family, 0, 
            config->socket_buffer_size, client_loop_cb, &loop_cb);
#else
        ret = picoquic_packet_loop_dpdk(qclient, 0, loop_cb.server_address.ss_family, 0,
            config->socket_buffer_size, config->do_not_use_gso, client_loop_cb, &loop_cb, portid, queueid, addr_from, mac_dst, mb_pool, tx_buffer);
#endif
    }

    if (ret == 0) {
        uint64_t last_err;
        
        if ((last_err = picoquic_get_local_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with local error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }
        if ((last_err = picoquic_get_remote_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with remote error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }
        if ((last_err = picoquic_get_application_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with application error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }

        /* Report on successes and failures */
        if (cnx_client->nb_zero_rtt_sent != 0) {
            fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
            picoquic_log_app_message(cnx_client, "Out of %d zero RTT packets, %d were acked by the server.",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
        }

        fprintf(stdout, "Quic Bit was %sgreased by the client.\n", (cnx_client->quic_bit_greased) ? "" : "NOT ");
        fprintf(stdout, "Quic Bit was %sgreased by the server.\n", (cnx_client->quic_bit_received_0) ? "" : "NOT ");

        if (cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect0_total_local != 0 ||
            cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect1_total_local != 0 ||
            cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ce_total_local != 0) {
            fprintf(stdout, "ECN was received (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect0_total_local,
                cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect1_total_local,
                cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ce_total_local);
        }
        else {
            fprintf(stdout, "ECN was not received.\n");
        }

        if (cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote != 0) {
            fprintf(stdout, "ECN was acknowledged (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote);
        }
        else {
            fprintf(stdout, "ECN was not acknowledged.\n");
        }

        if (config->desired_version != 0) {
            uint32_t v = picoquic_supported_versions[cnx_client->version_index].version;
            if (v == config->desired_version) {
                fprintf(stdout, "Successfully negotiated version 0x%" PRIx32 ".\n", v);
            }
            else {
                fprintf(stdout, "Could not negotiate version 0x%" PRIx32 ", used version 0x%" PRIu32 ".\n", 
                    config->desired_version, v);
            }
        }

        if (loop_cb.force_migration){
            if (!loop_cb.migration_started) {
                fprintf(stdout, "Could not start testing migration.\n");
                picoquic_log_app_message(cnx_client, "%s", "Could not start testing migration.");
                loop_cb.migration_started = -1;
            }
            else {
                int source_addr_cmp = picoquic_compare_addr(
                    (struct sockaddr*) & cnx_client->path[0]->local_addr,
                    (struct sockaddr*) & loop_cb.client_address);
                int dest_cid_cmp = picoquic_compare_connection_id(
                    &cnx_client->path[0]->p_remote_cnxid->cnx_id,
                    &loop_cb.server_cid_before_migration);
                fprintf(stdout, "After migration:\n");
                fprintf(stdout, "- Default source address %s\n", (source_addr_cmp) ? "changed" : "did not change");
                if (cnx_client->path[0]->p_local_cnxid == NULL) {
                    fprintf(stdout, "- Local CID is NULL!\n");
                }
                else {
                    int source_cid_cmp = picoquic_compare_connection_id(
                        &cnx_client->path[0]->p_local_cnxid->cnx_id,
                        &loop_cb.client_cid_before_migration);
                    fprintf(stdout, "- Local CID %s\n", (source_cid_cmp) ? "changed" : "did not change");
                }
                fprintf(stdout, "- Remode CID %s\n", (dest_cid_cmp) ? "changed" : "did not change");
            }
        }

        if (loop_cb.nb_packets_before_key_update > 0) {
            if (loop_cb.key_update_done == 0) {
                fprintf(stdout, "Did not start key rotation.\n");
            }
            else if (loop_cb.key_update_done == -1) {
                fprintf(stdout, "Error when starting key rotation.\n");
            }
            else {
                uint64_t crypto_rotation_sequence;
                if (cnx_client->is_multipath_enabled) {
                    crypto_rotation_sequence = cnx_client->path[0]->p_local_cnxid->ack_ctx.crypto_rotation_sequence;
                }
                else {
                    crypto_rotation_sequence = cnx_client->ack_ctx[picoquic_packet_context_application].crypto_rotation_sequence;
                }
                fprintf(stdout, "Crypto rotation sequence: %" PRIu64 ", phase ENC: %d, phase DEC: %d\n",
                    crypto_rotation_sequence, cnx_client->key_phase_enc, cnx_client->key_phase_dec);
            }
        }

        if (picoquic_get_data_received(cnx_client) > 0) {
            uint64_t start_time = picoquic_get_cnx_start_time(cnx_client);
            uint64_t close_time = picoquic_get_quic_time(qclient);
            double duration_usec = (double)(close_time - start_time);

            if (duration_usec > 0) {
                if (is_quicperf) {
                    double duration_sec = duration_usec / 1000000.0;
                    printf("Connection_duration_sec: %f\n", duration_sec);
                    printf("Nb_transactions: %" PRIu64"\n", quicperf_ctx->nb_streams);
                    printf("Upload_bytes: %" PRIu64"\n", quicperf_ctx->data_sent);
                    printf("Download_bytes: %" PRIu64"\n", quicperf_ctx->data_received);
                    printf("TPS: %f\n", ((double)quicperf_ctx->nb_streams) / duration_sec);
                    printf("Upload_Mbps: %f\n", ((double)quicperf_ctx->data_sent) * 8.0 / duration_usec);
                    printf("Download_Mbps: %f\n", ((double)quicperf_ctx->data_received) * 8.0 / duration_usec);

                    picoquic_log_app_message(cnx_client, "Received %" PRIu64 " bytes in %f seconds, %f Mbps.",
                        picoquic_get_data_received(cnx_client), duration_usec, ((double)quicperf_ctx->data_received) * 8.0 / duration_usec);
                }
                else {
                    double receive_rate_mbps = 8.0 * ((double)picoquic_get_data_received(cnx_client)) / duration_usec;
                    fprintf(stdout, "Received %" PRIu64 " bytes in %f seconds, %f Mbps.\n",
                        picoquic_get_data_received(cnx_client),
                        duration_usec / 1000000.0, receive_rate_mbps);
                    picoquic_log_app_message(cnx_client, "Received %" PRIu64 " bytes in %f seconds, %f Mbps.",
                        picoquic_get_data_received(cnx_client),
                        duration_usec / 1000000.0, receive_rate_mbps);
                }
                /* Print those for debugging the effects of ack frequency and flow control */
                printf("max_data_local: %" PRIu64 "\n", cnx_client->maxdata_local);
                printf("max_max_stream_data_local: %" PRIu64 "\n", cnx_client->max_max_stream_data_local);
                printf("max_data_remote: %" PRIu64 "\n", cnx_client->maxdata_remote);
                printf("max_max_stream_data_remote: %" PRIu64 "\n", cnx_client->max_max_stream_data_remote);
                printf("ack_delay_remote: %" PRIu64 " ... %" PRIu64 "\n",
                    cnx_client->min_ack_delay_remote, cnx_client->max_ack_delay_remote);
                printf("max_ack_gap_remote: %" PRIu64 "\n", cnx_client->max_ack_gap_remote);
                printf("ack_delay_local: %" PRIu64 " ... %" PRIu64 "\n",
                    cnx_client->min_ack_delay_local, cnx_client->max_ack_delay_local);
                printf("max_ack_gap_local: %" PRIu64 "\n", cnx_client->max_ack_gap_local);
                printf("max_mtu_sent: %zu\n", cnx_client->max_mtu_sent);
                printf("max_mtu_received: %zu\n", cnx_client->max_mtu_received);
            }
        }
    }

    if (qclient != NULL) {
        uint8_t* ticket;
        uint16_t ticket_length;

        if (sni != NULL && loop_cb.saved_alpn != NULL && 0 == picoquic_get_ticket(qclient->p_first_ticket, current_time, sni, (uint16_t)strlen(sni), loop_cb.saved_alpn,
            (uint16_t)strlen(loop_cb.saved_alpn), 0, &ticket, &ticket_length, NULL, 0)) {
            fprintf(stdout, "Received ticket from %s (%s):\n", sni, loop_cb.saved_alpn);
            picoquic_log_picotls_ticket(stdout, picoquic_null_connection_id, ticket, ticket_length);
        }

        if (picoquic_save_session_tickets(qclient, config->ticket_file_name) != 0) {
            fprintf(stderr, "Could not store the saved session tickets to <%s>.\n", config->ticket_file_name);
        }

        if (picoquic_save_retry_tokens(qclient, config->token_file_name) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", config->token_file_name);
        }

        picoquic_free(qclient);
    }

    /* Clean up */
    if (is_quicperf) {
        if (quicperf_ctx != NULL) {
            quicperf_delete_ctx(quicperf_ctx);
        }
    } else if (is_siduck) {
        if (siduck_ctx != NULL) {
            free(siduck_ctx);
        }
    }
    else {
        picoquic_demo_client_delete_context(&callback_ctx);
    }

    if (loop_cb.saved_alpn != NULL) {
        free((void *)loop_cb.saved_alpn);
        loop_cb.saved_alpn = NULL;
    }

    if (client_scenario_text != NULL && client_sc != NULL) {
        demo_client_delete_scenario_desc(client_sc_nb, client_sc);
        client_sc = NULL;
    }
    return ret;
}

/* TODO: rewrite using common code */
void usage()
{
    fprintf(stderr, "PicoQUIC demo client and server\n");
    fprintf(stderr, "Usage: picoquicdemo <options> [server_name [port [scenario]]] \n");
    fprintf(stderr, "  For the client mode, specify server_name and port.\n");
    fprintf(stderr, "  For the server mode, use -p to specify the port.\n");
    picoquic_config_usage();
    fprintf(stderr, "Picoquic demo options:\n");
    fprintf(stderr, "  -f migration_mode     Force client to migrate to start migration:\n");
    fprintf(stderr, "                        -f 1  test NAT rebinding,\n");
    fprintf(stderr, "                        -f 2  test CNXID renewal,\n");
    fprintf(stderr, "                        -f 3  test migration to new address.\n");
    fprintf(stderr, "  -u nb                 trigger key update after receiving <nb> packets on client\n");
    fprintf(stderr, "  -1                    Once: close the server after processing 1 connection.\n");

    fprintf(stderr, "\nThe scenario argument specifies the set of files that should be retrieved,\n");
    fprintf(stderr, "and their order. The syntax is:\n");
    fprintf(stderr, "  *{[<stream_id>':'[<previous_stream>':'[<format>:]]]path;}\n");
    fprintf(stderr, "where:\n");
    fprintf(stderr, "  <stream_id>:          The numeric ID of the QUIC stream, e.g. 4. By default, the\n");
    fprintf(stderr, "                        next stream in the logical QUIC order, 0, 4, 8, etc.");
    fprintf(stderr, "  <previous_stream>:    The numeric ID of the previous stream. The GET command will\n");
    fprintf(stderr, "                        be issued after that stream's transfer finishes. By default,\n");
    fprintf(stderr, "                        previous stream in this scenario.\n");
    fprintf(stderr, "  <format>:             Whether the received file should be written to disc as\n");
    fprintf(stderr, "                        binary(b) or text(t). Defaults to text.\n");
    fprintf(stderr, "  <path>:               The name of the document that should be retrieved\n");
    fprintf(stderr, "If no scenario is specified, the client executes the default scenario.\n");
    exit(1);
}


int init_mbuf_txbuffer(uint16_t portid,int index){

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

//client is scaling on the number of ports
int init_port_client(uint16_t portid)
{
    int ret = 0;
    int queueid = 0;
    struct rte_eth_dev_info dev_info;

    static struct rte_eth_conf local_port_conf = {
        .rxmode = {
            .split_hdr_size = 0,
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


//client is scaling on the number of cores
int init_port_server(uint16_t nb_of_queues)
{
    int ret = 0;
    int portid = 0;
    static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
    static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_dev_info dev_info;

    static struct rte_eth_conf local_port_conf = {
        .rxmode = {
            .split_hdr_size = 0,
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    };

    printf("after init\n");
    ret = rte_eth_dev_info_get(0, &dev_info);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "Error during getting device (port %u) info: %s\n",
                 0, strerror(-ret));

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    ret = rte_eth_dev_configure(portid, nb_of_queues, nb_of_queues, &local_port_conf);
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
    
    
    char mbuf_pool_name[20] = "mbuf_pool";
    char tx_buffer_name[20] = "tx_buffer_X";
    int index_of_X;
    char char_i;
    unsigned nb_mbufs = 8192U;

    printf("before mb_pools\n");
    mb_pools[0] = rte_pktmbuf_pool_create(mbuf_pool_name, nb_mbufs,
                                            MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                            rte_socket_id());
    printf("after mb_pools[0] = ... \n");
    if (mb_pools[0] == NULL)
    {
        printf("fail to init mb_pool\n");
        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        return 0;
    }
    printf("after mb_pools\n");
    for (int queueid = 0; queueid < nb_of_queues; queueid++)
    {
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
        // init rx queue
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;

        ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, rte_eth_dev_socket_id(0), &rxq_conf, mb_pools[portid]);
        if (ret != 0)
        {
            printf("failed to init rx_queue\n");
        }
        printf("before strlen\n");
        char_i = queueid + '0';
        index_of_X = strlen(tx_buffer_name) - 1;
        tx_buffer_name[index_of_X] = char_i;
        tx_buffers[queueid] = rte_zmalloc_socket(tx_buffer_name,
                                            RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                            rte_eth_dev_socket_id(0));
        if (tx_buffers[0] == NULL)
        {
            printf("fail to init buffer\n");
            return 0;
        }

    }
    
}

static int
client_job(void *arg)
{
    unsigned *tab = (unsigned *) arg;
    unsigned portid = tab[0];
    unsigned queueid = tab[1];

    unsigned lcore_id = rte_lcore_id();
    char char_lcore_id = lcore_id + '0';

    // printf("mychar : %c\n", char_lcore_id);
    struct sockaddr_storage addr_from;

    char str_addr[20] = "198.18.X.1";
    int index_of_x = 7;
    str_addr[index_of_x] = char_lcore_id;
    printf("str_addr %s\n", str_addr);

    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&addr_from)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = inet_addr(str_addr);

    quic_client(server_name, server_port, &config, force_migration, nb_packets_before_update, client_scenario,portid, queueid, addr_from, &eth_addr, mb_pools[portid], tx_buffers[portid]);
}

static int
server_job(void *arg)
{   
    unsigned portid = 0;
    unsigned queueid = *((unsigned *) arg);
    unsigned lcore_id;
    lcore_id = rte_lcore_id();
    struct sockaddr_storage addr_from;
    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&addr_from)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = inet_addr("198.18.0.2");
    printf("before quic_server\n");
    quic_server(server_name, &config, just_once,portid, queueid ,addr_from,NULL,mb_pools[0],tx_buffers[0]);
}


int check_ports_lcores_numbers(){
    int nbr_of_ports = 0;
    int nbr_of_lcores = 0;
    unsigned portid;
    unsigned lcore_id;

    RTE_ETH_FOREACH_DEV(portid)
    {   
        nbr_of_ports++;
    }
    
    RTE_LCORE_FOREACH(lcore_id)
    {
        nbr_of_lcores++;
    }
    if(nbr_of_lcores != nbr_of_ports){
        printf("nbr_of_lcores : %u\n", nbr_of_lcores);
        printf("nbr_of_ports %u\n",nbr_of_ports);
        return -1;
    }
    return 0;
}

int get_nb_port(){
    int count = 0;
    unsigned portid;
     RTE_ETH_FOREACH_DEV(portid)
    {   
        count++;
    }
    return count;
}

int get_nb_core(){
    int count = 0;
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id)
    {
        count++;
    }
    return count;
}

int str_to_mac(char *mac_txt, struct rte_ether_addr *mac_addr)
{
    printf("mac_txt : %s\n",mac_txt);
    int values[6];
    int i;
    printf("before if\n");
    if (6 == sscanf(mac_txt, "%x:%x:%x:%x:%x:%x%*c",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]))
    {
        /* convert to uint8_t */
        printf("before for\n");
        for (i = 0; i < 6; ++i){
            (mac_addr -> addr_bytes)[i] = (uint8_t)values[i];
        }
        return 0;
    }

    else
    {
        printf("invalid mac address : %s\n",mac_txt);
        return -1;
    }
}

int main(int argc, char** argv)
{
    picoquic_quic_config_t config;
    char option_string[512];
    int opt;
    char default_server_cert_file[512];
    char default_server_key_file[512];
    int just_once = 0;
    int is_client = 0;
    int ret;
    unsigned portid;
    unsigned lcore_id;
    unsigned args[2];
    server_name = default_server_name;


    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    argc -= ret;
    argv += ret;
    printf("after EAL \n");
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    picoquic_config_init(&config);
    memcpy(option_string, "u:f:1:A:", 8);
    ret = picoquic_config_option_letters(option_string + 8, sizeof(option_string) - 8, NULL);
    printf("after config\n");

    if (ret == 0) {
        /* Get the parameters */
        while ((opt = getopt(argc, argv, option_string)) != -1) {
            switch (opt) {
            case 'u':
                if ((nb_packets_before_update = atoi(optarg)) <= 0) {
                    fprintf(stderr, "Invalid number of packets: %s\n", optarg);
                    usage();
                }
                break;
            case 'f':
                force_migration = atoi(optarg);
                printf("optarg : %s\n",optarg);
                if (force_migration <= 0 || force_migration > 3) {
                    fprintf(stderr, "Invalid migration mode: %s\n", optarg);
                    usage();
                }
                break;
            case '1':
                just_once = 1;
                break;
            case 'A':
                printf("inside mac0\n");
                printf("optarg : %s\n",optarg);
                if(str_to_mac(optarg,&eth_addr) != 0){
                    printf("inside mac1\n");
                    return -1;
                }
                break;
            default:
                if (picoquic_config_command_line(opt, &optind, argc, (char const **)argv, optarg, &config) != 0) {
                    printf("inside default\n");
                    usage();
                }
                break;
            }
        }
    }
    printf("aftergetopt\n");
    /* Simplified style params */
    if (optind < argc) {
        server_name = argv[optind++];
        is_client = 1;
    }

    if (optind < argc) {
        if ((server_port = atoi(argv[optind++])) <= 0) {
            fprintf(stderr, "Invalid port: %s\n", optarg);
            usage();
        }
    }

    if (optind < argc) {
        client_scenario = argv[optind++];
    }

    if (optind < argc) {
        usage();
    }
    printf("before check\n");
    if (is_client == 0) {
        printf("inside server\n");
        if (config.server_port == 0) {
            config.server_port = server_port;
        }

        if (config.server_cert_file == NULL &&
            picoquic_get_input_path(default_server_cert_file, sizeof(default_server_cert_file), config.solution_dir, SERVER_CERT_FILE) == 0) {
            /* Using set option call to ensure proper memory management*/
            picoquic_config_set_option(&config, picoquic_option_CERT, default_server_cert_file);
        }

        if (config.server_key_file == NULL &&
            picoquic_get_input_path(default_server_key_file, sizeof(default_server_key_file), config.solution_dir, SERVER_KEY_FILE) == 0) {
            /* Using set option call to ensure proper memory management*/
            picoquic_config_set_option(&config, picoquic_option_KEY, default_server_key_file);
        }
        printf("before init_port\n");
        init_port_server(get_nb_core());
        printf("before start\n");
        ret = rte_eth_dev_start(0);
        if (ret != 0)
        {
            printf("failed to start device\n");
        }
    
        /* Run as server */
        int index_lcore = 0;
        printf("Starting Picoquic server (v%s) on port %d, server name = %s, just_once = %d, do_retry = %d\n",
            PICOQUIC_VERSION, config.server_port, server_name, just_once, config.do_retry);

        // RTE_LCORE_FOREACH_WORKER(lcore_id)
        // {
        //     printf("launching server\n");
        //     rte_eal_remote_launch(server_job, index_lcore, lcore_id);
        //     index_lcore++;
        // }
        unsigned q = 0;
        server_job(&q);

        printf("Server exit with code = %d\n", ret); 
    }
    else {
        printf("inside client\n");

        /* Run as client */
        // hardcoded server addr, need to change that
        unsigned portids[MAX_NB_OF_PORTS_AND_LCORES];

        int index_port = 0;
        RTE_ETH_FOREACH_DEV(portid)
        {   
            portids[index_port] = portid;
            init_port_client(portid);
            init_mbuf_txbuffer(portid,index_port);
            ret = rte_eth_dev_start(portid);
            if (ret != 0)
            {
                printf("failed to start device\n");
            }
            index_port++;
        }
        if(check_ports_lcores_numbers() != 0){
            printf("mismatch between the number of lcore and ports\n");
            return -1;
        }
        unsigned index_lcore = 0;
        
        printf("Starting Picoquic (v%s) connection to server = %s, port = %d\n", PICOQUIC_VERSION, server_name, server_port);
        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
            args[0] = index_lcore;
            args[1] = portids[index_lcore];
            rte_eal_remote_launch(client_job, args, lcore_id);
            index_lcore++;
        }
        /* call it on main lcore too */
        args[0] = index_lcore;
        args[1] = portids[index_lcore];

        client_job(args);
        printf("Client exit with code = %d\n", ret);

    }
    rte_eal_mp_wait_lcore();
    /* clean up the EAL */
    rte_eal_cleanup();
    picoquic_config_clear(&config);
}
