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
#include <unistd.h>

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

//server mac
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
int nb_of_repetition = 1;

/*
 * SIDUCK datagram demo call back.
 */


typedef struct st_sample_client_stream_ctx_t
{
    struct st_sample_client_stream_ctx_t *next_stream;
    size_t file_rank;
    uint64_t stream_id;
    size_t name_length;
    size_t name_sent_length;
    FILE *F;
    size_t bytes_received;
    uint64_t remote_error;
    unsigned int is_name_sent : 1;
    unsigned int is_file_open : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_client_stream_ctx_t;


typedef struct st_sample_client_ctx_t
{
    char const *default_dir;
    char const **file_names;
    sample_client_stream_ctx_t *first_stream;
    sample_client_stream_ctx_t *last_stream;
    int nb_files;
    int nb_files_received;
    int nb_files_failed;
    int is_disconnected;
} sample_client_ctx_t;


typedef struct st_sample_server_stream_ctx_t
{
    struct st_sample_server_stream_ctx_t *next_stream;
    struct st_sample_server_stream_ctx_t *previous_stream;
    uint64_t stream_id;
    FILE *F;
    uint8_t file_name[256];
    size_t name_length;
    size_t file_length;
    size_t file_sent;
    unsigned int is_name_read : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_server_stream_ctx_t;

typedef struct st_sample_server_ctx_t
{
    char const *default_dir;
    size_t default_dir_len;
    sample_server_stream_ctx_t *first_stream;
    sample_server_stream_ctx_t *last_stream;
} sample_server_ctx_t;

struct rte_mempool *mb_pools[10];
struct rte_eth_dev_tx_buffer *tx_buffers[10];

sample_server_stream_ctx_t *sample_server_create_stream_context(sample_server_ctx_t *server_ctx, uint64_t stream_id)
{
    sample_server_stream_ctx_t *stream_ctx = (sample_server_stream_ctx_t *)malloc(sizeof(sample_server_stream_ctx_t));

    if (stream_ctx != NULL)
    {
        memset(stream_ctx, 0, sizeof(sample_server_stream_ctx_t));

        if (server_ctx->last_stream == NULL)
        {
            server_ctx->last_stream = stream_ctx;
            server_ctx->first_stream = stream_ctx;
        }
        else
        {
            stream_ctx->previous_stream = server_ctx->last_stream;
            server_ctx->last_stream->next_stream = stream_ctx;
            server_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

int sample_server_open_stream(sample_server_ctx_t *server_ctx, sample_server_stream_ctx_t *stream_ctx)
{
    int ret = 0;
    char file_path[1024];

    /* Keep track that the full file name was acquired. */
    stream_ctx->is_name_read = 1;

    /* Verify the name, then try to open the file */
    if (server_ctx->default_dir_len + stream_ctx->name_length + 1 > sizeof(file_path))
    {
        ret = PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR;
    }
    else
    {
        /* Verify that the default path is empty of terminates with "/" or "\" depending on OS,
         * and format the file path */
        size_t dir_len = server_ctx->default_dir_len;
        if (dir_len > 0)
        {
            memcpy(file_path, server_ctx->default_dir, dir_len);
            if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0])
            {
                file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                dir_len++;
            }
        }
        memcpy(file_path + dir_len, stream_ctx->file_name, stream_ctx->name_length);
        file_path[dir_len + stream_ctx->name_length] = 0;

        /* Use the picoquic_file_open API for portability to Windows and Linux */
        stream_ctx->F = picoquic_file_open(file_path, "rb");

        if (stream_ctx->F == NULL)
        {
            ret = PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR;
        }
        else
        {
            /* Assess the file size, as this is useful for data planning */
            long sz;
            fseek(stream_ctx->F, 0, SEEK_END);
            sz = ftell(stream_ctx->F);

            if (sz <= 0)
            {
                stream_ctx->F = picoquic_file_close(stream_ctx->F);
                ret = PICOQUIC_SAMPLE_FILE_READ_ERROR;
            }
            else
            {
                stream_ctx->file_length = (size_t)sz;
                fseek(stream_ctx->F, 0, SEEK_SET);
                ret = 0;
            }
        }
    }

    return ret;
}

void sample_server_delete_stream_context(sample_server_ctx_t *server_ctx, sample_server_stream_ctx_t *stream_ctx)
{
    /* Close the file if it was open */
    if (stream_ctx->F != NULL)
    {
        stream_ctx->F = picoquic_file_close(stream_ctx->F);
    }

    /* Remove the context from the server's list */
    if (stream_ctx->previous_stream == NULL)
    {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    else
    {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }

    if (stream_ctx->next_stream == NULL)
    {
        server_ctx->last_stream = stream_ctx->previous_stream;
    }
    else
    {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }

    /* release the memory */
    free(stream_ctx);
}

void sample_server_delete_context(sample_server_ctx_t *server_ctx)
{
    /* Delete any remaining stream context */
    while (server_ctx->first_stream != NULL)
    {
        sample_server_delete_stream_context(server_ctx, server_ctx->first_stream);
    }

    /* release the memory */
    free(server_ctx);
}

int sample_server_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx)
{
    int ret = 0;
    sample_server_ctx_t *server_ctx = (sample_server_ctx_t *)callback_ctx;
    sample_server_stream_ctx_t *stream_ctx = (sample_server_stream_ctx_t *)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx)))
    {
        server_ctx = (sample_server_ctx_t *)malloc(sizeof(sample_server_ctx_t));
        if (server_ctx == NULL)
        {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else
        {
            sample_server_ctx_t *d_ctx = (sample_server_ctx_t *)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
            if (d_ctx != NULL)
            {
                memcpy(server_ctx, d_ctx, sizeof(sample_server_ctx_t));
            }
            else
            {
                /* This really is an error case: the default connection context should never be NULL */
                memset(server_ctx, 0, sizeof(sample_server_ctx_t));
                server_ctx->default_dir = "";
            }
            picoquic_set_callback(cnx, sample_server_callback, server_ctx);
        }
    }

    if (ret == 0)
    {
        switch (fin_or_event)
        {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL)
            {
                /* Create and initialize stream context */
                stream_ctx = sample_server_create_stream_context(server_ctx, stream_id);
            }

            if (stream_ctx == NULL)
            {
                /* Internal error */
                (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return (-1);
            }
            else if (stream_ctx->is_name_read)
            {
                /* Write after fin? */
                return (-1);
            }
            else
            {
                /* Accumulate data */
                size_t available = sizeof(stream_ctx->file_name) - stream_ctx->name_length - 1;

                if (length > available)
                {
                    /* Name too long: reset stream! */
                    sample_server_delete_stream_context(server_ctx, stream_ctx);
                    (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR);
                }
                else
                {
                    if (length > 0)
                    {
                        memcpy(stream_ctx->file_name + stream_ctx->name_length, bytes, length);
                        stream_ctx->name_length += length;
                    }
                    if (fin_or_event == picoquic_callback_stream_fin)
                    {
                        int stream_ret;

                        /* If fin, mark read, check the file, open it. Or reset if there is no such file */
                        stream_ctx->file_name[stream_ctx->name_length + 1] = 0;
                        stream_ctx->is_name_read = 1;
                        stream_ret = sample_server_open_stream(server_ctx, stream_ctx);

                        if (stream_ret == 0)
                        {
                            /* If data needs to be sent, set the context as active */
                            ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                        }
                        else
                        {
                            /* If the file could not be read, reset the stream */
                            sample_server_delete_stream_context(server_ctx, stream_ctx);
                            (void)picoquic_reset_stream(cnx, stream_id, stream_ret);
                        }
                    }
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL)
            {
                printf("inside stream_ctx == NULL\n");
                /* This should never happen */
            }
            else if (stream_ctx->F == NULL)
            {
                printf("inside stream_ctx->F == NULL\n");
                /* Error, asking for data after end of file */
            }
            else
            {
                /* Implement the zero copy callback */
                size_t available = stream_ctx->file_length - stream_ctx->file_sent;
                int is_fin = 1;
                uint8_t *buffer;

                if (available > length)
                {
                    available = length;
                    is_fin = 0;
                }

                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL)
                {
                    size_t nb_read = fread(buffer, 1, available, stream_ctx->F);

                    if (nb_read != available)
                    {
                        /* Error while reading the file */
                        sample_server_delete_stream_context(server_ctx, stream_ctx);
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_READ_ERROR);
                    }
                    else
                    {
                        stream_ctx->file_sent += available;
                    }
                }
                else
                {
                    /* Should never happen according to callback spec. */
                    ret = -1;
                }
            }
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            if (stream_ctx != NULL)
            {
                /* Mark stream as abandoned, close the file, etc. */
                sample_server_delete_stream_context(server_ctx, stream_ctx);
                picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_CANCEL_ERROR);
            }
            break;
        case picoquic_callback_stateless_reset:   /* Received an error message */
        case picoquic_callback_close:             /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            sample_server_delete_context(server_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/* Server loop setup:
 * - Create the QUIC context.
 * - Open the sockets
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the socket return an error.
 */

int picoquic_sample_server(int server_port,
                           const char *server_cert,
                           const char *server_key,
                           const char *default_dir,
                           unsigned queueid,
                           unsigned portid,
                           struct sockaddr_storage addr_from,
                           struct rte_mempool *mb_pool,
                           struct rte_eth_dev_tx_buffer *tx_buffer)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t *quic = NULL;
    char const *qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;
    sample_server_ctx_t default_context = {0};

    default_context.default_dir = default_dir;
    default_context.default_dir_len = strlen(default_dir);

    printf("Starting Picoquic Sample server on port %d\n", server_port);

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
                           sample_server_callback, &default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

    if (quic == NULL)
    {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else
    {
        picoquic_set_cookie_mode(quic, 2);

        picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

        // picoquic_set_qlog(quic, qlog_dir);

        // picoquic_set_log_level(quic, 1);

        // picoquic_set_key_log_file_from_env(quic);
    }

    /* Wait for packets */
    if (ret == 0)
    {
        int running = 1;
        ret = picoquic_packet_loop_dpdk(quic, server_port, 0, 0, 0, 0, NULL, NULL,
        &running,
        portid, addr_from, NULL, NULL, mb_pool, tx_buffer);
    }

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    if (quic != NULL)
    {
        picoquic_free(quic);
    }
    return ret;
}

static int sample_client_create_stream(picoquic_cnx_t *cnx,
                                       sample_client_ctx_t *client_ctx, int file_rank)
{
    int ret = 0;
    sample_client_stream_ctx_t *stream_ctx = (sample_client_stream_ctx_t *)
        malloc(sizeof(sample_client_stream_ctx_t));

    if (stream_ctx == NULL)
    {
        fprintf(stdout, "Memory Error, cannot create stream for file number %d\n", (int)file_rank);
        ret = -1;
    }
    else
    {
        memset(stream_ctx, 0, sizeof(sample_client_stream_ctx_t));
        if (client_ctx->first_stream == NULL)
        {
            client_ctx->first_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        else
        {
            client_ctx->last_stream->next_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        stream_ctx->file_rank = file_rank;
        stream_ctx->stream_id = (uint64_t)4 * file_rank;
        stream_ctx->name_length = strlen(client_ctx->file_names[file_rank]);

        /* Mark the stream as active. The callback will be asked to provide data when
         * the connection is ready. */
        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
        if (ret != 0)
        {
            fprintf(stdout, "Error %d, cannot initialize stream for file number %d\n", ret, (int)file_rank);
        }
        else
        {
            printf("Opened stream %d for file %s\n", 4 * file_rank, client_ctx->file_names[file_rank]);
        }
    }

    return ret;
}

static void sample_client_report(sample_client_ctx_t *client_ctx)
{
    sample_client_stream_ctx_t *stream_ctx = client_ctx->first_stream;

    while (stream_ctx != NULL)
    {
        char const *status;
        if (stream_ctx->is_stream_finished)
        {
            status = "complete";
        }
        else if (stream_ctx->is_stream_reset)
        {
            status = "reset";
        }
        else
        {
            status = "unknown status";
        }
        printf("%s: %s, received %zu bytes", client_ctx->file_names[stream_ctx->file_rank], status, stream_ctx->bytes_received);
        if (stream_ctx->is_stream_reset && stream_ctx->remote_error != PICOQUIC_SAMPLE_NO_ERROR)
        {
            char const *error_text = "unknown error";
            switch (stream_ctx->remote_error)
            {
            case PICOQUIC_SAMPLE_INTERNAL_ERROR:
                error_text = "internal error";
                break;
            case PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR:
                error_text = "internal error";
                break;
            case PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR:
                error_text = "no such file";
                break;
            case PICOQUIC_SAMPLE_FILE_READ_ERROR:
                error_text = "file read error";
                break;
            case PICOQUIC_SAMPLE_FILE_CANCEL_ERROR:
                error_text = "cancelled";
                break;
            default:
                break;
            }
            printf(", error 0x%" PRIx64 " -- %s", stream_ctx->remote_error, error_text);
        }
        printf("\n");
        stream_ctx = stream_ctx->next_stream;
    }
}

static void sample_client_free_context(sample_client_ctx_t *client_ctx)
{
    sample_client_stream_ctx_t *stream_ctx;

    while ((stream_ctx = client_ctx->first_stream) != NULL)
    {
        client_ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->F != NULL)
        {
            (void)picoquic_file_close(stream_ctx->F);
        }
        free(stream_ctx);
    }
    client_ctx->last_stream = NULL;
}

int sample_client_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx)
{
    int ret = 0;
    sample_client_ctx_t *client_ctx = (sample_client_ctx_t *)callback_ctx;
    sample_client_stream_ctx_t *stream_ctx = (sample_client_stream_ctx_t *)v_stream_ctx;

    if (client_ctx == NULL)
    {
        /* This should never happen, because the callback context for the client is initialized
         * when creating the client connection. */
        return -1;
    }

    if (ret == 0)
    {
        // printf("inside ret == 0\n");
        switch (fin_or_event)
        {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL)
            {
                /* This is unexpected, as all contexts were declared when initializing the
                 * connection. */
                return -1;
            }
            else if (!stream_ctx->is_name_sent)
            {
                /* Unexpected: should not receive data before sending the file name to the server */
                return -1;
            }
            else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished)
            {
                /* Unexpected: receive after fin */
                return -1;
            }
            else
            {
                if (stream_ctx->F == NULL)
                {
                    /* Open the file to receive the data. This is done at the last possible moment,
                     * to minimize the number of files open simultaneously.
                     * When formatting the file_path, verify that the directory name is zero-length,
                     * or terminated by a proper file separator.
                     */
                    printf("inside writting to file\n");
                    char file_path[1024];
                    size_t dir_len = strlen(client_ctx->default_dir);
                    size_t file_name_len = strlen(client_ctx->file_names[stream_ctx->file_rank]);

                    if (dir_len > 0 && dir_len < sizeof(file_path))
                    {
                        memcpy(file_path, client_ctx->default_dir, dir_len);
                        if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0])
                        {
                            file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                            dir_len++;
                        }
                    }

                    if (dir_len + file_name_len + 1 >= sizeof(file_path))
                    {
                        /* Unexpected: could not format the file name */
                        fprintf(stderr, "Could not format the file path.\n");
                        ret = -1;
                    }
                    else
                    {
                        memcpy(file_path + dir_len, client_ctx->file_names[stream_ctx->file_rank],
                               file_name_len);

                        unsigned lcore_id = rte_lcore_id();
                        char char_lcore_id = lcore_id + '0';

                        file_path[dir_len + file_name_len] = char_lcore_id;
                        file_path[dir_len + file_name_len] = 0;

                        stream_ctx->F = picoquic_file_open(file_path, "wb");

                        if (stream_ctx->F == NULL)
                        {
                            /* Could not open the file */
                            fprintf(stderr, "Could not open the file: %s\n", file_path);
                            ret = -1;
                        }
                    }
                }

                if (ret == 0 && length > 0)
                {
                    // /* write the received bytes to the file */
                    // if (fwrite(bytes, length, 1, stream_ctx->F) != 1)
                    // {
                    //     /* Could not write file to disk */
                    //     fprintf(stderr, "Could not write data to disk.\n");
                    //     ret = -1;
                    // }
                    // else
                    // {
                    stream_ctx->bytes_received += length;
                    // }
                }

                if (ret == 0 && fin_or_event == picoquic_callback_stream_fin)
                {
                    stream_ctx->F = picoquic_file_close(stream_ctx->F);
                    stream_ctx->is_stream_finished = 1;
                    client_ctx->nb_files_received++;

                    if ((client_ctx->nb_files_received + client_ctx->nb_files_failed) >= client_ctx->nb_files)
                    {
                        /* everything is done, close the connection */
                        ret = picoquic_close(cnx, 0);
                    }
                }
            }
            break;
        case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
            /* Mark stream as abandoned, close the file, etc. */
            picoquic_reset_stream(cnx, stream_id, 0);
            /* Fall through */
        case picoquic_callback_stream_reset: /* Server reset stream #x */
            if (stream_ctx == NULL)
            {
                /* This is unexpected, as all contexts were declared when initializing the
                 * connection. */
                return -1;
            }
            else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished)
            {
                /* Unexpected: receive after fin */
                return -1;
            }
            else
            {
                stream_ctx->remote_error = picoquic_get_remote_stream_error(cnx, stream_id);
                stream_ctx->is_stream_reset = 1;
                client_ctx->nb_files_failed++;

                if ((client_ctx->nb_files_received + client_ctx->nb_files_failed) >= client_ctx->nb_files)
                {
                    /* everything is done, close the connection */
                    fprintf(stdout, "All done, closing the connection.\n");
                    ret = picoquic_close(cnx, 0);
                }
            }
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close:             /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            fprintf(stdout, "Connection closed.\n");
            /* Mark the connection as completed */
            client_ctx->is_disconnected = 1;
            /* Remove the application callback */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The client did not get the right version.
             * TODO: some form of negotiation?
             */
            fprintf(stdout, "Received a version negotiation request:");
            for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4)
            {
                uint32_t vn = 0;
                for (int i = 0; i < 4; i++)
                {
                    vn <<= 8;
                    vn += bytes[byte_index + i];
                }
                fprintf(stdout, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
            }
            fprintf(stdout, "\n");
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL)
            {
                /* Decidedly unexpected */
                return -1;
            }
            else if (stream_ctx->name_sent_length < stream_ctx->name_length)
            {
                uint8_t *buffer;
                size_t available = stream_ctx->name_length - stream_ctx->name_sent_length;
                int is_fin = 1;

                /* The length parameter marks the space available in the packet */
                if (available > length)
                {
                    available = length;
                    is_fin = 0;
                }
                /* Needs to retrieve a pointer to the actual buffer
                 * the "bytes" parameter points to the sending context
                 */
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL)
                {
                    char const *filename = client_ctx->file_names[stream_ctx->file_rank];
                    memcpy(buffer, filename + stream_ctx->name_sent_length, available);
                    stream_ctx->name_sent_length += available;
                    stream_ctx->is_name_sent = is_fin;
                }
                else
                {
                    ret = -1;
                }
            }
            else
            {
                /* Nothing to send, just return */
            }
            break;
        case picoquic_callback_almost_ready:
            fprintf(stdout, "Connection to the server completed, almost ready.\n");
            break;
        case picoquic_callback_ready:
            /* TODO: Check that the transport parameters are what the sample expects */
            fprintf(stdout, "Connection to the server confirmed.\n");
            break;
        default:
            /* unexpected -- just ignore. */
            break;
        }
    }

    return ret;
}

/* Sample client,  loop call back management.
 * The function "picoquic_packet_loop" will call back the application when it is ready to
 * receive or send packets, after receiving a packet, and after sending a packet.
 * We implement here a minimal callback that instruct  "picoquic_packet_loop" to exit
 * when the connection is complete.
 */

static int sample_client_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode,
                                 void *callback_ctx, void *callback_arg)
{
    int ret = 0;
    sample_client_ctx_t *cb_ctx = (sample_client_ctx_t *)callback_ctx;

    if (cb_ctx == NULL)
    {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else
    {
        switch (cb_mode)
        {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            if (cb_ctx->is_disconnected)
            {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
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
int picoquic_sample_client(char const *server_name,
                           int server_port,
                           char const *default_dir,
                           int nb_files,
                           char const **file_names,
                           unsigned portid,
                           struct sockaddr_storage addr_from,
                           struct rte_ether_addr *mac_dst,
                           struct rte_mempool *mb_pool,
                           struct rte_eth_dev_tx_buffer *tx_buffer)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    char const *sni = PICOQUIC_SAMPLE_SNI;
    picoquic_quic_t *quic = NULL;
    char const *ticket_store_filename = PICOQUIC_SAMPLE_CLIENT_TICKET_STORE;
    char const *token_store_filename = PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE;
    char const *qlog_dir = PICOQUIC_SAMPLE_CLIENT_QLOG_DIR;
    sample_client_ctx_t client_ctx = {0};
    picoquic_cnx_t *cnx = NULL;
    uint64_t current_time = picoquic_current_time();

    /* Get the server's address */
    (*(struct sockaddr_in *)(&server_address)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&server_address)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&server_address)).sin_addr.s_addr = inet_addr("198.18.0.2");

    /* Create a QUIC context. It could be used for many connections, but in this sample we
     * will use it for just one connection.
     * The sample code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    if (ret == 0)
    {
        quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, NULL, NULL,
                               NULL, NULL, NULL, current_time, NULL,
                               ticket_store_filename, NULL, 0);

        if (quic == NULL)
        {
            fprintf(stderr, "Could not create quic context\n");
            ret = -1;
        }
        else
        {
            if (picoquic_load_retry_tokens(quic, token_store_filename) != 0)
            {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
            }

            picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

            // picoquic_set_key_log_file_from_env(quic);
            // picoquic_set_qlog(quic, qlog_dir);
            // picoquic_set_log_level(quic, 1);
        }
    }

    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */

    if (ret == 0)
    {
        client_ctx.default_dir = default_dir;
        client_ctx.file_names = file_names;
        client_ctx.nb_files = nb_files;

        printf("Starting connection to %s, port %d\n", server_name, server_port);

        /* Create a client connection */
        cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                                  (struct sockaddr *)&server_address, current_time, 0, sni, PICOQUIC_SAMPLE_ALPN, 1);

        if (cnx == NULL)
        {
            fprintf(stderr, "Could not create connection context\n");
            ret = -1;
        }
        else
        {

            /* Set the client callback context */
            picoquic_set_callback(cnx, sample_client_callback, &client_ctx);
            /* Client connection parameters could be set here, before starting the connection. */
            ret = picoquic_start_client_cnx(cnx);
            if (ret < 0)
            {
                fprintf(stderr, "Could not activate connection\n");
            }
            else
            {
                /* Printing out the initial CID, which is used to identify log files */
                picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
                printf("Initial connection ID: ");
                for (uint8_t i = 0; i < icid.id_len; i++)
                {
                    printf("%02x", icid.id[i]);
                }
                printf("\n");
            }
        }

        /* Create a stream context for all the files that should be downloaded */
        for (int i = 0; ret == 0 && i < client_ctx.nb_files; i++)
        {
            ret = sample_client_create_stream(cnx, &client_ctx, i);
            if (ret < 0)
            {
                fprintf(stderr, "Could not initiate stream for fi\n");
            }
        }
    }

    /* Wait for packets */
    int running = 1;
    ret = picoquic_packet_loop_dpdk(quic, 0, server_address.ss_family, 0, 0, 0,
    sample_client_loop_cb, &client_ctx,
    &running,
    0, portid, addr_from, NULL, mac_dst, mb_pool, tx_buffer);

    /* Done. At this stage, we could print out statistics, etc. */
    sample_client_report(&client_ctx);

    /* Save tickets and tokens, and free the QUIC context */
    if (quic != NULL)
    {
        if (picoquic_save_session_tickets(quic, ticket_store_filename) != 0)
        {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }
        if (picoquic_save_retry_tokens(quic, token_store_filename) != 0)
        {
            fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
        }
        picoquic_free(quic);
    }

    /* Free the Client context */
    sample_client_free_context(&client_ctx);

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


//client is scaling on the number of cores
int init_port_server(uint16_t nb_of_queues)
{
    int ret = 0;
    int portid = 0;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_dev_info dev_info;

    static struct rte_eth_conf local_port_conf = {
        .rxmode = {
            .split_hdr_size = 0,
            .mq_mode = ETH_MQ_RX_RSS,
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
    
    
    char mbuf_pool_name[20] = "mbuf_pool_X";
    char tx_buffer_name[20] = "tx_buffer_X";
    int index_of_X;
    char char_i;
    unsigned nb_mbufs = 8192U * nb_of_queues;

    mb_pools[0] = rte_pktmbuf_pool_create(mbuf_pool_name, nb_mbufs,
                                            MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                            rte_socket_id());
   
    if (mb_pools[0] == NULL)
    {
        printf("fail to init mb_pool\n");
        rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        return 0;
    }
 
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

        ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, mb_pools[portid]);
        if (ret != 0)
        {
            printf("failed to init rx_queue\n");
        }
        char_i = queueid + '0';
        index_of_X = strlen(tx_buffer_name) - 1;
        tx_buffer_name[index_of_X] = char_i;
        tx_buffers[queueid] = rte_zmalloc_socket(tx_buffer_name,
                                            RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                            rte_eth_dev_socket_id(0));
        if (tx_buffers[queueid] == NULL)
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
    unsigned portid = *((unsigned *) arg);
    unsigned queueid = 0;
    unsigned lcore_id = rte_lcore_id();
    printf("lcore_id : %u\n", lcore_id);
    printf("portid : %u\n", portid);
    printf("queueid : %u\n", queueid);
    
    
    //giving a different IP for each client using the portid
    uint32_t ip = (198U << 24) | (18 << 16) | (portid << 8) | 1;
    struct in_addr ip_addr;
    ip_addr.s_addr = rte_cpu_to_be_32(ip);
    printf("The IP address of client %u is %u\n",portid, rte_cpu_to_be_32(ip));

    struct sockaddr_storage addr_from;

    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&addr_from)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = rte_cpu_to_be_32(ip);


    char filename[100] = "50MB.bin";
    char **files = (char **)malloc(1 * sizeof(char *));
    files[0] = (char *)malloc(sizeof(strlen(filename)) + 1);

    memcpy(files[0], filename, strlen(filename) + 1);
    
    for(int i = 0; i < nb_of_repetition;i++){
        picoquic_sample_client("root@TFE-Tyunyayev2", 55, "ClientFolder", 1, files,portid, addr_from, &eth_addr, mb_pools[portid], tx_buffers[pord]);
        sleep(0.1);
    }
}

static int
server_job(void *arg)
{   
    unsigned portid = 0;
    unsigned queueid = (unsigned) arg;
    struct sockaddr_storage addr_from;
    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&addr_from)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = inet_addr("198.18.0.2");
    printf("before quic_server\n");
    quic_server(server_name, &config, just_once,portid, queueid ,addr_from,NULL,mb_pools[portid],tx_buffers[queueid]);
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
    
    RTE_LCORE_FOREACH_WORKER(lcore_id)
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
    RTE_LCORE_FOREACH_WORKER(lcore_id)
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
    if (6 == sscanf(mac_txt, "%x:%x:%x:%x:%x:%x%*c",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]))
    {
        /* convert to uint8_t */
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
    
    char option_string[512];
    int opt;
    char default_server_cert_file[512];
    char default_server_key_file[512];
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
    memcpy(option_string, "u:f:1:A:N:", 10);
    ret = picoquic_config_option_letters(option_string + 10, sizeof(option_string) - 10, NULL);
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
            case 'N':
                ;
                int rep = atoi(optarg);
                if(rep > 0){
                    nb_of_repetition = atoi(optarg);
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
        printf("cores : %u\n", get_nb_core());
        init_port_server(get_nb_core());
        ret = rte_eth_dev_start(0);
        if (ret != 0)
        {
            printf("failed to start device\n");
        }
    
        /* Run as server */
        unsigned index_lcore = 0;
        printf("Starting Picoquic server (v%s) on port %d, server name = %s, just_once = %d, do_retry = %d\n",
            PICOQUIC_VERSION, config.server_port, server_name, just_once, config.do_retry);

        RTE_LCORE_FOREACH_WORKER(lcore_id)
        {
            printf("launching server\n");
            rte_eal_remote_launch(server_job, index_lcore, lcore_id);
            index_lcore++;
        }
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
            
            portids[index_lcore];
            rte_eal_remote_launch(client_job, &portids[index_lcore], lcore_id);
            index_lcore++;
        }
        /* call it on main lcore too */
        // client_job(args);
        printf("Client exit with code = %d\n", ret);

    }
    rte_eal_mp_wait_lcore();
    /* clean up the EAL */
    rte_eal_cleanup();
    picoquic_config_clear(&config);
}
