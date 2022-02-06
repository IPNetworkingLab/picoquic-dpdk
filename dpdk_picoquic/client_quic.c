/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <netinet/if_ether.h>

#include <sys/socket.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <stdarg.h>
#include <inttypes.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <picoquic_packet_loop.h>
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
#include <autoqlog.h>

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

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
                    /* write the received bytes to the file */
                    if (fwrite(bytes, length, 1, stream_ctx->F) != 1)
                    {
                        /* Could not write file to disk */
                        fprintf(stderr, "Could not write data to disk.\n");
                        ret = -1;
                    }
                    else
                    {
                        stream_ctx->bytes_received += length;
                    }
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

/* Client:
 * - Create the QUIC context.
 * - Open the sockets
 * - Find the server's address
 * - Create a client context and a client connection.
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the client connection is finished.
 */

int picoquic_sample_client(char const *server_name, int server_port, char const *default_dir,
                           int nb_files, char const **file_names, 
                           struct sockaddr_storage addr_from)
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

            picoquic_set_key_log_file_from_env(quic);
            picoquic_set_qlog(quic, qlog_dir);
            picoquic_set_log_level(quic, 1);
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

    ret = picoquic_packet_loop_dpdk(quic, 0, server_address.ss_family, 0, 0, 0, sample_client_loop_cb, &client_ctx,addr_from);

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
static int
lcore_hello2(__rte_unused void *arg)
{
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;

    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&addr_from)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = inet_addr("198.18.0.1");

    char filename[100] = "bible.pdf";
    char **files = (char **)malloc(1 * sizeof(char *));
    files[0] = (char *)malloc(sizeof(strlen(filename)) + 1);


    memcpy(files[0], filename, strlen(filename) + 1);
    picoquic_sample_client("root@TFE-Tyunyayev2", 55, "ClientFolder", 1, files,addr_from);
}
int main(int argc, char **argv)
{

    int ret;
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    /* call lcore_hello() on every worker lcore */
    // RTE_LCORE_FOREACH_WORKER(lcore_id)
    // {
    // 	rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
    // }

    /* call it on main lcore too */
    lcore_hello2(NULL);
    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
