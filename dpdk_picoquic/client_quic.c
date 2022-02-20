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
// #include <autoqlog.h>

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

struct rte_mempool *mb_pools[MAX_NB_OF_PORTS_AND_LCORES];
struct rte_eth_dev_tx_buffer *tx_buffers[MAX_NB_OF_PORTS_AND_LCORES];
struct rte_eth_rxconf rxq_conf;
struct rte_eth_txconf txq_conf;

// hardcoded server mac
struct rte_ether_addr eth_addr;
uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

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

    ret = picoquic_packet_loop_dpdk(quic, 0, server_address.ss_family, 0, 0, 0, sample_client_loop_cb, &client_ctx, 0,portid, addr_from, mac_dst, mb_pool, tx_buffer);

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

int init_port(uint16_t portid)
{
    int ret = 0;
    
    

    static struct rte_ether_addr eth_addr;
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
    ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                    rte_eth_dev_socket_id(portid),
                                    &txq_conf);
    if (ret != 0)
    {
        printf("failed to init queue\n");
        return 0;
    }

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

static int
lcore_hello(void *arg)
{
    unsigned *tab = (unsigned *) arg;
    unsigned portid = tab[0];
    unsigned index = tab[1];

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

    char filename[100] = "50MB.bin";
    char **files = (char **)malloc(1 * sizeof(char *));
    files[0] = (char *)malloc(sizeof(strlen(filename)) + 1);

    memcpy(files[0], filename, strlen(filename) + 1);
    picoquic_sample_client("root@TFE-Tyunyayev2", 55, "ClientFolder", 1, files,portid, addr_from, &eth_addr, mb_pools[index], tx_buffers[index]);
}

int main(int argc, char **argv)
{
    eth_addr.addr_bytes[0] = 0x50;
    eth_addr.addr_bytes[1] = 0x6b;
    eth_addr.addr_bytes[2] = 0x4b;
    eth_addr.addr_bytes[3] = 0xf3;
    eth_addr.addr_bytes[4] = 0x7c;
    eth_addr.addr_bytes[5] = 0x70;

    int ret;
    unsigned portid;
    unsigned lcore_id;
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    
    
    unsigned portids[MAX_NB_OF_PORTS_AND_LCORES];
    int index_port = 0;
    RTE_ETH_FOREACH_DEV(portid)
    {   
        portids[index_port] = portid;
        init_port(portid);
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
    unsigned args[2];
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        args[0] = index_lcore;
        args[1] = portids[index_lcore];
        rte_eal_remote_launch(lcore_hello, args, lcore_id);
        index_lcore++;
    }

    /* call it on main lcore too */
    args[0] = index_lcore;
    args[1] = portids[index_lcore];

    lcore_hello(args);

    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
