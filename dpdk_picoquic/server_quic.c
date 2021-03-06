/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
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
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <picoquic_packet_loop.h>
// #include <autoqlog.h>

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
        queueid, portid, addr_from,
        NULL, NULL,mb_pool, tx_buffer);
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
lcore_hello(__rte_unused void *arg)


{
    unsigned lcore_id;
    lcore_id = rte_lcore_id();


    struct sockaddr_storage addr_from;
    
    (*(struct sockaddr_in *)(&addr_from)).sin_family = AF_INET;
    (*(struct sockaddr_in *)(&addr_from)).sin_port = htons(55);
    (*(struct sockaddr_in *)(&addr_from)).sin_addr.s_addr = inet_addr("198.18.0.2");

	picoquic_sample_server(55, "certs/cert.pem", "certs/key.pem", "ServerFolder",0,0,addr_from,mb_pools[0],tx_buffers[0]);
   
}

int main(int argc, char **argv)
{
    int ret;
    unsigned lcore_id;
    lcore_id = rte_lcore_id();
    int portid = 0;
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    init_port_server(1);
    ret = rte_eth_dev_start(portid);

    static struct rte_ether_addr eth_addr;
    ret = rte_eth_macaddr_get(portid, &eth_addr);
    
    printf("%x\n", eth_addr.addr_bytes[0]);
    printf("%x\n", eth_addr.addr_bytes[1]);
    printf("%x\n", eth_addr.addr_bytes[2]);
    printf("%x\n", eth_addr.addr_bytes[3]);
    printf("%x\n", eth_addr.addr_bytes[4]);
    printf("%x\n", eth_addr.addr_bytes[5]);


    if (ret != 0)
    {
        printf("failed to start device\n");
    }
    ret = rte_eth_promiscuous_enable(portid);
    // if (ret != 0)
    //     rte_exit(EXIT_FAILURE,
    //              "rte_eth_promiscuous_enable:err=%s, port=%u\n",
    //              rte_strerror(-ret), portid);
    printf("after dpdk setup\n");
    

    /* call lcore_hello() on every worker lcore */

    /* call it on main lcore too */
    lcore_hello(NULL);

    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
