#include "dpdk_picoquicdemo.h"

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";
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
            printf("error\n");
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
                        int dpdk,
                        int batching_size, 
                        unsigned portid,
                        unsigned queueid,
                        struct sockaddr_storage *addr_from,
                        struct rte_ether_addr *mac_dst,
                        struct rte_mempool *mb_pool,
                        struct rte_eth_dev_tx_buffer *tx_buffer,
                        int proxy_portid,
                        int proxy_queueid,
                        struct rte_mempool *mb_pool_proxy,
                        struct rte_ether_addr eth_client_proxy_addr)
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
        if(dpdk){
            ret = picoquic_packet_loop_dpdk(qserver, config->server_port, 0, config->dest_if,
            config->socket_buffer_size, config->do_not_use_gso, server_loop_cb, &loop_cb_ctx, portid,queueid, batching_size,*addr_from,NULL,mb_pool, tx_buffer);
        }
        else{
            printf("not good\n");
            ret = picoquic_packet_loop(qserver, config->server_port, 0, config->dest_if,
            config->socket_buffer_size, config->do_not_use_gso, server_loop_cb, &loop_cb_ctx);
        }
        
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