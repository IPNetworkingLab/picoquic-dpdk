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

#ifndef PICOQUIC_CONFIG_H
#define PICOQUIC_CONFIG_H

#include <stdio.h>
#include <inttypes.h>
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    picoquic_option_CERT,
    picoquic_option_KEY,
    picoquic_option_ESNI_KEY,
    picoquic_option_SERVER_PORT,
    picoquic_option_PROPOSED_VERSION,
    picoquic_option_OUTDIR,
    picoquic_option_WWWDIR,
    picoquic_option_DO_RETRY,
    picoquic_option_INITIAL_RANDOM,
    picoquic_option_RESET_SEED,
    picoquic_option_SOLUTION_DIR,
    picoquic_option_CC_ALGO,
    picoquic_option_SPINBIT,
    picoquic_option_LOSSBIT,
    picoquic_option_MULTIPATH,
    picoquic_option_DEST_IF,
    picoquic_option_CIPHER_SUITE,
    picoquic_option_ESNI_RR_FILE,
    picoquic_option_INIT_CNXID,
    picoquic_option_LOG_FILE,
    picoquic_option_LONG_LOG,
    picoquic_option_BINLOG_DIR,
    picoquic_option_QLOG_DIR,
    picoquic_option_MTU_MAX,
    picoquic_option_SNI,
    picoquic_option_ALPN,
    picoquic_option_ROOT_TRUST_FILE,
    picoquic_option_FORCE_ZERO_SHARE,
    picoquic_option_CNXID_LENGTH,
    picoquic_option_NO_DISK,
    picoquic_option_LARGE_CLIENT_HELLO,
    picoquic_option_Ticket_File_Name,
    picoquic_option_Token_File_Name,
    picoquic_option_HELP
}  picoquic_option_enum_t;

typedef struct st_picoquic_quic_config_t {
    uint32_t nb_connections;
    char const* solution_dir;
    char const* server_cert_file;
    char const* server_key_file;
    char const* esni_key_file;
    char const* esni_rr_file;
    char const* log_file;
    char const* bin_dir;
    char const* qlog_dir;
    int server_port;
    int dest_if;
    int mtu_max;
    int cnx_id_length;
    char const* cc_algo_id;
    picoquic_connection_id_callback_ctx_t* cnx_id_cbdata;
    /* TODO: control key logging */
    picoquic_spinbit_version_enum spinbit_policy; /* control spin bit */
    picoquic_lossbit_version_enum lossbit_policy; /* control loss bit */
    int multipath_option;
    /* TODO: control other extensions, e.g. time stamp, ack delay */
    /* Common flags */
    unsigned int initial_random : 1;
    unsigned int use_long_log : 1;
    /* Server only */
    char const* www_dir;
    uint64_t reset_seed[2];
    const uint8_t* ticket_encryption_key; /* TODO: allocate key. Or maybe consider this a PEM file */
    size_t ticket_encryption_key_length;
    /* Server flags */
    unsigned int do_retry : 1;

    /* Client only */
    char const* ticket_file_name; /* TODO: allocate key */
    char const* token_file_name; /* TODO: allocate key */
    char const* sni;
    char const* alpn;
    char const* out_dir;
    char const* root_trust_file;
    int cipher_suite_id;
    uint32_t proposed_version;
    unsigned int force_zero_share : 1;
    unsigned int no_disk : 1;
    unsigned int large_client_hello : 1;
} picoquic_quic_config_t;

int picoquic_config_option_letters(char* option_string, size_t string_max, size_t* string_length);
void picoquic_config_usage();
int picoquic_config_set_option(picoquic_quic_config_t* config, picoquic_option_enum_t option_num, const char* opt_val);

int picoquic_config_command_line(int opt, int* p_optind, int argc, char const** argv, char const* optarg, picoquic_quic_config_t* config);

int picoquic_config_file(char const* file_name, picoquic_quic_config_t* config);

picoquic_quic_t* picoquic_create_and_configure(picoquic_quic_config_t* config,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    uint64_t current_time,
    uint64_t* p_simulated_time);

void picoquic_config_clear(picoquic_quic_config_t* config);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_CONFIG_H */