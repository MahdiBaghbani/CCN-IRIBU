#ifndef CCN_IRIBU_CCN_IRIBU_FETCH_H
#define CCN_IRIBU_CCN_IRIBU_FETCH_H

#include "ccn-iribu-common.h"

void ccn_iribu_fetch(char *uri, char *udp, char *ux, float wait, char *output_file_name);

int ccn_iribu_fetch_content_for_chunk_num(struct ccn_iribu_prefix_s *prefix,
                                          uint32_t *chunk_num, uint8_t *buffer,
                                          size_t buffer_length, size_t *length,
                                          float wait, int sock, struct sockaddr sa);

int ccn_iribu_extract_data_and_chunk_info(uint8_t **data, size_t *data_length,
                                          struct ccn_iribu_prefix_s **prefix,
                                          int64_t *last_chunk_num,
                                          struct ccn_iribu_pkt_s **packet);

int ccn_iribu_prefix_remove_chunk_num_component(struct ccn_iribu_prefix_s *prefix);

#endif    // CCN_IRIBU_CCN_IRIBU_FETCH_H
