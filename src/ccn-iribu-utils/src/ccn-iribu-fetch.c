/*
 * @f util/ccn-iribu-fetch.c
 * @b request content: send an interest, wait for reply, output to stdout
 *
 * Copyright (C) 2013-14, Basil Kohler, University of Basel
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File history:
 * 2014-10-13  created
 */

#include "ccn-iribu-fetch.h"

int main(int argc, char *argv[])
{

    int opt;
    char *udp = NULL, *ux = NULL;
    char *output_file_name = NULL;
    float wait             = 3.0;

    while ((opt = getopt(argc, argv, "hu:v:o:w:x:")) != -1) {
        switch (opt) {
        case 'u':
            udp = optarg;
            break;
        case 'v':
#ifdef USE_LOGGING
            if (isdigit(optarg[0]))
                debug_level = (int) strtol(optarg, (char **) NULL, 10);
            else
                debug_level = ccn_iribu_debug_str2level(optarg);
#endif
            break;
        case 'o':
            output_file_name = optarg;
            break;
        case 'w':
            wait = (float) strtof(optarg, (char **) NULL);
            break;
        case 'x':
            ux = optarg;
            break;
        case 'h':
        default:
        usage:
            fprintf(
                stderr,
                "usage: %s [options] URI\n"
                "  -u a.b.c.d/port  UDP destination (default is 127.0.0.1/6363)\n"
#ifdef USE_LOGGING
                "  -v DEBUG_LEVEL (fatal, error, warning, info, debug, verbose, trace)\n"
#endif
                "  -w timeout       in sec (float)\n"
                "  -x ux_path_name  UNIX IPC: use this instead of UDP\n"
                "Examples:\n"
                "%% fetch -u 127.0.0.1/9998 /ndn/test/content\n",
                argv[0]);
            exit(0);
        }
    }

    if (!argv[optind]) {
        goto usage;
    }

    ccn_iribu_fetch(argv[optind], udp, ux, wait, output_file_name);

    return 0;
}

void ccn_iribu_fetch(char *uri, char *udp, char *ux, float wait, char *output_file_name)
{
    // TODO: suit is only here for compatibility, remove in future.
    int suite = CCN_IRIBU_SUITE_NDNTLV;

    int port, fetch_response, extract_response, output_file;
    const int max_retry = 3;
    int retry           = 0;
    int sock            = 0;
    char *addr          = NULL;
    unsigned char buffer[64 * 1024];
    struct sockaddr sa;
    struct ccn_iribu_prefix_s *prefix;
    struct ccn_iribu_pkt_s *packet = NULL;
    struct ccn_iribu_prefix_s *next_prefix;
    size_t len;
    uint32_t chunk_num;
    int64_t last_chunk_num;
    uint8_t *buffer_pointer;
    uint32_t *current_chunk_num;

    srandom(time(NULL));

    if (ccn_iribu_parseUdp(udp, suite, &addr, &port) != 0) {
        exit(-1);
    }

    DEBUGMSG(TRACE, "using udp address %s/%d\n", addr, port);

    if (ux) {    // use UNIX socket
        struct sockaddr_un *su = (struct sockaddr_un *) &sa;
        su->sun_family         = AF_UNIX;
        strncpy(su->sun_path, ux, sizeof(su->sun_path));
        sock = ux_open();
    } else {    // UDP
        struct sockaddr_in *si = (struct sockaddr_in *) &sa;
        si->sin_family         = PF_INET;
        si->sin_addr.s_addr    = inet_addr(addr);
        si->sin_port           = htons(port);
        sock                   = udp_open();
    }

    current_chunk_num = ccn_iribu_malloc(sizeof(uint32_t));
    if (!current_chunk_num) {
        DEBUGMSG(ERROR, "Failed to allocate memory: %d", errno);
        exit(1);
    }
    *current_chunk_num = 0;

    prefix = ccn_iribu_URItoPrefix(uri, suite, current_chunk_num);

    while (retry < max_retry) {

        if (!prefix->chunknum) {

            prefix->chunknum = ccn_iribu_malloc(sizeof(uint32_t));

            if (!prefix->chunknum) {
                DEBUGMSG(ERROR, "Failed to allocate memory: %d", errno);
                exit(1);
            }
        }
        *(prefix->chunknum) = *current_chunk_num;

        DEBUGMSG(INFO, "fetching chunk %d for prefix '%s'\n", *current_chunk_num,
                 ccn_iribu_prefix_to_path(prefix));

        // fetch chunk
        fetch_response = ccn_iribu_fetch_content_for_chunk_num(
            prefix, current_chunk_num, buffer, sizeof(buffer), &len, wait, sock, sa);

        if (fetch_response) {

            retry++;
            DEBUGMSG(WARNING, "timeout\n");

        } else {

            buffer_pointer = &buffer[0];
            next_prefix    = NULL;

            // parse response
            extract_response = ccn_iribu_extract_data_and_chunk_info(
                &buffer_pointer, &len, &next_prefix, &last_chunk_num, &packet);

            if (extract_response) {

                retry++;
                DEBUGMSG(WARNING, "Could not extract response or it was an interest\n");

            } else {

                prefix = next_prefix;

                chunk_num = *(prefix->chunknum);

                // Remove chunk component from name
                if (ccn_iribu_prefix_remove_chunk_num_component(prefix) < 0) {
                    retry++;
                    DEBUGMSG(WARNING, "Could not remove chunk number\n");
                }

                // check if the chunk is the first chunk or the next valid chunk
                // otherwise discard content and try again (except if it is the first
                // fetched chunk)
                if (chunk_num == 0 ||
                    (current_chunk_num && *current_chunk_num == chunk_num)) {
                    DEBUGMSG(
                        DEBUG,
                        "Found chunk %d with content length=%zu, last chunk number=%ld\n",
                        *current_chunk_num, packet->contlen, last_chunk_num);

                    // create output file or write to stdout
                    if (output_file_name != NULL) {

                        // for first chunk if file exists, truncate it (remove all
                        // the contents) and write new data, for other chunks just append
                        // to end of file
                        if (chunk_num == 0) {
                            output_file = open(output_file_name,
                                               O_WRONLY | O_CREAT | O_TRUNC, 0666);
                        } else {
                            output_file = open(output_file_name,
                                               O_WRONLY | O_CREAT | O_APPEND, 0666);
                        }

                        if (output_file == -1) {
                            DEBUGMSG(ERROR, "Cannot open file for writing!\n");
                            exit(-1);
                        }

                        write(output_file, packet->content, packet->contlen);
                        close(output_file);
                    } else {
                        write(1, packet->content, packet->contlen);
                    }

                    ccn_iribu_pkt_free(packet);

                    if (last_chunk_num != -1 && last_chunk_num == chunk_num) {
                        goto Done;
                    } else {
                        *current_chunk_num += 1;
                        retry = 0;
                    }
                } else {
                    // retry if the fetched chunk
                    retry++;
                    DEBUGMSG(WARNING,
                             "Could not find chunk %d, extracted chunk number is %d "
                             "(last chunk number=%ld)\n",
                             *current_chunk_num, chunk_num, last_chunk_num);
                }
            }
        }

        if (retry > 0) {
            DEBUGMSG(INFO, "Retry %d of %d\n", retry, max_retry);
        }
    }

    close(sock);
    DEBUGMSG(DEBUG, "Fetching failed!\n");
    exit(1);

Done:
    DEBUGMSG(DEBUG, "Successfully fetched content\n");
    close(sock);
}

int ccn_iribu_fetch_content_for_chunk_num(struct ccn_iribu_prefix_s *prefix,
                                          uint32_t *chunk_num, uint8_t *buffer,
                                          size_t buffer_length, size_t *length,
                                          float wait, int sock, struct sockaddr sa)
{
    (void) chunk_num;
    ccn_iribu_interest_opts_u int_opts;

    int nonce                   = random();
    int_opts.ndntlv.nonce       = nonce;
    struct ccn_iribu_buf_s *buf = ccn_iribu_mkSimpleInterest(prefix, &int_opts);

    if (buf->datalen <= 0) {
        fprintf(stderr, "Could not create interest message\n");
    }

    if (sendto(sock, buf->data, buf->datalen, 0, &sa, sizeof(sa)) < 0) {
        perror("sendto");
        myexit(1);
    }

    if (block_on_read(sock, wait) <= 0) {
        DEBUGMSG(WARNING, "timeout after block_on_read\n");
        return -1;
    }

    *length = recv(sock, buffer, buffer_length, 0);
    return 0;
}

int ccn_iribu_extract_data_and_chunk_info(uint8_t **data, size_t *data_length,
                                          struct ccn_iribu_prefix_s **prefix,
                                          int64_t *last_chunk_num,
                                          struct ccn_iribu_pkt_s **packet)
{
    uint64_t type;
    size_t length;
    uint8_t *start = *data;

    // set packet to null (just in case it is not null which is a bug!)
    *packet = NULL;

    if (ccn_iribu_ndntlv_dehead(data, data_length, &type, &length)) {
        DEBUGMSG(WARNING, "could not de-head\n");
        return -1;
    }

    if (type != NDN_TLV_Data) {
        DEBUGMSG(WARNING, "received non-content-object packet with type %lu\n", type);
        return -1;
    }

    *packet = ccn_iribu_ndntlv_bytes2pkt(type, start, data, data_length);

    if (!*packet) {
        DEBUGMSG(WARNING,
                 "ccn_iribu_extract_data_and_chunk_info: parsing error or no prefix\n");
        return -1;
    }

    *prefix         = ccn_iribu_prefix_dup((*packet)->pfx);
    *last_chunk_num = (*packet)->val.final_block_id;

    return 0;
}

int ccn_iribu_prefix_remove_chunk_num_component(struct ccn_iribu_prefix_s *prefix)
{

    if (prefix->comp[prefix->compcnt - 1][0] == NDN_Marker_SegmentNumber) {
        prefix->compcnt--;
    }

    return 0;
}
