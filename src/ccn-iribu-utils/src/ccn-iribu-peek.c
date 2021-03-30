/*
 * @f util/ccn-iribu-peek.c
 * @b request content: send an interest, wait for reply, output to stdout
 *
 * Copyright (C) 2013-15, Christian Tschudin, University of Basel
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
 * 2013-04-06  created
 * 2014-06-18  added NDNTLV support
 */

#include "ccn-iribu-peek.h"

int main(int argc, char *argv[])
{
    int opt, output_file;
    char *udp = NULL, *ux = NULL;
    char *output_file_name    = NULL;
    float wait                = 3.0;
    unsigned int chunk_number = UINT_MAX;

    while ((opt = getopt(argc, argv, "hn:u:v:o:w:x:")) != -1) {
        switch (opt) {
        case 'n': {
            errno                     = 0;
            unsigned long chunknum_ul = strtoul(optarg, (char **) NULL, 10);
            if (errno || chunknum_ul > UINT_MAX) {
                goto usage;
            }
            chunk_number = (unsigned int) chunknum_ul;
            break;
        }
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
            wait = strtof(optarg, (char **) NULL);
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
                "  -n CHUNKNUM      positive integer for chunk interest\n"
                "  -u a.b.c.d/port  UDP destination\n"
#ifdef USE_LOGGING
                "  -v DEBUG_LEVEL (fatal, error, warning, info, debug, verbose, trace)\n"
#endif
                "  -o output file   specifies a filename to store received data\n"
                "  -w timeout       in sec (float)\n"
                "  -x ux_path_name  UNIX IPC: use this instead of UDP\n"
                "Examples:\n"
                "%% peek /ndn/edu/wustl/ping             (classic lookup)\n"
                "%% peek /rpc/site \"call 1 /test/data\"   (lambda RPC, directed)\n",
                argv[0]);
            exit(0);
        }
    }

    if (!argv[optind])
        goto usage;

    struct peek_output *output =
        ccn_iribu_peek(argv[optind], udp, ux, chunk_number, wait);

    // create output file or write to stdout.
    if (output_file_name != NULL) {
        output_file = open(output_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);

        if (output_file == -1) {
            DEBUGMSG(ERROR, "Cannot open file for writing!\n");
            exit(-1);
        }

        write(output_file, output->data, output->data_length);
        close(output_file);
    } else {
        write(1, output->data, output->data_length);
    }

    // free memory.
    free(output->data);
    free(output);

    return 0;
}

struct peek_output *ccn_iribu_peek(char *uri, char *udp, char *ux,
                                   unsigned int chunk_number, float wait)
{
    // TODO: suit is only here for compatibility, remove in future.
    int suite = CCN_IRIBU_SUITE_NDNTLV;

    int len, port, sock_size, rc;
    const int max_retry = 3;
    int retry           = 0;
    int sock            = 0;
    char *addr          = NULL;
    struct sockaddr sa;
    struct ccn_iribu_prefix_s *prefix;
    struct ccn_iribu_buf_s *buf = NULL;
    ccn_iribu_interest_opts_u int_opts;
    size_t output_max_size = sizeof(unsigned char) * 8 * CCN_IRIBU_MAX_PACKET_SIZE;

    struct peek_output *output =
        (struct peek_output *) malloc(sizeof(struct peek_output));

    if (output == NULL) {
        DEBUGMSG(ERROR, "Error: Failed to allocate memory\n");
        exit(1);
    }

    unsigned char *data = (unsigned char *) malloc(output_max_size);

    if (data == NULL) {
        DEBUGMSG(ERROR, "Error: Failed to allocate memory\n");
        exit(1);
    }

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

    // create prefix from uri
    prefix = ccn_iribu_URItoPrefix(uri, suite,
                                   chunk_number == UINT_MAX ? NULL : &chunk_number);

    DEBUGMSG(DEBUG, "prefix <%s> became %s\n", uri, ccn_iribu_prefix_to_path(prefix));

    while (retry < max_retry) {

        int32_t nonce         = (int32_t) random();
        int_opts.ndntlv.nonce = nonce;

        DEBUGMSG(TRACE, "sending request, iteration %d\n", retry);

        buf = ccn_iribu_mkSimpleInterest(prefix, &int_opts);

        if (!buf) {
            fprintf(stderr, "Failed to create interest.\n");
            myexit(1);
        }

        DEBUGMSG(DEBUG, "interest has %zd bytes\n", buf->datalen);

        if (ux) {
            sock_size = sizeof(struct sockaddr_un);
        } else {
            sock_size = sizeof(struct sockaddr_in);
        }

        // send interest
        rc = sendto(sock, buf->data, buf->datalen, 0, (struct sockaddr *) &sa, sock_size);

        if (rc < 0) {
            perror("sendto");
            myexit(1);
        }

        DEBUGMSG(DEBUG, "sendto returned %d\n", rc);

        // wait for a content pkt (ignore interests)
        for (;;) {
            unsigned char *cp = data;
            int32_t enc;
            int suite2;
            size_t len2;
            DEBUGMSG(TRACE, "  waiting for packet\n");

            if (block_on_read(sock, wait) <= 0) {
                // timeout
                break;
            }

            len = recv(sock, data, output_max_size, 0);
            DEBUGMSG(DEBUG, "received %d bytes\n", len);
            suite2 = -1;
            len2   = len;

            while (!ccn_iribu_switch_dehead(&cp, &len2, &enc)) {
                suite2 = ccn_iribu_enc2suite(enc);
            }

            if (suite2 != -1 && suite2 != suite) {
                DEBUGMSG(DEBUG, "  unknown suite %d\n", suite);
                continue;
            }

            // check for received data.
            rc = ccn_iribu_isContent(data, len, suite);

            if (rc < 0) {
                DEBUGMSG(ERROR, "error when checking type of packet\n");
                // write(1, data, len);
                goto done;
            }

            if (rc == 0) {    // it's an interest, ignore it
                DEBUGMSG(WARNING, "skipping non-data packet\n");
                continue;
            }

            // return output data.
            output->data        = data;
            output->data_length = len;
            return output;
        }
        retry++;
        DEBUGMSG(WARNING, "re-sending interest\n");
    }

    fprintf(stderr, "timeout\n");

done:
    close(sock);
    myexit(-1);
    return output;
}
