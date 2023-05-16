/**
 * @file  ccn-iribu-dump.h
 * @brief CCN lite extension
 *
 * Copyright (C) 2012-18, University of Basel
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
 */

#ifndef CCN_IRIBU_DUMP_H
#define CCN_IRIBU_DUMP_H

/**
 * @brief A macro which prints @p n whitespace characters
 */
#define INDENT(n)             \
    for (i = 0; i < (n); i++) \
    CONSOLE("  ")

/**
 * @brief Lists different packet types and data structures for @ref ccn_iribu_dump
 */
enum {
    CCN_IRIBU_BUF = 1,               /**< data type is a buffer */
    CCN_IRIBU_PREFIX,                /**< data type is a prefix */
    CCN_IRIBU_RELAY,                 /**< data type is a relay */
    CCN_IRIBU_FACE,                  /**< data type is a face */
    CCN_IRIBU_FRAG,                  /**< data type is a fragment */
    CCN_IRIBU_FWD,                   /**< data type is a fib entry */
    CCN_IRIBU_INTEREST,              /**< data type is an interest */
    CCN_IRIBU_PENDINT,               /**< data type is pending interest */
    CCN_IRIBU_PACKET,                /**< data type is packet */
    CCN_IRIBU_CONTENT,               /**< data type is content */
    CCN_IRIBU_DO_NOT_USE = UINT8_MAX /**< for internal use only, sets the width of the
                                        enum to sizeof(uint8_t) */
};

char *frag_protocol(int e);
void ccn_iribu_dump(int lev, int typ, void *p);
int get_buf_dump(int lev, void *p, long *outbuf, int *len, long *next);
int get_prefix_dump(int lev, void *p, int *len, char **val);
int get_num_faces(void *p);
int get_faces_dump(int lev, void *p, int *faceid, long *next, long *prev, int *ifndx,
                   int *flags, char **peer, int *type, char **frag);
int get_num_fwds(void *p);
int get_fwd_dump(int lev, void *p, long *outfwd, long *next, long *face, int *faceid,
                 int *suite, int *prefixlen, char **prefix);
int get_num_interface(void *p);
int get_interface_dump(int lev, void *p, int *ifndx, char **addr, long *dev, int *devtype,
                       int *reflect);
int get_num_interests(void *p);
int get_interest_dump(int lev, void *p, long *interest, long *next, long *prev, int *last,
                      int *min, int *max, int *retries, long *publisher, int *prefixlen,
                      char **prefix);

/**
 * @brief Writes PIT entries to @p out (an array of arrays).
 *
 * @param[in] lev The number of spaces to indent the log output (defunct)
 * @param[in] p A pointer to the global @ref struct ccn_iribu_relay_s
 * @param[out] out A array of arrays where the PIT is written to
 *
 * @return The number of entries written for the PIT
 */
int get_pendint_dump(int lev, void *p, char **out);

int get_num_contents(void *p);
int get_content_dump(int lev, void *p, long *content, long *next, long *prev,
                     int *last_use, int *served_cnt, int *prefixlen, char **prefix);

#endif    // CCN_IRIBU_DUMP_H
