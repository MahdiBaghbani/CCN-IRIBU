/*
 * @f ccn-iribu-buf.c
 * @b CCN lite (CCNL), core header file (internal data structures)
 *
 * Copyright (C) 2011-17, University of Basel
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
 * 2017-06-16 created
 */

#ifndef CCN_IRIBU_LINUXKERNEL
#include <stdio.h>
#include "ccn-iribu-os-time.h"
#include "ccn-iribu-buf.h"
#include "ccn-iribu-logging.h"
#include "ccn-iribu-relay.h"
#include "ccn-iribu-forward.h"
#include "ccn-iribu-prefix.h"
#include "ccn-iribu-malloc.h"
#else
#include "../include/ccn-iribu-os-time.h"
#include "../include/ccn-iribu-buf.h"
#include "../include/ccn-iribu-logging.h"
#include "../include/ccn-iribu-relay.h"
#include "../include/ccn-iribu-forward.h"
#include "../include/ccn-iribu-prefix.h"
#include "../include/ccn-iribu-malloc.h"
#endif

struct ccn_iribu_buf_s*
ccn_iribu_buf_new(void *data, size_t len)
{
    struct ccn_iribu_buf_s *b = (struct ccn_iribu_buf_s*) ccn_iribu_malloc(sizeof(*b) + len);

    if (!b) {
        return NULL;
    }
    b->next = NULL;
    b->datalen = len;
    if (data) {
        memcpy(b->data, data, len);
    }
    return b;
}

void
ccn_iribu_core_cleanup(struct ccn_iribu_relay_s *ccn_iribu)
{
    int k;

    DEBUGMSG_CORE(TRACE, "ccn_iribu_core_cleanup %p\n", (void *) ccn_iribu);

    while (ccn_iribu->pit)
        ccn_iribu_interest_remove(ccn_iribu, ccn_iribu->pit);
    while (ccn_iribu->faces)
        ccn_iribu_face_remove(ccn_iribu, ccn_iribu->faces); // removes allmost all FWD entries
    while (ccn_iribu->fib) {
        struct ccn_iribu_forward_s *fwd = ccn_iribu->fib->next;
        ccn_iribu_prefix_free(ccn_iribu->fib->prefix);
        ccn_iribu_free(ccn_iribu->fib);
        ccn_iribu->fib = fwd;
    }
    while (ccn_iribu->contents)
        ccn_iribu_content_remove(ccn_iribu, ccn_iribu->contents);
    while (ccn_iribu->nonces) {
        struct ccn_iribu_buf_s *tmp = ccn_iribu->nonces->next;
        ccn_iribu_free(ccn_iribu->nonces);
        ccn_iribu->nonces = tmp;
    }
    for (k = 0; k < ccn_iribu->ifcount; k++)
        ccn_iribu_interface_cleanup(ccn_iribu->ifs + k);
}
