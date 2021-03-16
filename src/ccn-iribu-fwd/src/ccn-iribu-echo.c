/*
 * @f ccn-iribu-ext-echo.c
 * @b CCN lite extension: echo/ping service - send back run-time generated data
 *
 * Copyright (C) 2015, Christian Tschudin, University of Basel
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
 * 2015-01-12 created
 */

void null_func(void);

#ifdef USE_ECHO

void
ccn_iribu_echo_request(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *inface,
                  struct ccn_iribu_prefix_s *pfx, struct ccn_iribu_buf_s *buf)
{
    time_t t;
    char *s, *cp;
    struct ccn_iribu_buf_s *reply;
    unsigned char *ucp;
    int len, enc;
    struct ccn_iribu_prefix_s *pfx2 = NULL;
    char s[CCN_IRIBU_MAX_PREFIX_SIZE];
    (void) s;

    DEBUGMSG(DEBUG, "echo request for <%s>\n", ccn_iribu_prefix_to_str(pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE));

//    if (pfx->chunknum) {
        // mkSimpleContent adds the chunk number, so remove it here
      /*
        ccn_iribu_free(pfx->chunknum);
        pfx->chunknum = NULL;
      */
#ifdef USE_SUITE_CCNTLV
    if (pfx->complen[pfx->compcnt-1] > 1 &&
        pfx->comp[pfx->compcnt-1][1] == CCNX_TLV_N_Chunk) {
        struct ccn_iribu_prefix_s *pfx2 = ccn_iribu_prefix_dup(pfx);
        pfx2->compcnt--;
        pfx2->chunknum = (int*) ccn_iribu_malloc(sizeof(unsigned int));
        *(pfx2->chunknum) = 0;
        pfx = pfx2;
    }
#endif

    t = time(NULL);
    ccn_iribu_prefix_to_str(pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE);

    cp = ccn_iribu_malloc(strlen(s) + 60);
    snprintf(cp, strlen(s) + 60, "%s\n%suptime %s\n", s, ctime(&t), timestamp());

    reply = ccn_iribu_mkSimpleContent(pfx, (unsigned char*) cp, strlen(cp), 0, NULL);
    ccn_iribu_free(cp);
    if (pfx2) {
        ccn_iribu_prefix_free(pfx2);
    }

    ucp = reply->data;
    len = reply->datalen;

    ccn_iribu_core_suites[(int)pfx->suite].RX(relay, NULL, &ucp, &len);
    ccn_iribu_free(reply);
}

// insert forwarding entry with a tap - the prefix arg is consumed
int
ccn_iribu_echo_add(struct ccn_iribu_relay_s *relay, struct ccn_iribu_prefix_s *pfx)
{
    return ccn_iribu_set_tap(relay, pfx, ccn_iribu_echo_request);
}

void
ccn_iribu_echo_cleanup(struct ccn_iribu_relay_s *relay)
{
    struct ccn_iribu_forward_s *fwd;

    DEBUGMSG(DEBUG, "removing all echo servers\n");

    for (fwd = relay->fib; fwd; fwd = fwd->next) {
        if (fwd->tap == ccn_iribu_echo_request) {
            fwd->tap = NULL;
/*
            if (fwd->face == NULL) { // remove this entry
                ccn_iribu_prefix_free(fwd->prefix);
                fwd->prefix = 0;
            }
*/
        }
    }
}

#endif // USE_ECHO

// eof
