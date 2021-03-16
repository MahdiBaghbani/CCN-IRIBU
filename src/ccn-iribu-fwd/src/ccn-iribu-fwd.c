/*
 * @f ccn-iribu-fwd.c
 * @b CCN lite (CCNL), fwd source file (internal data structures)
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
#include <inttypes.h>
#include <limits.h>
#include "ccn-iribu-fwd.h"
#include "ccn-iribu-core.h"
#include "ccn-iribu-producer.h"
#include "ccn-iribu-callbacks.h"
#include "ccn-iribu-pkt-util.h"
#include "ccn-iribu-pkt-ccnb.h"
#include "ccn-iribu-pkt-ccntlv.h"
#include "ccn-iribu-pkt-ndntlv.h"
#include "ccn-iribu-pkt-switch.h"
#else
#include <linux/types.h>
#include "../include/ccn-iribu-fwd.h"
#include "../../ccn-iribu-core/include/ccn-iribu-core.h"
#include "../../ccn-iribu-core/include/ccn-iribu-producer.h"
#include "../../ccn-iribu-core/include/ccn-iribu-callbacks.h"
#include "../../ccn-iribu-core/include/ccn-iribu-pkt-util.h"
#include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ccnb.h"
#include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ccntlv.h"
#include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ndntlv.h"
#include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-switch.h"
#endif

//#include "ccn-iribu-logging.h"


#ifdef NEEDS_PREFIX_MATCHING
struct ccn_iribu_prefix_s* ccn_iribu_prefix_dup(struct ccn_iribu_prefix_s *prefix);
int ccn_iribu_fib_add_entry(struct ccn_iribu_relay_s *relay, struct ccn_iribu_prefix_s *pfx,
                       struct ccn_iribu_face_s *face);
#endif

// returning 0 if packet was
int
ccn_iribu_fwd_handleContent(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
                       struct ccn_iribu_pkt_s **pkt)
{
    struct ccn_iribu_content_s *c;
    char s[CCN_IRIBU_MAX_PREFIX_SIZE];
    (void) s;

    if (from) {
        char *from_as_str = ccn_iribu_addr2ascii(&(from->peer));

        if (from_as_str) {
             DEBUGMSG_CFWD(INFO, "  incoming data=<%s>%s from=%s\n",
                ccn_iribu_prefix_to_str((*pkt)->pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE), ccn_iribu_suite2str((*pkt)->suite),
                  from_as_str ? from_as_str : "");
        }
    } else {
        DEBUGMSG_CFWD(INFO, "  incoming data=<%s>%s from=%s\n",
            ccn_iribu_prefix_to_str((*pkt)->pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE), ccn_iribu_suite2str((*pkt)->suite), "");

    }

#if defined(USE_SUITE_CCNB) && defined(USE_SIGNATURES)
//  FIXME: mgmt messages for NDN and other suites?
        if (pkt->pfx->compcnt == 2 && !memcmp(pkt->pfx->comp[0], "ccnx", 4)
                && !memcmp(pkt->pfx->comp[1], "crypto", 6) &&
                from == relay->crypto_face) {
            return ccn_iribu_crypto(relay, pkt->buf, pkt->pfx, from);
        }
#endif /* USE_SUITE_CCNB && USE_SIGNATURES*/
#ifndef CCN_IRIBU_LINUXKERNEL
    if (ccn_iribu_callback_rx_on_data(relay, from, *pkt)) {
        *pkt = NULL;
        return 0;
    }
#endif

    // CONFORM: Step 1:
    for (c = relay->contents; c; c = c->next) {
        if (ccn_iribu_prefix_cmp(c->pkt->pfx, NULL, (*pkt)->pfx, CMP_EXACT) == 0) {
            DEBUGMSG_CFWD(TRACE, "  content is duplicate, ignoring\n");
            return 0; // content is dup, do nothing
        }
    }

    c = ccn_iribu_content_new(pkt);
    if (!c) {
        return 0;
    }

    if (!ccn_iribu_content_serve_pending(relay, c)) { // unsolicited content
        // CONFORM: "A node MUST NOT forward unsolicited data [...]"
        DEBUGMSG_CFWD(DEBUG, "  removed because no matching interest\n");
        ccn_iribu_content_free(c);
        return 0;
    }

    if (relay->max_cache_entries != 0 && cache_strategy_cache(relay,c)) {
        DEBUGMSG_CFWD(DEBUG, "  adding content to cache\n");
        ccn_iribu_content_add2cache(relay, c);
        int contlen = (int) (c->pkt->contlen > INT_MAX ? INT_MAX : c->pkt->contlen);
        DEBUGMSG_CFWD(INFO, "data after creating packet %.*s\n", contlen, c->pkt->content);
    } else {
        DEBUGMSG_CFWD(DEBUG, "  content not added to cache\n");
        ccn_iribu_content_free(c);
    }

#ifdef USE_RONR
    /* if we receive a chunk, we assume more chunks of this content may be
     * retrieved along the same path */
    if (c->pkt->pfx->chunknum) {
        struct ccn_iribu_prefix_s *pfx_wo_chunk = ccn_iribu_prefix_dup(c->pkt->pfx);
        pfx_wo_chunk->compcnt--;
        ccn_iribu_free(pfx_wo_chunk->chunknum);
        pfx_wo_chunk->chunknum = NULL;
        ccn_iribu_fib_add_entry(relay, pfx_wo_chunk, from);
    }
#endif
    return 0;
}

#ifdef USE_FRAG
// returning 0 if packet was
int
ccn_iribu_fwd_handleFragment(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
                        struct ccn_iribu_pkt_s **pkt, dispatchFct callback)
{
    unsigned char *data = (*pkt)->content;
    int datalen = (*pkt)->contlen;

    if (from) {
        char *from_as_str = ccn_iribu_addr2ascii(&(from->peer));

        DEBUGMSG_CFWD(INFO, "  incoming fragment (%zd bytes) from=%s\n", 
            (*pkt)->buf->datalen, from_as_str ? from_as_str : "");
    }

    ccn_iribu_frag_RX_BeginEnd2015(callback, relay, from,
                              relay->ifs[from->ifndx].mtu,
                              ((*pkt)->flags >> 2) & 0x03,
                              (*pkt)->val.seqno, &data, &datalen);

    ccn_iribu_pkt_free(*pkt);
    *pkt = NULL;
    return 0;
}
#endif

// ----------------------------------------------------------------------
// returns 0 if packet should not be forwarded further
int
ccn_iribu_pkt_fwdOK(struct ccn_iribu_pkt_s *pkt)
{
    switch (pkt->suite) {
#ifdef USE_SUITE_NDNTLV
    case CCN_IRIBU_SUITE_NDNTLV:
        return pkt->s.ndntlv.scope > 2;
#endif
    default:
        break;
    }

    return -1;
}

int
ccn_iribu_fwd_handleInterest(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
                        struct ccn_iribu_pkt_s **pkt, cMatchFct cMatch)
{
    struct ccn_iribu_interest_s *i;
    struct ccn_iribu_content_s *c;
    int propagate= 0;
    char s[CCN_IRIBU_MAX_PREFIX_SIZE];
    (void) s;
    int32_t nonce = 0;
    if (pkt != NULL && (*pkt) != NULL && (*pkt)->s.ndntlv.nonce != NULL) {
        if ((*pkt)->s.ndntlv.nonce->datalen == 4) {
            memcpy(&nonce, (*pkt)->s.ndntlv.nonce->data, 4);
        }
    }

    if (from) {
        char *from_as_str = ccn_iribu_addr2ascii(&(from->peer));
#ifndef CCN_IRIBU_LINUXKERNEL
        DEBUGMSG_CFWD(INFO, "  incoming interest=<%s>%s nonce=%"PRIi32" from=%s\n",
             ccn_iribu_prefix_to_str((*pkt)->pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE),
             ccn_iribu_suite2str((*pkt)->suite), nonce,
             from_as_str ? from_as_str : "");
#else
        DEBUGMSG_CFWD(INFO, "  incoming interest=<%s>%s nonce=%d from=%s\n",
            ccn_iribu_prefix_to_str((*pkt)->pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE),
            ccn_iribu_suite2str((*pkt)->suite), nonce,
            from_as_str ? from_as_str : "");
#endif
    }

#ifdef USE_DUP_CHECK

    if (ccn_iribu_nonce_isDup(relay, *pkt)) {
    #ifndef CCN_IRIBU_LINUXKERNEL
        DEBUGMSG_CFWD(DEBUG, "  dropped because of duplicate nonce %"PRIi32"\n", nonce);
    #else
        DEBUGMSG_CFWD(DEBUG, "  dropped because of duplicate nonce %d\n", nonce);
    #endif
        return 0;
    }
#endif
#ifndef CCN_IRIBU_LINUXKERNEL
    if (local_producer(relay, from, *pkt)) {
        return 0;
    }
#endif
#if defined(USE_SUITE_CCNB) && defined(USE_MGMT)
    if ((*pkt)->suite == CCN_IRIBU_SUITE_CCNB && (*pkt)->pfx->compcnt == 4 &&
                                  !memcmp((*pkt)->pfx->comp[0], "ccnx", 4)) {
        DEBUGMSG_CFWD(INFO, "  found a mgmt message\n");
        ccn_iribu_mgmt(relay, (*pkt)->buf, (*pkt)->pfx, from); // use return value? // TODO uncomment
        return 0;
    }
#endif

#ifdef USE_SUITE_NDNTLV
    if ((*pkt)->suite == CCN_IRIBU_SUITE_NDNTLV && (*pkt)->pfx->compcnt == 4 &&
        !memcmp((*pkt)->pfx->comp[0], "ccnx", 4)) {
        DEBUGMSG_CFWD(INFO, "  found a mgmt message\n");
#ifdef USE_MGMT
        ccn_iribu_mgmt(relay, (*pkt)->buf, (*pkt)->pfx, from); // use return value?
#endif
        return 0;
    }
#endif

            // Step 1: search in content store
    DEBUGMSG_CFWD(DEBUG, "  searching in CS\n");

    for (c = relay->contents; c; c = c->next) {
        if (c->pkt->pfx->suite != (*pkt)->pfx->suite)
            continue;
        if (cMatch(*pkt, c))
            continue;

        DEBUGMSG_CFWD(DEBUG, "  found matching content %p\n", (void *) c);

        if (from) {
            if (from->ifndx >= 0) {
                ccn_iribu_send_pkt(relay, from, c->pkt);
            } else {
#ifdef CCN_IRIBU_APP_RX 
                ccn_iribu_app_RX(relay, c);
#endif 
            }
        }

        return 0; // we are done
    }

    // CONFORM: Step 2: check whether interest is already known
    for (i = relay->pit; i; i = i->next)
        if (ccn_iribu_interest_isSame(i, *pkt))
            break;

    if (!i) { // this is a new/unknown I request: create and propagate
        propagate = 1;
    }
    if (!ccn_iribu_pkt_fwdOK(*pkt))
        return -1;
    if (!i) {
        i = ccn_iribu_interest_new(relay, from, pkt);

        DEBUGMSG_CFWD(DEBUG,
                      "  created new interest entry %p (prefix=%s)\n",
                      (void *) i, ccn_iribu_prefix_to_str(i->pkt->pfx,s,CCN_IRIBU_MAX_PACKET_SIZE));
    }
    if (i) { // store the I request, for the incoming face (Step 3)
        DEBUGMSG_CFWD(DEBUG, "  appending interest entry %p\n", (void *) i);
        ccn_iribu_interest_append_pending(i, from);
        if(propagate) {
            ccn_iribu_interest_propagate(relay, i);
        }
    }
    return 0;
}

// ----------------------------------------------------------------------

#ifdef USE_SUITE_CCNB

// helper proc: work on a message, top level type is already stripped
int8_t
ccn_iribu_ccnb_fwd(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
              uint8_t **data, size_t *datalen, uint64_t typ)
{
    int8_t rc= -1;
    struct ccn_iribu_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccnb fwd (%zu bytes left)\n", *datalen);

    pkt = ccn_iribu_ccnb_bytes2pkt(*data - 2, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(WARNING, "  parsing error or no prefix\n");
        goto Done;
    }
    pkt->type = typ;
    pkt->flags |= typ == CCN_DTAG_INTEREST ? CCN_IRIBU_PKT_REQUEST : CCN_IRIBU_PKT_REPLY;

    if (pkt->flags & CCN_IRIBU_PKT_REQUEST) { // interest
        if (ccn_iribu_fwd_handleInterest(relay, from, &pkt, ccn_iribu_ccnb_cMatch)) {
            goto Done;
        }
    } else { // content
        if (ccn_iribu_fwd_handleContent(relay, from, &pkt)) {
            goto Done;
        }
    }
    rc = 0;
Done:
    ccn_iribu_pkt_free(pkt);
    return rc;
}

// loops over a frame until empty or error
int8_t
ccn_iribu_ccnb_forwarder(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
                    uint8_t **data, size_t *datalen)
{
    int8_t rc = 0;
    uint64_t num;
    uint8_t typ;
    DEBUGMSG_CFWD(DEBUG, "ccn_iribu_ccnb_forwarder: %zuB from face=%p (id=%d.%d)\n",
             *datalen, (void*)from, relay->id, from ? from->faceid : -1);

    while (rc >= 0 && *datalen > 0) {
        if (ccn_iribu_ccnb_dehead(data, datalen, &num, &typ) || typ != CCN_TT_DTAG) {
            return -1;
        }
        switch (num) {
        case CCN_DTAG_INTEREST:
        case CCN_DTAG_CONTENTOBJ:
            rc = ccn_iribu_ccnb_fwd(relay, from, data, datalen, num);
            continue;
#ifdef OBSOLETE_BY_2015_06
#ifdef USE_FRAG
        // FIXME: Propagate size_t through to frag functions
        case CCN_IRIBU_DTAG_FRAGMENT2012: {
            int dlen;
            if (datalen > INT_MAX) {
                return -1;
            }
            dlen = (int) *datalen;
            rc = ccn_iribu_frag_RX_frag2012(ccn_iribu_ccnb_forwarder, relay,
                                       from, data, &dlen);
            if (dlen < 0) {
                return -1;
            }
            *datalen = (size_t) dlen;
            continue;
        }
        case CCN_IRIBU_DTAG_FRAGMENT2013: {
            int dlen;
            if (datalen > INT_MAX) {
                return -1;
            }
            dlen = (int) *datalen;
            rc = ccn_iribu_frag_RX_CCNx2013(ccn_iribu_ccnb_forwarder, relay,
                                       from, data, &dlen);
            if (dlen < 0) {
                return -1;
            }
            *datalen = (size_t) dlen;
            continue;
        }
#endif
#endif // OBSOLETE
        default:
            DEBUGMSG_CFWD(DEBUG, "  unknown datagram type %llu\n", (unsigned long long) num);
            return -1;
        }
    }
    return rc;
}

#endif // USE_SUITE_CCNB

// ----------------------------------------------------------------------

#ifdef USE_SUITE_CCNTLV

// process one CCNTLV packet, return <0 if no bytes consumed or error
int8_t
ccn_iribu_ccntlv_forwarder(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
                      uint8_t **data, size_t *datalen)
{
    int8_t rc = -1;
    size_t payloadlen;
    size_t hdrlen;
    struct ccnx_tlvhdr_ccnx2015_s *hp;
    uint8_t *start = *data;
    struct ccn_iribu_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccn_iribu_ccntlv_forwarder: %zuB from face=%p (id=%d.%d)\n",
                  *datalen, (void*)from, relay->id, from ? from->faceid : -1);

    if (*datalen < sizeof(struct ccnx_tlvhdr_ccnx2015_s) || **data != CCNX_TLV_V1) {
        DEBUGMSG_CFWD(DEBUG, "  short header or wrong version (%d)\n", **data);
        return -1;
    }

    hp = (struct ccnx_tlvhdr_ccnx2015_s*) *data;
    hdrlen = hp->hdrlen; // ntohs(hp->hdrlen);
    if (hdrlen > *datalen) { // not enough bytes for a full header
        DEBUGMSG_CFWD(DEBUG, "  hdrlen too large (%zu > %zu)\n",
                      hdrlen, *datalen);
        return -1;
    }

    payloadlen = ntohs(hp->pktlen);
    if (payloadlen < hdrlen || payloadlen > *datalen) { // not enough data to reconstruct message
        DEBUGMSG_CFWD(DEBUG, "  pkt too small or too big (%zu < %zu < %zu)\n",
                 hdrlen, payloadlen, *datalen);
        return -1;
    }
    payloadlen -= hdrlen;

    *data += hdrlen;
    *datalen -= hdrlen;

    if (hp->pkttype == CCNX_PT_Interest ||
#ifdef USE_FRAG
        hp->pkttype == CCNX_PT_Fragment ||
#endif
        hp->pkttype == CCNX_PT_NACK) {
        hp->hoplimit--;
        if (hp->hoplimit <= 0) { // drop it
            DEBUGMSG_CFWD(DEBUG, "  pkt dropped because of hop limit\n");
            *data += payloadlen;
            *datalen -= payloadlen;
            return 0;
        }
    }

    DEBUGMSG_CFWD(DEBUG, "ccn_iribu_ccntlv_forwarder (%zu bytes left, hdrlen=%zu)\n",
                  *datalen, hdrlen);

#ifdef USE_FRAG
    if (hp->pkttype == CCNX_PT_Fragment) {
        uint16_t *sp = (uint16_t*) *data;
        int fraglen = ntohs(*(sp+1));

        if (ntohs(*sp) == CCNX_TLV_TL_Fragment && fraglen == (payloadlen-4)) {
            uint16_t fragfields; // = *(uint16_t *) &hp->fill;
            *data += 4;
            *datalen -= 4;
            payloadlen = fraglen;

            memcpy(&fragfields, hp->fill, 2);
            fragfields = ntohs(fragfields);

            ccn_iribu_frag_RX_BeginEnd2015(ccn_iribu_ccntlv_forwarder, relay, from,
                            relay->ifs[from->ifndx].mtu, fragfields >> 14,
                            fragfields & 0x3fff, data, datalen);

            DEBUGMSG_CFWD(TRACE, "  done (fraglen=%d, payloadlen=%d, *datalen=%d)\n",
                     fraglen, payloadlen, *datalen);
        } else {
            DEBUGMSG_CFWD(DEBUG, "  problem with frag type or length (%d, %d, %d)\n",
                     ntohs(*sp), fraglen, payloadlen);
            *data += payloadlen;
            *datalen -= payloadlen;
        }
        DEBUGMSG_CFWD(TRACE, "  returning after fragment: %d bytes\n", *datalen);
        return 0;
    } else {
        DEBUGMSG_CFWD(TRACE, "  not a fragment, continueing\n");
    }
#endif

    if (!from) {
        DEBUGMSG_CFWD(TRACE, "  local data, datalen=%zu\n", *datalen);
    }

    pkt = ccn_iribu_ccntlv_bytes2pkt(start, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(WARNING, "  parsing error or no prefix\n");
        goto Done;
    }
    if (!from) {
        DEBUGMSG_CFWD(TRACE, "  pkt ok\n");
//        goto Done;
    }


    if (hp->pkttype == CCNX_PT_Interest) {
        if (pkt->type == CCNX_TLV_TL_Interest) {
            pkt->flags |= CCN_IRIBU_PKT_REQUEST;
            // DEBUGMSG_CFWD(DEBUG, "  interest=<%s>\n", ccn_iribu_prefix_to_path(pkt->pfx));
            if (ccn_iribu_fwd_handleInterest(relay, from, &pkt, ccn_iribu_ccntlv_cMatch))
                goto Done;
        } else {
            DEBUGMSG_CFWD(WARNING, "  ccntlv: interest pkt type mismatch %d %lld\n",
                          hp->pkttype, (unsigned long long) pkt->type);
        }
    } else if (hp->pkttype == CCNX_PT_Data) {
        if (pkt->type == CCNX_TLV_TL_Object) {
            pkt->flags |= CCN_IRIBU_PKT_REPLY;
            ccn_iribu_fwd_handleContent(relay, from, &pkt);
        } else {
            DEBUGMSG_CFWD(WARNING, "  ccntlv: data pkt type mismatch %d %lld\n",
                     hp->pkttype, (unsigned long long) pkt->type);
        }
    } // else ignore
    rc = 0;
Done:
    ccn_iribu_pkt_free(pkt);

    DEBUGMSG_CFWD(TRACE, "  returning %zu bytes\n", *datalen);
    return rc;
}

#endif // USE_SUITE_CCNTLV

// ----------------------------------------------------------------------

#ifdef USE_SUITE_NDNTLV


int8_t
ccn_iribu_ndntlv_forwarder(struct ccn_iribu_relay_s *relay, struct ccn_iribu_face_s *from,
                      uint8_t **data, size_t *datalen)
{
    int8_t rc = -1;
    size_t len;
    uint64_t typ;
    unsigned char *start = *data;
    struct ccn_iribu_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccn_iribu_ndntlv_forwarder (%zu bytes left)\n", *datalen);

    if (ccn_iribu_ndntlv_dehead(data, datalen, &typ, &len) || len > *datalen) {
        DEBUGMSG_CFWD(TRACE, "  invalid packet format\n");
        return -1;
    }
    pkt = ccn_iribu_ndntlv_bytes2pkt(typ, start, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(INFO, "  ndntlv packet coding problem\n");
        goto Done;
    }
    pkt->type = typ;
    switch (typ) {
    case NDN_TLV_Interest:
        if (ccn_iribu_fwd_handleInterest(relay, from, &pkt, ccn_iribu_ndntlv_cMatch)) {
            goto Done;
        }
        break;
    case NDN_TLV_Data:
        if (ccn_iribu_fwd_handleContent(relay, from, &pkt)) {
            goto Done;
        }
        break;
#ifdef USE_FRAG
    case NDN_TLV_Fragment:
        if (ccn_iribu_fwd_handleFragment(relay, from, &pkt, ccn_iribu_ndntlv_forwarder)) {
            goto Done;
        }
        break;
#endif
    default:
        DEBUGMSG_CFWD(INFO, "  unknown packet type %llu, dropped\n", (unsigned long long) typ);
        break;
    }
    rc = 0;
Done:
    ccn_iribu_pkt_free(pkt);
    return rc;
}

#endif // USE_SUITE_NDNTLV

// ----------------------------------------------------------------------

// insert forwarding entry with a tap - the prefix arg is consumed
int
ccn_iribu_set_tap(struct ccn_iribu_relay_s *relay, struct ccn_iribu_prefix_s *pfx,
             tapCallback callback)
{
    struct ccn_iribu_forward_s *fwd, **fwd2;
    char s[CCN_IRIBU_MAX_PREFIX_SIZE];
    (void) s;

    DEBUGMSG_CFWD(INFO, "setting tap for <%s>, suite %s\n",
             ccn_iribu_prefix_to_str(pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE),
             ccn_iribu_suite2str(pfx->suite));

    for (fwd = relay->fib; fwd; fwd = fwd->next) {
        if (fwd->suite == pfx->suite &&
                        !ccn_iribu_prefix_cmp(fwd->prefix, NULL, pfx, CMP_EXACT)) {
            ccn_iribu_prefix_free(fwd->prefix);
            fwd->prefix = NULL;
            break;
        }
    }
    if (!fwd) {
        fwd = (struct ccn_iribu_forward_s *) ccn_iribu_calloc(1, sizeof(*fwd));
        if (!fwd)
            return -1;
        fwd2 = &relay->fib;
        while (*fwd2)
            fwd2 = &((*fwd2)->next);
        *fwd2 = fwd;
        fwd->suite = pfx->suite;
    }
    fwd->prefix = pfx;
    fwd->tap = callback;
    return 0;
}
