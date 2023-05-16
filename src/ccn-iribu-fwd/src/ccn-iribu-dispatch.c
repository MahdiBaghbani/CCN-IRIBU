/*
 * @f ccn-iribu-dispatch.c
 *
 * Copyright (C) 2011-18, University of Basel
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
 * 2017-06-20 created
 */
#ifndef CCN_IRIBU_LINUXKERNEL
#    include "ccn-iribu-dispatch.h"

#    include "ccn-iribu-os-time.h"

#    include "ccn-iribu-localrpc.h"

#    include "ccn-iribu-pkt-util.h"
#    include "ccn-iribu-relay.h"

#    include "ccn-iribu-fwd.h"

#    include "ccn-iribu-pkt-ccnb.h"
#    include "ccn-iribu-pkt-ccntlv.h"
#    include "ccn-iribu-pkt-localrpc.h"
#    include "ccn-iribu-pkt-ndntlv.h"
#    include "ccn-iribu-pkt-switch.h"

#    include "ccn-iribu-logging.h"
#else
#    include "../include/ccn-iribu-dispatch.h"

#    include "../../ccn-iribu-core/include/ccn-iribu-os-time.h"

#    include "../include/ccn-iribu-localrpc.h"

#    include "../../ccn-iribu-core/include/ccn-iribu-pkt-util.h"
#    include "../../ccn-iribu-core/include/ccn-iribu-relay.h"

#    include "../include/ccn-iribu-fwd.h"

#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ccnb.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ccntlv.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-localrpc.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ndntlv.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-switch.h"

#    include "../../ccn-iribu-core/include/ccn-iribu-logging.h"
#endif

struct ccn_iribu_suite_s ccn_iribu_core_suites[CCN_IRIBU_SUITE_LAST];

void ccn_iribu_core_RX(struct ccn_iribu_relay_s *relay, int ifndx, uint8_t *data,
                       size_t datalen, struct sockaddr *sa, size_t addrlen)
{
    uint8_t *base = data;
    struct ccn_iribu_face_s *from;
    int32_t enc;
    int suite = -1;
    size_t skip;
    dispatchFct dispatch;
    (void) enc;

    (void) base;    // silence compiler warning (if USE_DEBUG is not set)

    DEBUGMSG_CORE(DEBUG, "ccn_iribu_core_RX ifndx=%d, %zu bytes\n", ifndx, datalen);
    //    DEBUGMSG_ON(DEBUG, "ccn_iribu_core_RX ifndx=%d, %d bytes\n", ifndx, datalen);

#ifdef USE_STATS
    if (ifndx >= 0) {
        relay->ifs[ifndx].rx_cnt++;
    }
#endif

    from = ccn_iribu_get_face_or_create(relay, ifndx, sa, addrlen);
    if (!from) {
        DEBUGMSG_CORE(DEBUG, "  no face\n");
        return;
    } else {
        DEBUGMSG_CORE(DEBUG, "  face %d, peer=%s\n", from->faceid,
                      ccn_iribu_addr2ascii(&from->peer));
    }

    // loop through all packets in the received frame (UDP, Ethernet etc)
    while (datalen > 0) {
        // work through explicit code switching
        while (!ccn_iribu_switch_dehead(&data, &datalen, &enc))
            suite = ccn_iribu_enc2suite(enc);
        if (suite == -1)
            suite = ccn_iribu_pkt2suite(data, datalen, &skip);

        if (!ccn_iribu_isSuite(suite)) {
            DEBUGMSG_CORE(WARNING,
                          "?unknown packet format? ccn_iribu_core_RX ifndx=%d, %zu bytes "
                          "starting with 0x%02x at offset %zd\n",
                          ifndx, datalen, *data, (data - base));
            return;
        }

        dispatch = ccn_iribu_core_suites[suite].RX;
        if (!dispatch) {
            DEBUGMSG_CORE(ERROR,
                          "Forwarder not initialized or dispatcher "
                          "for suite %s does not exist.\n",
                          ccn_iribu_suite2str(suite));
            return;
        }
        if (dispatch(relay, from, &data, &datalen) < 0) {
            break;
        }
        if (datalen > 0) {
            DEBUGMSG_CORE(WARNING, "ccn_iribu_core_RX: %zu bytes left\n", datalen);
        }
    }
}

// ----------------------------------------------------------------------

void ccn_iribu_core_init(void)
{
#ifdef USE_SUITE_CCNB
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_CCNB].RX     = ccn_iribu_ccnb_forwarder;
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_CCNB].cMatch = ccn_iribu_ccnb_cMatch;
#endif
#ifdef USE_SUITE_CCNTLV
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_CCNTLV].RX     = ccn_iribu_ccntlv_forwarder;
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_CCNTLV].cMatch = ccn_iribu_ccntlv_cMatch;
#endif
#ifdef USE_SUITE_LOCALRPC
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_LOCALRPC].RX = ccn_iribu_localrpc_exec;
    //    ccn_iribu_core_suites[CCN_IRIBU_SUITE_LOCALRPC].cMatch =
    //    ccn_iribu_localrpc_cMatch;
#endif
#ifdef USE_SUITE_NDNTLV
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_NDNTLV].RX     = ccn_iribu_ndntlv_forwarder;
    ccn_iribu_core_suites[CCN_IRIBU_SUITE_NDNTLV].cMatch = ccn_iribu_ndntlv_cMatch;
#endif
}
