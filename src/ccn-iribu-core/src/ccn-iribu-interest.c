/*
 * @f ccn-iribu-interest.c
 * @b CCN lite (CCNL), core source file (internal data structures)
 *
 * Copyright (C) 2011-18 University of Basel
 * Copyright (C) 2018    Safety IO 
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
#include "ccn-iribu-interest.h"
#include "ccn-iribu-relay.h"
#include "ccn-iribu-malloc.h"
#include "ccn-iribu-os-time.h"
#include "ccn-iribu-prefix.h"
#include "ccn-iribu-logging.h"
#include "ccn-iribu-pkt-util.h"
#else
#include "../include/ccn-iribu-relay.h"
#include "../include/ccn-iribu-interest.h"
#include "../include/ccn-iribu-malloc.h"
#include "../include/ccn-iribu-os-time.h"
#include "../include/ccn-iribu-prefix.h"
#include "../include/ccn-iribu-logging.h"
#include "../include/ccn-iribu-pkt-util.h"
#endif

#ifdef CCN_IRIBU_RIOT
#include "ccn-iribu-riot.h"
#endif

struct ccn_iribu_interest_s*
ccn_iribu_interest_new(struct ccn_iribu_relay_s *ccn_iribu, struct ccn_iribu_face_s *from,
                  struct ccn_iribu_pkt_s **pkt)
{
    char s[CCN_IRIBU_MAX_PREFIX_SIZE];
    (void) s;

    struct ccn_iribu_interest_s *i = (struct ccn_iribu_interest_s *) ccn_iribu_calloc(1,
                                            sizeof(struct ccn_iribu_interest_s));
    DEBUGMSG_CORE(TRACE,
                  "ccn_iribu_new_interest(prefix=%s, suite=%s)\n",
                  ccn_iribu_prefix_to_str((*pkt)->pfx, s, CCN_IRIBU_MAX_PREFIX_SIZE),
                  ccn_iribu_suite2str((*pkt)->pfx->suite));

    if (!i)
        return NULL;
    i->pkt = *pkt;
    /* currently, the aging function relies on seconds rather than on milli seconds */
    i->lifetime = ccn_iribu_pkt_interest_lifetime(*pkt);

    *pkt = NULL;
    i->from = from;
    i->last_used = CCN_IRIBU_NOW();

    /** default value for max_pit_entries is defined in ccn-iribu-defs.h as CCN_IRIBU_DEFAULT_MAX_PIT_ENTRIES */
    /** it is set to -1 (means infinity) for anything other than arduino, riot or android */
    /** this code checks if max_pit_entries isn't defaulted to -1 and then compares its value against pitcnt value */
    if ((ccn_iribu->max_pit_entries != -1) && (ccn_iribu->pitcnt >= ccn_iribu->max_pit_entries)) {
        ccn_iribu_pkt_free(i->pkt);
        ccn_iribu_free(i);
        return NULL;
    }

    DBL_LINKED_LIST_ADD(ccn_iribu->pit, i);

    ccn_iribu->pitcnt++;

#ifdef CCN_IRIBU_RIOT
    ccn_iribu_evtimer_reset_interest_retrans(i);
    ccn_iribu_evtimer_reset_interest_timeout(i);
#endif

    return i;
}

int
ccn_iribu_interest_isSame(struct ccn_iribu_interest_s *i, struct ccn_iribu_pkt_s *pkt)
{
    if (i) {
        if (pkt) {
            if (i->pkt->pfx->suite != pkt->suite || ccn_iribu_prefix_cmp(i->pkt->pfx, NULL, pkt->pfx, CMP_EXACT)) { 
                return 0;
            }
            
            switch (i->pkt->pfx->suite) {
#ifdef USE_SUITE_CCNB
                case CCN_IRIBU_SUITE_CCNB: 
                    return i->pkt->s.ccnb.minsuffix == pkt->s.ccnb.minsuffix && i->pkt->s.ccnb.maxsuffix == pkt->s.ccnb.maxsuffix &&
                    ((!i->pkt->s.ccnb.ppkd && !pkt->s.ccnb.ppkd) || buf_equal(i->pkt->s.ccnb.ppkd, pkt->s.ccnb.ppkd));
#endif
                    
#ifdef USE_SUITE_NDNTLV
                case CCN_IRIBU_SUITE_NDNTLV: 
                    return i->pkt->s.ndntlv.minsuffix == pkt->s.ndntlv.minsuffix && i->pkt->s.ndntlv.maxsuffix == pkt->s.ndntlv.maxsuffix &&
                    ((!i->pkt->s.ndntlv.ppkl && !pkt->s.ndntlv.ppkl) || buf_equal(i->pkt->s.ndntlv.ppkl, pkt->s.ndntlv.ppkl));
#endif
#ifdef USE_SUITE_CCNTLV 
                case CCN_IRIBU_SUITE_CCNTLV: 
                    break;
#endif
                default:
                    break;
            }
            
            return 1;
        }

        return -2;
    }

    return -1;
}


int
ccn_iribu_interest_append_pending(struct ccn_iribu_interest_s *i,  struct ccn_iribu_face_s *from)
{
    if (i) {
        DEBUGMSG_CORE(TRACE, "ccn_iribu_append_pending\n");
        if (from) {
            struct ccn_iribu_pendint_s *pi, *last = NULL;
            char s[CCN_IRIBU_MAX_PREFIX_SIZE];

            for (pi = i->pending; pi; pi = pi->next) { // check whether already listed
                    if (pi->face == from) {
                            DEBUGMSG_CORE(DEBUG, "  we found a matching interest, updating time\n");
                            pi->last_used = CCN_IRIBU_NOW();
                            return 0;
                    }
                    last = pi;
            }
            pi = (struct ccn_iribu_pendint_s *) ccn_iribu_calloc(1,sizeof(struct ccn_iribu_pendint_s));
            if (!pi) {
                    DEBUGMSG_CORE(DEBUG, "  no mem\n");
                    return -1;
            }

            DEBUGMSG_CORE(DEBUG, "  appending a new pendint entry %p <%s>(%p)\n",
                            (void *) pi, ccn_iribu_prefix_to_str(i->pkt->pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE),
                            (void *) i->pkt->pfx);
            pi->face = from;
            pi->last_used = CCN_IRIBU_NOW();
            if (last)
                    last->next = pi;
            else
                    i->pending = pi;
            return 0;
        }

        return -2;
    }

    return -1;
}

int
ccn_iribu_interest_remove_pending(struct ccn_iribu_interest_s *interest, struct ccn_iribu_face_s *face)
{
    /** set result value to error-case */
    int result = -1;

    /** interest is valid? */
    if (interest) {
        /** face is valid? */
        if (face) {
            char s[CCN_IRIBU_MAX_PREFIX_SIZE];
            result = 0;

            struct ccn_iribu_pendint_s *prev = NULL;
            struct ccn_iribu_pendint_s *pend = interest->pending; 
            
            DEBUGMSG_CORE(TRACE, "ccn_iribu_interest_remove_pending\n"); 
            
            while (pend) {  // TODO: is this really the most elegant solution?
                if (face->faceid == pend->face->faceid) { 
                    DEBUGMSG_CFWD(INFO, "  removed face (%s) for interest %s\n",
                        ccn_iribu_addr2ascii(&pend->face->peer), 
                        ccn_iribu_prefix_to_str(interest->pkt->pfx,s,CCN_IRIBU_MAX_PREFIX_SIZE)); 
                    
                    result++; 
                    if (prev) { 
                        prev->next = pend->next;
                        ccn_iribu_free(pend);
                        pend = prev->next;
                    } else {
                        interest->pending = pend->next;
                        ccn_iribu_free(pend);
                        pend = interest->pending;
                    }
                } else {
                    prev = pend;
                    pend = pend->next; 
                }
            }
            return result;
        }

        /** face was NULL */
        result = -2;
    }

    /** interest was NULL */
    return result;
}
