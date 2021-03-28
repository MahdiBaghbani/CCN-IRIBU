/*
 * @f ccn-iribu-interest.h
 * @b CCN lite (CCNL), core header file (internal data structures)
 *
 * Copyright (C) 2011-17  University of Basel
 * Copyright (C) 2018     HAW Hamburg
 * Copyright (C) 2018     Safety IO
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

#ifndef CCN_IRIBU_INTEREST_H
#define CCN_IRIBU_INTEREST_H

#include "ccn-iribu-face.h"
#include "ccn-iribu-pkt.h"

#ifdef CCN_IRIBU_RIOT
#    include "evtimer_msg.h"
#endif

/**
 * @brief A pending interest linked list element
 */
struct ccn_iribu_pendint_s {
    struct ccn_iribu_pendint_s *next; /**< pointer to the next list element */
    struct ccn_iribu_face_s *face;    /**< pointer to incoming face  */
    uint32_t last_used;               /** */
};

/**
 * @brief A interest linked list element
 */
struct ccn_iribu_interest_s {
    struct ccn_iribu_interest_s *next; /**< pointer to the next list element */
    struct ccn_iribu_interest_s *prev; /**< pointer to the previous list element */
    struct ccn_iribu_pkt_s *pkt;   /**< the packet the interests originates from (?) */
    struct ccn_iribu_face_s *from; /**< the face the interest was received from */
    struct ccn_iribu_pendint_s *pending; /**< linked list of faces wanting that content */
    uint32_t lifetime;                   /**< interest lifetime */
    uint32_t last_used;                  /**< last time the entry was used */
    int retries;                         /**< current number of executed retransmits. */
#ifdef CCN_IRIBU_RIOT
    evtimer_msg_event_t evtmsg_retrans; /**< retransmission timer */
    evtimer_msg_event_t evtmsg_timeout; /**< timeout timer for (?) */
#endif
};

/**
 * Creates a new interest of type \ref ccn_iribu_interest_s
 *
 * @param[in] ccn_iribu
 * @param[in] from
 * @param[in] pkt
 *
 * @return Upon success a new interest of type \ref ccn_iribu_interest_s, otherwise NULL
 */
struct ccn_iribu_interest_s *ccn_iribu_interest_new(struct ccn_iribu_relay_s *ccn_iribu,
                                                    struct ccn_iribu_face_s *from,
                                                    struct ccn_iribu_pkt_s **pkt);

/**
 * Checks if two interests are the same
 *
 * @param[in] i
 * @param[in] pkt
 *
 * @return 0
 * @return 1
 * @return -1 if \ref i was NULL
 * @return -2 if \ref pkt was NULL
 */
int ccn_iribu_interest_isSame(struct ccn_iribu_interest_s *i,
                              struct ccn_iribu_pkt_s *pkt);

/**
 * Adds a pending interest
 *
 * @param[in] i
 * @param[in] face
 *
 * @return 0
 * @return 1
 * @return -1 if \ref i was NULL
 * @return -2 if \ref face was NULL
 */
int ccn_iribu_interest_append_pending(struct ccn_iribu_interest_s *i,
                                      struct ccn_iribu_face_s *from);

/**
 * Removes a pending interest
 *
 * @param[in] i
 * @param[in] face
 *
 * @return 0
 * @return 1
 * @return -1 if \ref i was NULL
 * @return -2 if \ref face was NULL
 */
int ccn_iribu_interest_remove_pending(struct ccn_iribu_interest_s *i,
                                      struct ccn_iribu_face_s *face);

#endif    // CCN_IRIBU_INTEREST_H
