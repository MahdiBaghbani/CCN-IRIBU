/*
 * @f ccn-iribu-face.h
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

#ifndef CCN_IRIBU_FACE_H
#define CCN_IRIBU_FACE_H

#include "ccn-iribu-sockunion.h"

#ifdef CCN_IRIBU_RIOT
#include "evtimer_msg.h"
#endif

struct ccn_iribu_face_s {
    struct ccn_iribu_face_s *next, *prev;
    int faceid;
    int ifndx;
    sockunion peer;
    int flags;
    uint32_t last_used; // updated when we receive a packet
    struct ccn_iribu_buf_s *outq, *outqend; // queue of packets to send
    struct ccn_iribu_frag_s *frag;  // which special datagram armoring
    struct ccn_iribu_sched_s *sched;
#ifdef CCN_IRIBU_RIOT
    evtimer_msg_event_t evtmsg_timeout;
#endif
};

void
ccn_iribu_face_free(struct ccn_iribu_face_s *face);

#endif // CCN_IRIBU_FACE_H
