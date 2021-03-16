/*
 * @f ccn-iribu-callbacks.c
 * @b Callback functions
 *
 * Copyright (C) 2018 HAW Hamburg
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
 * 2018-05-21 created (based on ccn-iribu-producer.c)
 */

#include "ccn-iribu-callbacks.h"

/**
 * callback function for inbound on-data events
 */
static ccn_iribu_cb_on_data _cb_rx_on_data = NULL;

/**
 * callback function for outbound on-data events
 */
static ccn_iribu_cb_on_data _cb_tx_on_data = NULL;

void
ccn_iribu_set_cb_rx_on_data(ccn_iribu_cb_on_data func)
{
    _cb_rx_on_data = func;
}

void
ccn_iribu_set_cb_tx_on_data(ccn_iribu_cb_on_data func)
{
    _cb_tx_on_data = func;
}

int
ccn_iribu_callback_rx_on_data(struct ccn_iribu_relay_s *relay,
                         struct ccn_iribu_face_s *from,
                         struct ccn_iribu_pkt_s *pkt)
{
    if (_cb_rx_on_data) {
        return _cb_rx_on_data(relay, from, pkt);
    }

    return 0;
}

int
ccn_iribu_callback_tx_on_data(struct ccn_iribu_relay_s *relay,
                         struct ccn_iribu_face_s *to,
                         struct ccn_iribu_pkt_s *pkt)
{
    if (_cb_tx_on_data) {
        return _cb_tx_on_data(relay, to, pkt);
    }

    return 0;
}
