/*
 * @f ccn-iribu-callbacks.h
 * @b CCN lite, core CCNx protocol logic
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
 * 2018-05-21 created (based on ccn-iribu-producer.h)
 */
#ifndef CCN_IRIBU_CALLBACKS_H
#define CCN_IRIBU_CALLBACKS_H

#include "ccn-iribu-core.h"

/**
 * @brief Function pointer callback type for on-data events
 */
typedef int (*ccn_iribu_cb_on_data)(struct ccn_iribu_relay_s *relay,
                               struct ccn_iribu_face_s *face,
                               struct ccn_iribu_pkt_s *pkt);

/**
 * @brief Set an inbound on-data event callback function
 *
 * Setting an on-data callback function allows to intercept inbound Data
 * packets. The event is triggered before a Content Store lookup is performed.
 *
 * @param[in] func  The callback function for inbound on-data events
 */
void ccn_iribu_set_cb_rx_on_data(ccn_iribu_cb_on_data func);

/**
 * @brief Set an outbound on-data event callback function
 *
 * Setting an on-data callback function allows to intercept outbound Data
 * packets. The event is triggered after a Content Store lookup is performed.
 *
 * @param[in] func  The callback function for outbound on-data events
 */
void ccn_iribu_set_cb_tx_on_data(ccn_iribu_cb_on_data func);

/**
 * @brief Callback for inbound on-data events
 *
 * @param[in] relay The active ccn-lite relay
 * @param[in] from  The face the packet was received over
 * @param[in] pkt   The actual received packet 
 *
 * @note if the callback function returns any other value than 0,
 *       then the data packet is discarded.
 *
 * @return return value of the callback function
 * @return 0, if no function has been set
 */
int ccn_iribu_callback_rx_on_data(struct ccn_iribu_relay_s *relay,
                             struct ccn_iribu_face_s *from,
                             struct ccn_iribu_pkt_s *pkt);

/**
 * @brief Callback for outbound on-data events
 *
 * @param[in] relay The active ccn-lite relay
 * @param[in] from  The face the packet is sent over
 * @param[in] pkt   The actual packet to send
 *
 * @note if the callback function returns any other value than 0,
 *       then the data packet is not sent and discarded.
 *
 * @return return value of the callback function
 * @return 0, if no function has been set
 */
int ccn_iribu_callback_tx_on_data(struct ccn_iribu_relay_s *relay,
                             struct ccn_iribu_face_s *to,
                             struct ccn_iribu_pkt_s *pkt);

#endif  /* CCN_IRIBU_CALLBACKS_H */
