/**
 * @addtogroup CCNL-fwd
 * @{
 * @file ccn-iribu-localrpc.h
 * @brief CCN-lite - local RPC processing logic
 *
 * @author Christian Tschudin <christian.tschudin@unibas.ch>
 *
 * @copyright (C) 2014-2018, Christian Tschudin, University of Basel
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef CCN_IRIBU_LOCALRPC_H
#    define CCN_IRIBU_LOCALRPC_H

#    ifndef CCN_IRIBU_LINUXKERNEL
#        include "ccn-iribu-face.h"
#        include "ccn-iribu-relay.h"
#    else
#        include "../../ccn-iribu-core/include/ccn-iribu-face.h"
#        include "../../ccn-iribu-core/include/ccn-iribu-relay.h"
#    endif

/**
 * @brief       Processing of Local RPC messages
 *
 * @param[in] relay     pointer to current ccn iribu relay
 * @param[in] from      face on which the message was received
 * @param[in] buf       data which were received
 * @param[in] buflen   length of the received data
 *
 * @return      < 0 if no bytes consumed or error
 */
int8_t ccn_iribu_localrpc_exec(struct ccn_iribu_relay_s *relay,
                               struct ccn_iribu_face_s *from, uint8_t **buf,
                               size_t *buflen);

#endif

/** @} */
