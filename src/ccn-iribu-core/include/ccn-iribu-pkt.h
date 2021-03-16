/** 
 * @addtogroup CCNL-core
 * @{
 *
 * @file ccn-iribu-pkt.h
 * @brief CCN lite, core CCN PKT data structure
 *
 * @author Christopher Scherb <christopher.scherb@unibas.ch>
 * @author Balazs Faludi <balazs.faludi@unibas.ch>
 *
 * @copyright (C) 2011-18 University of Basel
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

#ifndef CCN_IRIBU_PKT_H
#define CCN_IRIBU_PKT_H

#include <stddef.h>
#ifndef CCN_IRIBU_LINUXKERNEL
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#include "ccn-iribu-buf.h"
#include "ccn-iribu-prefix.h"

#ifdef USE_SUITE_NDNTLV
#ifndef CCN_IRIBU_LINUXKERNEL
#include "ccn-iribu-pkt-ndntlv.h"
#else
#include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ndntlv.h"
#endif
#endif

// packet flags:  0000ebtt
#define CCN_IRIBU_PKT_REQUEST    0x01 // "Interest"
#define CCN_IRIBU_PKT_REPLY      0x02 // "Object", "Data"
#define CCN_IRIBU_PKT_FRAGMENT   0x03 // "Fragment"
#define CCN_IRIBU_PKT_FRAG_BEGIN 0x04 // see also CCN_IRIBU_DATA_FRAG_FLAG_FIRST etc
#define CCN_IRIBU_PKT_FRAG_END   0x08

/**
 * @brief Options for Interest messages of all TLV formats
 */
typedef union {
#ifdef USE_SUITE_NDNTLV
    struct ccn_iribu_ndntlv_interest_opts_s ndntlv;      /**< options for NDN Interest messages */
#endif
} ccn_iribu_interest_opts_u;

/**
 * @brief Options for Data messages of all TLV formats
 */
typedef union {
#ifdef USE_SUITE_NDNTLV
    struct ccn_iribu_ndntlv_data_opts_s ndntlv;      /**< options for NDN Data messages */
#endif
} ccn_iribu_data_opts_u;

struct ccn_iribu_pktdetail_ccnb_s {
    uint32_t minsuffix, maxsuffix;
    uint16_t aok;
    int scope;
    struct ccn_iribu_buf_s *nonce;
    struct ccn_iribu_buf_s *ppkd;        /**< publisher public key digest */
};

struct ccn_iribu_pktdetail_ccntlv_s {
    struct ccn_iribu_buf_s *keyid;       /**< publisher keyID */
};

/**
 * @brief Packet details for the NDN TLV format
 */
struct ccn_iribu_pktdetail_ndntlv_s {
    /* Interest */
    uint64_t minsuffix, maxsuffix, scope;
    uint8_t mbf;
    struct ccn_iribu_buf_s *nonce;      /**< nonce */
    struct ccn_iribu_buf_s *ppkl;       /**< publisher public key locator */
    uint64_t interestlifetime;     /**< interest lifetime */
    /* Data */
    uint64_t freshnessperiod;      /**< defines how long a node has to wait (after the arrival of this data before) marking it “non-fresh” */
};

struct ccn_iribu_pkt_s {
    struct ccn_iribu_buf_s *buf;        /**< the packet's bytes */
    struct ccn_iribu_prefix_s *pfx;     /**< prefix/name */
    uint8_t *content;              /**< pointer into the data buffer */
    size_t contlen;
    uint64_t type;                 /**< suite-specific value (outermost type) */
    union {
        int64_t final_block_id;
        uint64_t seqno;
    } val;
    union {
        struct ccn_iribu_pktdetail_ccnb_s   ccnb;
        struct ccn_iribu_pktdetail_ccntlv_s ccntlv;
        struct ccn_iribu_pktdetail_ndntlv_s ndntlv;
    } s;                           /**< suite specific packet details */
#ifdef USE_HMAC256
    uint8_t *hmacStart;
    size_t hmacLen;
    uint8_t *hmacSignature;
#endif
    unsigned int flags;
    char suite;
};

/**
 * @brief Free a pkt data structure
 *
 * @param[in] pkt       pkt datastructure to be freed
*/
void
ccn_iribu_pkt_free(struct ccn_iribu_pkt_s *pkt);

/**
 * @brief Duplicates a pkt data structure
 *
 * @param[in] pkt       pkt data structure to be duplicated
 *
 * @return  returns a copy of @p pkt, NULL if failed
*/
struct ccn_iribu_pkt_s *
ccn_iribu_pkt_dup(struct ccn_iribu_pkt_s *pkt);

/**
 * @brief Create a component for a pkt data structure (CCNTLV and CISTLV need special component start)
 *
 * @param[in] suite     suite for which the component should be created
 * @param[out] dst      target, where the created component should be stored
 * @param[in] src       content that should be written into the component
 * @param[in] srclen    length of the content @p s
 *
 * @return              length of the created component
*/
size_t
ccn_iribu_pkt_mkComponent(int suite, uint8_t *dst, char *src, size_t srclen);

/**
 * @brief prepend a component to buf
 *
 * @param[in] suite     suite for which the component should be created
 * @param[in] src       content that should be written into the component
 * @param[in] offset    offset for prepending the component
 * @param[out] buf      target, where the component was prepended
 *
 * @return              length of the entire component
*/
int
ccn_iribu_pkt_prependComponent(int suite, char *src, int *offset, unsigned char *buf);

#endif // EOF
/** @} */
