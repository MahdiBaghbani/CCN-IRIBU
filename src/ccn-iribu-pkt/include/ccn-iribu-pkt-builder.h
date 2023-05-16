/*
 * @f ccn-iribu-pkt-bilder.h
 * @b CCN lite - CCN packet builder
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
 */

#ifndef CCN_IRIBU_PKT_BUILDER
#define CCN_IRIBU_PKT_BUILDER

#ifndef CCN_IRIBU_LINUXKERNEL
#    include "ccn-iribu-core.h"

#    include "ccn-iribu-pkt-ccnb.h"
#    include "ccn-iribu-pkt-ccntlv.h"
#    include "ccn-iribu-pkt-localrpc.h"
#    include "ccn-iribu-pkt-ndntlv.h"
#    include "ccn-iribu-pkt-switch.h"
#    include "ccn-iribu-pkt.h"
#else
#    include "../../ccn-iribu-core/include/ccn-iribu-core.h"

#    include "../../ccn-iribu-core/include/ccn-iribu-pkt.h"
#    include "../include/ccn-iribu-pkt-ccnb.h"
#    include "../include/ccn-iribu-pkt-ccntlv.h"
#    include "../include/ccn-iribu-pkt-localrpc.h"
#    include "../include/ccn-iribu-pkt-ndntlv.h"
#    include "../include/ccn-iribu-pkt-switch.h"
#endif

#ifdef USE_SUITE_CCNB
int8_t ccnb_isContent(uint8_t *buf, size_t len);
#endif    // USE_SUITE_CCNB

#ifdef USE_SUITE_CCNTLV

struct ccnx_tlvhdr_ccnx2015_s *ccntlv_isHeader(uint8_t *buf, size_t len);

int8_t ccntlv_isData(uint8_t *buf, size_t len);

int8_t ccntlv_isFragment(uint8_t *buf, size_t len);
#endif    // USE_SUITE_CCNTLV

#ifdef USE_SUITE_NDNTLV
int8_t ndntlv_isData(uint8_t *buf, size_t len);
#endif    // USE_SUITE_NDNTLV

int8_t ccn_iribu_isContent(uint8_t *buf, size_t len, int suite);

int8_t ccn_iribu_isFragment(uint8_t *buf, size_t len, int suite);

#ifdef NEEDS_PACKET_CRAFTING

struct ccn_iribu_content_s *ccn_iribu_mkContentObject(struct ccn_iribu_prefix_s *name,
                                                      uint8_t *payload, size_t paylen,
                                                      ccn_iribu_data_opts_u *opts);

struct ccn_iribu_buf_s *ccn_iribu_mkSimpleContent(struct ccn_iribu_prefix_s *name,
                                                  uint8_t *payload, size_t paylen,
                                                  size_t *payoffset,
                                                  ccn_iribu_data_opts_u *opts);

int8_t ccn_iribu_mkContent(struct ccn_iribu_prefix_s *name, uint8_t *payload,
                           size_t paylen, uint8_t *tmp, size_t *len, size_t *contentpos,
                           size_t *offs, ccn_iribu_data_opts_u *opts);

struct ccn_iribu_interest_s *ccn_iribu_mkInterestObject(struct ccn_iribu_prefix_s *name,
                                                        ccn_iribu_interest_opts_u *opts);

struct ccn_iribu_buf_s *ccn_iribu_mkSimpleInterest(struct ccn_iribu_prefix_s *name,
                                                   ccn_iribu_interest_opts_u *opts);

int8_t ccn_iribu_mkInterest(struct ccn_iribu_prefix_s *name,
                            ccn_iribu_interest_opts_u *opts, uint8_t *tmp,
                            uint8_t *tmpend, size_t *len, size_t *offs);

#endif

#endif    // CCN_IRIBU_PKT_BUILDER
