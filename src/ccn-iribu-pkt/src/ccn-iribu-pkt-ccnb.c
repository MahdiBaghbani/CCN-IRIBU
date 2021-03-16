/*
 * @f pkt-ccnb.c
 * @b CCN lite - parse, create and manipulate CCNb formatted packets
 *
 * Copyright (C) 2011-15, Christian Tschudin, University of Basel
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
 * 2011-03-13 created (cft): orig name ccn-iribu-parse-ccnb.c
 * 2014-03-17 renamed to prepare for a world with many wire formats
 * 2014-03-20 extracted from ccn-iribu-core.c
 * 2014-11-05 merged from pkt-ccnb-dec.c and pkt-ccnb-enc.c
 */



#ifdef USE_SUITE_CCNB

#ifndef CCN_IRIBU_LINUXKERNEL
#include "ccn-iribu-pkt-ccnb.h"
#include "ccn-iribu-core.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <assert.h>
#else
#include "../include/ccn-iribu-pkt-ccnb.h"
#include "../../ccn-iribu-core/include/ccn-iribu-core.h"
#endif



// ----------------------------------------------------------------------
// ccnb parsing support



int8_t
ccn_iribu_ccnb_dehead(uint8_t **buf, size_t *len, uint64_t *num, uint8_t *typ)
{
    size_t i;
    uint64_t val = 0;

    if (*len > 0 && **buf == 0) { // end
        *num = *typ = 0;
        *buf += 1;
        *len -= 1;
        return 0;
    }
    for (i = 0; i < sizeof(i) && i < *len; i++) {
        uint8_t c = (*buf)[i];
        if ( c & 0x80 ) {
            *num = (val << 4) | ((c >> 3) & 0xf);
            *typ = (uint8_t) (c & 0x7);
            *buf += i+1;
            *len -= i+1;
            return 0;
        }
        val = (val << 7) | c;
    }
    return -1;
}

static int8_t
ccn_iribu_ccnb_hunt_for_end(uint8_t **buf, size_t *len,
                       uint8_t **valptr, size_t *vallen)
{
    uint8_t typ;
    uint64_t num;

    while (ccn_iribu_ccnb_dehead(buf, len, &num, &typ) == 0) {
        if (num == 0 && typ == 0) {
            return 0;
        }
        if (ccn_iribu_ccnb_consume(typ, num, buf, len, valptr, vallen)) {
            return -1;
        }
    }
    return -1;
}

int8_t
ccn_iribu_ccnb_consume(int8_t typ, uint64_t num, uint8_t **buf, size_t *len,
                  uint8_t **valptr, size_t *vallen)
{
    if (typ == CCN_TT_BLOB || typ == CCN_TT_UDATA) {
        if (valptr) {
            *valptr = *buf;
        }
        if (vallen) {
            if (num > SIZE_MAX) {
                return -1;
            }
            *vallen = num;
        }
        *buf += num, *len -= num;
        return 0;
    }
    if (typ == CCN_TT_DTAG || typ == CCN_TT_DATTR) {
        return ccn_iribu_ccnb_hunt_for_end(buf, len, valptr, vallen);
    }
//  case CCN_TT_TAG, CCN_TT_ATTR:
//  case DTAG, DATTR:
    return -1;
}

int8_t
ccn_iribu_ccnb_data2uint(uint8_t *cp, size_t len, uint64_t *retval)
{
    size_t i;
    uint64_t val;

    for (i = 0, val = 0; i < len; i++) {
        if (isdigit(cp[i])) {
            val = 10 * val + cp[i] - '0';
        } else {
            return -1;
        }
    }
    *retval = val;
    return 0;
}

struct ccn_iribu_pkt_s*
ccn_iribu_ccnb_bytes2pkt(uint8_t *start, uint8_t **data, size_t *datalen)
{
    struct ccn_iribu_pkt_s *pkt;
    uint8_t *cp;
    uint64_t num;
    uint8_t typ;
    size_t len, oldpos;
    struct ccn_iribu_prefix_s *p;

    DEBUGMSG(TRACE, "ccn_iribu_ccnb_extract\n");

    //pkt = (struct ccn_iribu_pkt_s *) ccn_iribu_calloc(1, sizeof(*pkt));
    pkt = (struct ccn_iribu_pkt_s *) ccn_iribu_calloc(1, sizeof(*pkt));
    if (!pkt) {
        return NULL;
    }
    pkt->suite = CCN_IRIBU_SUITE_CCNB;
    pkt->val.final_block_id = -1;
    pkt->s.ccnb.scope = 3;
    pkt->s.ccnb.aok = 3;
    pkt->s.ccnb.maxsuffix = CCN_IRIBU_MAX_NAME_COMP;

    pkt->pfx = p = ccn_iribu_prefix_new(CCN_IRIBU_SUITE_CCNB, CCN_IRIBU_MAX_NAME_COMP);
    if (!p) {
        ccn_iribu_free(pkt);
        return NULL;
    }
    p->compcnt = 0;

    oldpos = *data - start;
    while (!ccn_iribu_ccnb_dehead(data, datalen, &num, &typ)) {
        if (num == 0 && typ == 0) { // end
            break;
        }
        if (typ == CCN_TT_DTAG) {
            switch (num) {
            case CCN_DTAG_NAME:
                p->nameptr = start + oldpos;
                for (;;) {
                    if (ccn_iribu_ccnb_dehead(data, datalen, &num, &typ)) {
                        goto Bail;
                    }
                    if (num == 0 && typ == 0) {
                        break;
                    }
                    if (typ == CCN_TT_DTAG && num == CCN_DTAG_COMPONENT &&
                        p->compcnt < CCN_IRIBU_MAX_NAME_COMP) {
                        if (ccn_iribu_ccnb_hunt_for_end(data, datalen, p->comp + p->compcnt,
                                                   (p->complen + p->compcnt))) {
                            goto Bail;
                        }
                        p->compcnt++;
                    } else {
                        if (ccn_iribu_ccnb_consume(typ, num, data, datalen, 0, 0)) {
                            goto Bail;
                        }
                    }
                }
                p->namelen = *data - p->nameptr;
                break;
            case CCN_DTAG_CONTENT: {
                if (ccn_iribu_ccnb_consume(typ, num, data, datalen,
                                      &pkt->content, &pkt->contlen)) {
                    goto Bail;
                }
                oldpos = *data - start;
                continue;
            }
            case CCN_DTAG_SCOPE:
            case CCN_DTAG_ANSWERORIGKIND:
            case CCN_DTAG_MINSUFFCOMP:
            case CCN_DTAG_MAXSUFFCOMP:
            case CCN_DTAG_NONCE:
            case CCN_DTAG_PUBPUBKDIGEST:
                if (ccn_iribu_ccnb_hunt_for_end(data, datalen, &cp, &len)) {
                    goto Bail;
                }
                switch (num) {
                case CCN_DTAG_SCOPE:
                    if (len == 1) {
                        pkt->s.ccnb.scope = isdigit(*cp) && (*cp < '3') ?
                                            *cp - '0' : -1;
                    }
                    break;
                case CCN_DTAG_ANSWERORIGKIND: {
                    uint64_t aok;
                    if (ccn_iribu_ccnb_data2uint(cp, len, &aok)) {
                        goto Bail;
                    }
                    if (aok > UINT16_MAX) {
                        goto Bail;
                    }
                    pkt->s.ccnb.aok = (uint16_t) aok;
                    break;
                }
                case CCN_DTAG_MINSUFFCOMP: {
                    uint64_t minsuffix;
                    if (ccn_iribu_ccnb_data2uint(cp, len, &minsuffix)) {
                        goto Bail;
                    }
                    if (minsuffix > UINT32_MAX) {
                        goto Bail;
                    }
                    pkt->s.ccnb.minsuffix = (uint32_t) minsuffix;
                    break;
                }
                case CCN_DTAG_MAXSUFFCOMP: {
                    uint64_t maxsuffix;
                    if (ccn_iribu_ccnb_data2uint(cp, len, &maxsuffix)) {
                        goto Bail;
                    }
                    if (maxsuffix > UINT32_MAX) {
                        goto Bail;
                    }
                    pkt->s.ccnb.maxsuffix = (uint32_t) maxsuffix;
                    break;
                }
                case CCN_DTAG_NONCE:
                    if (!pkt->s.ccnb.nonce) {
                        pkt->s.ccnb.nonce = ccn_iribu_buf_new(cp, len);
                        if (!pkt->s.ccnb.nonce) {
                            goto Bail;
                        }
                    }
                    break;
                case CCN_DTAG_PUBPUBKDIGEST:
                    if (!pkt->s.ccnb.ppkd) {
                        pkt->s.ccnb.ppkd = ccn_iribu_buf_new(cp, len);
                        if (!pkt->s.ccnb.ppkd) {
                            goto Bail;
                        }
                    }
                    break;
                case CCN_DTAG_EXCLUDE:
                    DEBUGMSG(WARNING, "ccnb 'exclude' field ignored\n");
                    break;
                default:
                    DEBUGMSG(WARNING, "ccnb: unexpected DTAG: %llu\n", (unsigned long long)num);
                    break;
                }
                break;
            default:
                if (ccn_iribu_ccnb_hunt_for_end(data, datalen, &cp, &len)) {
                    goto Bail;
                }
            }
            oldpos = *data - start;
            continue;
        }
        if (ccn_iribu_ccnb_consume(typ, num, data, datalen, 0, 0)) {
            goto Bail;
        }
        oldpos = *data - start;
    }
    pkt->pfx = p;
    pkt->buf = ccn_iribu_buf_new(start, *data - start);
    // carefully rebase ptrs to new buf because of 64bit pointers:
    if (pkt->content) {
        pkt->content = pkt->buf->data + (pkt->content - start);
    }
    for (num = 0; num < p->compcnt; num++) {
        p->comp[num] = pkt->buf->data + (p->comp[num] - start);
    }
    if (p->nameptr) {
        p->nameptr = pkt->buf->data + (p->nameptr - start);
    }

    return pkt;
Bail:
    ccn_iribu_pkt_free(pkt);
    return NULL;
}

int8_t
ccn_iribu_ccnb_unmkBinaryInt(uint8_t **data, size_t *datalen,
                        unsigned int *result, uint8_t *width)
{
    uint8_t *cp = *data;
    size_t len = *datalen;
    uint8_t typ;
    uint64_t num;
    uint32_t val = 0;

    if (ccn_iribu_ccnb_dehead(&cp, &len, &num, &typ) || typ != CCN_TT_BLOB) {
        return -1;
    }
    if (width) {
        if (*width < num) {
            num = *width;
        } else {
            if (num > UINT8_MAX) {
                return -1;
            }
            *width = (uint8_t) num;
        }
    }

    // big endian (network order):
    while (num-- > 0 && len > 0) {
        val = (val << 8) | *cp++;
        len--;
    }
    *result = val;

    if (len < 1 || *cp != '\0') {// no end-of-entry
        return -1;
    }
    *data = cp+1;
    *datalen = len-1;
    return 0;
}

// ----------------------------------------------------------------------

#ifdef NEEDS_PREFIX_MATCHING

// returns: 0=match, -1=otherwise
int8_t
ccn_iribu_ccnb_cMatch(struct ccn_iribu_pkt_s *p, struct ccn_iribu_content_s *c)
{
#ifndef CCN_IRIBU_LINUXKERNEL
    assert(p);
    assert(p->suite == CCN_IRIBU_SUITE_CCNB);
#endif

    if (ccn_iribu_i_prefixof_c(p->pfx, p->s.ccnb.minsuffix, p->s.ccnb.maxsuffix, c) < 0) {
        return -1;
    }
    if (p->s.ccnb.ppkd && !buf_equal(p->s.ccnb.ppkd, c->pkt->s.ccnb.ppkd)) {
        return -1;
    }
    // FIXME: should check stale bit in aok here
    return 0;
}
#endif

// ----------------------------------------------------------------------
// ccnb encoding support

#ifdef NEEDS_PACKET_CRAFTING

int8_t
ccn_iribu_ccnb_mkHeader(uint8_t *buf, const uint8_t *bufend, uint64_t num, uint8_t tt, size_t *retlen)
{
    uint8_t tmp[100];
    size_t len = 0, i;

    *tmp = (uint8_t) (0x80 | ((num & 0x0f) << 3) | tt);
    len = 1;
    num = num >> 4;

    while (num > 0) {
        tmp[len++] = (uint8_t) (num & 0x7f);
        num = num >> 7;
    }
    if (buf + len >= bufend) {
        return -1;
    }
    for (i = len; i > 0; i--) {
        *buf++ = tmp[i-1];
    }
    *retlen += len;
    return 0;
}

int8_t
ccn_iribu_ccnb_addBlob(uint8_t *buf, const uint8_t *bufend, char *cp, size_t cnt, size_t *retlen)
{
    size_t len = 0;

    if (ccn_iribu_ccnb_mkHeader(buf, bufend, cnt, CCN_TT_BLOB, &len)) {
        return -1;
    }
    if (buf + len + cnt >= bufend) {
        return -1;
    }
    memcpy(buf+len, cp, cnt);
    len += cnt;

    *retlen += len;
    return 0;
}

int8_t
ccn_iribu_ccnb_mkField(uint8_t *out, const uint8_t *bufend, uint64_t num, uint8_t typ,
                  uint8_t *data, size_t datalen, size_t *retlen)
{
    size_t len = 0;

    if (ccn_iribu_ccnb_mkHeader(out, bufend, num, CCN_TT_DTAG, &len)) {
        return -1;
    }
    if (ccn_iribu_ccnb_mkHeader(out + len, bufend, datalen, typ, &len)) {
        return -1;
    }
    if (out + len + 1 >=bufend) {
        return -1;
    }
    memcpy(out + len, data, datalen);
    len += datalen;
    out[len++] = 0; // end-of-field

    *retlen += len;
    return 0;
}

int8_t
ccn_iribu_ccnb_mkBlob(uint8_t *out, const uint8_t *bufend, uint64_t num, uint8_t tt,
                 char *cp, size_t cnt, size_t *retlen)
{
    (void) tt;
    return ccn_iribu_ccnb_mkField(out, bufend, num, CCN_TT_BLOB,
                             (uint8_t*) cp, cnt, retlen);
}

int8_t
ccn_iribu_ccnb_mkStrBlob(uint8_t *out, const uint8_t *bufend, uint64_t num, uint8_t tt,
                    char *str, size_t *retlen)
{
    (void) tt;
    return ccn_iribu_ccnb_mkField(out, bufend, num, CCN_TT_BLOB,
                             (unsigned char*) str, strlen(str), retlen);
}

int8_t
ccn_iribu_ccnb_mkBinaryInt(uint8_t *out, const uint8_t *bufend, uint64_t num, uint8_t tt,
                      uint64_t val, uint64_t bytes, size_t *retlen)
{
    size_t len = 0;
    if (ccn_iribu_ccnb_mkHeader(out, bufend, num, tt, &len)) {
        return -1;
    }

    if (!bytes) {
        for (bytes = sizeof(val) - 1; bytes > 0; bytes--) {
            if (val >> (8 * bytes)) {
                break;
            }
        }
        bytes++;
    }
    if (ccn_iribu_ccnb_mkHeader(out+len, bufend, bytes, CCN_TT_BLOB, &len)) {
        return -1;
    }

    if (out + len + bytes + 1 >= bufend) {
        return -1;
    }

    while (bytes > 0) { // big endian
        bytes--;
        out[len++] = (uint8_t) (0xff & (val >> (8 * bytes)));
    }

    out[len++] = 0; // end-of-entry
    *retlen += len;
    return 0;
}

int8_t
ccn_iribu_ccnb_mkComponent(uint8_t *val, size_t vallen, uint8_t *out, const uint8_t *bufend, size_t *retlen)
{
    size_t len = 0;

    if (ccn_iribu_ccnb_mkHeader(out, bufend, CCN_DTAG_COMPONENT, CCN_TT_DTAG, &len)) {  // comp
        return -1;
    }
    if (ccn_iribu_ccnb_mkHeader(out+len, bufend, vallen, CCN_TT_BLOB, &len)) {
        return -1;
    }

    if (out + len + vallen + 1 >= bufend) {
        return -1;
    }

    memcpy(out+len, val, vallen);
    len += vallen;
    out[len++] = 0; // end-of-component

    *retlen += len;
    return 0;
}

int8_t
ccn_iribu_ccnb_mkName(struct ccn_iribu_prefix_s *name, uint8_t *out, const uint8_t *bufend, size_t *retlen)
{
    size_t len = 0, i;

    if (ccn_iribu_ccnb_mkHeader(out, bufend, CCN_DTAG_NAME, CCN_TT_DTAG, &len)) {  // name
        return -1;
    }
    for (i = 0; i < name->compcnt; i++) {
        if (ccn_iribu_ccnb_mkComponent(name->comp[i], name->complen[i], out+len, bufend, &len)) {
            return -1;
        }
    }

    if (out + len + 1 >= bufend) {
        return -1;
    }

    out[len++] = 0; // end-of-name

    *retlen += len;
    return 0;
}

// ----------------------------------------------------------------------

int8_t
ccn_iribu_ccnb_fillInterest(struct ccn_iribu_prefix_s *name, uint32_t *nonce,
                       uint8_t *out, const uint8_t *bufend, size_t outlen, size_t *retlen)
{
     size_t len = 0;
    (void) outlen;

    if (ccn_iribu_ccnb_mkHeader(out, bufend, CCN_DTAG_INTEREST, CCN_TT_DTAG, &len)) {  // interest
        return -1;
    }
    if (ccn_iribu_ccnb_mkName(name, out+len, bufend, &len)) {
        return -1;
    }
    if (nonce) {
        if (ccn_iribu_ccnb_mkHeader(out+len, bufend, CCN_DTAG_NONCE, CCN_TT_DTAG, &len)) {
            return -1;
        }
        if (ccn_iribu_ccnb_mkHeader(out+len, bufend, sizeof(uint32_t), CCN_TT_BLOB, &len)) {
            return -1;
        }

        if (out + len + sizeof(uint32_t) >= bufend) {
            return -1;
        }
        memcpy(out+len, (void*)nonce, sizeof(uint32_t));
        len += sizeof(uint32_t);
    }

    if (out + len + 1 >= bufend) {
        return -1;
    }
    out[len++] = 0; // end-of-interest

    *retlen += len;
    return 0;
}

int8_t
ccn_iribu_ccnb_fillContent(struct ccn_iribu_prefix_s *name, uint8_t *data, size_t datalen,
                      size_t *contentpos, uint8_t *out, const uint8_t *bufend, size_t *retlen)
{
    size_t len = 0;

    if (ccn_iribu_ccnb_mkHeader(out, bufend, CCN_DTAG_CONTENTOBJ, CCN_TT_DTAG, &len)) {
        return -1;
    }
    if (ccn_iribu_ccnb_mkName(name, out+len, bufend, &len)) {
        return -1;
    }
    if (ccn_iribu_ccnb_mkHeader(out+len, bufend, CCN_DTAG_CONTENT, CCN_TT_DTAG, &len)) {
        return -1;
    }
    if (ccn_iribu_ccnb_mkHeader(out+len, bufend, datalen, CCN_TT_BLOB, &len)) {
        return -1;
    }
    if (contentpos) {
        *contentpos = len;
    }
    if (out + len + 2 >= bufend) {
        return -1;
    }
    memcpy(out+len, data, datalen);
    if (contentpos) {
        *contentpos = len;
    }
    len += datalen;
    out[len++] = 0; // end-of-content

    out[len++] = 0; // end-of-content obj

    *retlen += len;
    return 0;
}

#endif // NEEDS_PACKET_CRAFTING

#endif // USE_SUITE_CCNB

/* suppress empty translation unit error */
typedef int unused_typedef;

// eof
