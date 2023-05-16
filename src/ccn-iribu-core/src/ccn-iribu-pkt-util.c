/*
 * @f ccn-iribu-pkt-util.c
 *
 * Copyright (C) 2011-15, University of Basel
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
#    include "ccn-iribu-pkt-util.h"
#    include "ccn-iribu-defs.h"
#    include "ccn-iribu-logging.h"
#    include "ccn-iribu-os-time.h"
#    include "ccn-iribu-pkt-ccnb.h"
#    include "ccn-iribu-pkt-ccntlv.h"
#    include "ccn-iribu-pkt-ndntlv.h"
#    include "ccn-iribu-pkt-switch.h"
#else
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ccnb.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ccntlv.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-ndntlv.h"
#    include "../../ccn-iribu-pkt/include/ccn-iribu-pkt-switch.h"
#    include "../include/ccn-iribu-defs.h"
#    include "../include/ccn-iribu-logging.h"
#    include "../include/ccn-iribu-os-time.h"
#    include "../include/ccn-iribu-pkt-util.h"
#endif

int ccn_iribu_str2suite(char *cp)
{
    if (!cp)
        return -1;
#ifdef USE_SUITE_CCNB
    if (!strcmp(cp, CONSTSTR("ccnb")))
        return CCN_IRIBU_SUITE_CCNB;
#endif
#ifdef USE_SUITE_CCNTLV
    if (!strcmp(cp, CONSTSTR("ccnx2015")))
        return CCN_IRIBU_SUITE_CCNTLV;
#endif
#ifdef USE_SUITE_LOCALRPC
    if (!strcmp(cp, CONSTSTR("localrpc")))
        return CCN_IRIBU_SUITE_LOCALRPC;
#endif
#ifdef USE_SUITE_NDNTLV
    if (!strcmp(cp, CONSTSTR("ndn2013")))
        return CCN_IRIBU_SUITE_NDNTLV;
#endif
    return -1;
}

const char *ccn_iribu_suite2str(int suite)
{
#ifdef USE_SUITE_CCNB
    if (suite == CCN_IRIBU_SUITE_CCNB)
        return CONSTSTR("ccnb");
#endif
#ifdef USE_SUITE_CCNTLV
    if (suite == CCN_IRIBU_SUITE_CCNTLV)
        return CONSTSTR("ccnx2015");
#endif
#ifdef USE_SUITE_LOCALRPC
    if (suite == CCN_IRIBU_SUITE_LOCALRPC)
        return CONSTSTR("localrpc");
#endif
#ifdef USE_SUITE_NDNTLV
    if (suite == CCN_IRIBU_SUITE_NDNTLV)
        return CONSTSTR("ndn2013");
#endif
    return CONSTSTR("?");
}

int ccn_iribu_suite2defaultPort(int suite)
{
#ifdef USE_SUITE_CCNB
    if (suite == CCN_IRIBU_SUITE_CCNB)
        return CCN_UDP_PORT;
#endif
#ifdef USE_SUITE_CCNTLV
    if (suite == CCN_IRIBU_SUITE_CCNTLV)
        return CCN_UDP_PORT;
#endif
#ifdef USE_SUITE_NDNTLV
    if (suite == CCN_IRIBU_SUITE_NDNTLV)
        return NDN_UDP_PORT;
#endif
    return NDN_UDP_PORT;
}

uint8_t ccn_iribu_isSuite(int suite)
{
#ifdef USE_SUITE_CCNB
    if (suite == CCN_IRIBU_SUITE_CCNB)
        return true;
#endif
#ifdef USE_SUITE_CCNTLV
    if (suite == CCN_IRIBU_SUITE_CCNTLV)
        return true;
#endif
#ifdef USE_SUITE_LOCALRPC
    if (suite == CCN_IRIBU_SUITE_LOCALRPC)
        return true;
#endif
#ifdef USE_SUITE_NDNTLV
    if (suite == CCN_IRIBU_SUITE_NDNTLV)
        return true;
#endif
    return false;
}

int ccn_iribu_pkt2suite(uint8_t *data, size_t len, size_t *skip)
{
    int suite = -1;
    int32_t enc;
    uint8_t *olddata = data;

    if (skip) {
        *skip = 0;
    }

    if (len <= 0) {
        return -1;
    }

    DEBUGMSG_CUTL(TRACE, "pkt2suite %d %d\n", data[0], data[1]);

    while (!ccn_iribu_switch_dehead(&data, &len, &enc)) {
        suite = ccn_iribu_enc2suite(enc);
    }
    if (skip) {
        *skip = data - olddata;
    }
    if (suite >= 0) {
        return suite;
    }

#ifdef USE_SUITE_CCNB
    if (*data == 0x04) {
        return CCN_IRIBU_SUITE_CCNB;
    }
    if (*data == 0x01 && len > 1 &&    // check for CCNx2015 and Cisco collision:
        (data[1] != 0x00 &&            // interest
         data[1] != 0x01 &&            // data
         data[1] != 0x02 &&            // interestReturn
         data[1] != 0x03)) {           // fragment
        return CCN_IRIBU_SUITE_CCNB;
    }
#endif

#ifdef USE_SUITE_CCNTLV
    if (data[0] == CCNX_TLV_V1 && len > 1) {
        if (data[1] == CCNX_PT_Interest || data[1] == CCNX_PT_Data ||
            data[1] == CCNX_PT_Fragment || data[1] == CCNX_PT_NACK) {
            return CCN_IRIBU_SUITE_CCNTLV;
        }
    }
#endif

#ifdef USE_SUITE_NDNTLV
    if (*data == NDN_TLV_Interest || *data == NDN_TLV_Data || *data == NDN_TLV_Fragment) {
        return CCN_IRIBU_SUITE_NDNTLV;
    }
#endif

    /*
    #ifdef USE_SUITE_LOCALRPC
            if (*data == LRPC_PT_REQUEST || *data == LRPC_PT_REPLY) {
                return CCN_IRIBU_SUITE_LOCALRPC;
            }
    #endif
        }
    */
    return -1;
}

int ccn_iribu_cmp2int(unsigned char *cmp, size_t cmplen)
{
    if (cmp) {
        long int i;
        char *str = (char *) ccn_iribu_malloc(cmplen + 1);

        DEBUGMSG(DEBUG, "  inter a: %zd\n", cmplen);
        DEBUGMSG(DEBUG, "  inter b\n");

        memcpy(str, (char *) cmp, cmplen);
        str[cmplen] = '\0';

        DEBUGMSG(DEBUG, "  inter c: %s\n", str);

        i = strtol(str, NULL, 0);

        DEBUGMSG(DEBUG, "  inter d\n");

        ccn_iribu_free(str);
        return (int) i;
    }

    return 0;
}

uint64_t ccn_iribu_pkt_interest_lifetime(const struct ccn_iribu_pkt_s *pkt)
{
    switch (pkt->suite) {
#ifdef USE_SUITE_CCNTLV
    case CCN_IRIBU_SUITE_CCNTLV:
        /* CCN-TLV parser does not support lifetime parsing, yet. */
        return CCN_IRIBU_INTEREST_TIMEOUT;
#endif
#ifdef USE_SUITE_NDNTLV
    case CCN_IRIBU_SUITE_NDNTLV:
        return (pkt->s.ndntlv.interestlifetime / 1000);
#endif
    default:
        break;
    }

    return CCN_IRIBU_INTEREST_TIMEOUT;
}
