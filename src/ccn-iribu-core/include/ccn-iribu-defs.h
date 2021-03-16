/*
 * @f ccn-iribu-defs.h
 * @b header file with constants for CCN lite (CCNL)
 *
 * Copyright (C) 2011-14, Christian Tschudin, University of Basel
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
 * 2011-03-30 created
 */

#ifndef CCN_IRIBU_DEFS_H
#define CCN_IRIBU_DEFS_H

#define CCN_IRIBU_VERSION "2015-07-07"

#define ETHTYPE_XEROX_PUP               0x0a00
#define ETHTYPE_PARC_CCNX               0x0801

#define CCN_IRIBU_ETH_TYPE                   ETHTYPE_PARC_CCNX
//#define CCN_IRIBU_ETH_TYPE                 0x88b5

#define CCN_IRIBU_DEFAULT_UNIXSOCKNAME       "/tmp/.ccn_iribu.sock"

/* assuming that all broadcast addresses consist of a sequence of equal octets */
#define CCN_IRIBU_BROADCAST_OCTET            0xFF

#if defined(CCN_IRIBU_ARDUINO) || defined(CCN_IRIBU_RIOT)
# define CCN_IRIBU_MAX_INTERFACES             1
# define CCN_IRIBU_MAX_IF_QLEN                14
#ifndef CCN_IRIBU_MAX_PACKET_SIZE
# define CCN_IRIBU_MAX_PACKET_SIZE            120
#endif
#ifndef CCN_IRIBU_MAX_PREFIX_SIZE
# define CCN_IRIBU_MAX_PREFIX_SIZE            50
#endif
# define CCN_IRIBU_MAX_ADDRESS_LEN            8
# define CCN_IRIBU_MAX_NAME_COMP              8
#ifndef CCN_IRIBU_DEFAULT_MAX_PIT_ENTRIES
# define CCN_IRIBU_DEFAULT_MAX_PIT_ENTRIES    20
#endif
#elif defined(CCN_IRIBU_ANDROID) // max of BTLE and 2xUDP
# define CCN_IRIBU_MAX_INTERFACES             3
# define CCN_IRIBU_MAX_IF_QLEN                10
# define CCN_IRIBU_MAX_PACKET_SIZE            4096
# define CCN_IRIBU_MAX_ADDRESS_LEN            6
# define CCN_IRIBU_MAX_NAME_COMP              16
# define CCN_IRIBU_DEFAULT_MAX_PIT_ENTRIES    100
# define CCN_IRIBU_MAX_PREFIX_SIZE            2048
#else
# define CCN_IRIBU_MAX_INTERFACES             10
# define CCN_IRIBU_MAX_IF_QLEN                64
# define CCN_IRIBU_MAX_PACKET_SIZE            8096
# define CCN_IRIBU_MAX_ADDRESS_LEN            6
# define CCN_IRIBU_MAX_NAME_COMP              64
# define CCN_IRIBU_MAX_PREFIX_SIZE            2048
# define CCN_IRIBU_DEFAULT_MAX_PIT_ENTRIES    (-1)
#endif

#ifndef CCN_IRIBU_CONTENT_TIMEOUT
# define CCN_IRIBU_CONTENT_TIMEOUT            300 // sec
#endif
#ifndef CCN_IRIBU_INTEREST_TIMEOUT
# define CCN_IRIBU_INTEREST_TIMEOUT           10  // sec
#endif
#ifndef CCN_IRIBU_MAX_INTEREST_RETRANSMIT
# define CCN_IRIBU_MAX_INTEREST_RETRANSMIT    7
#endif

#ifndef CCN_IRIBU_FACE_TIMEOUT
// # define CCN_IRIBU_FACE_TIMEOUT    60 // sec
# define CCN_IRIBU_FACE_TIMEOUT       30 // sec
#endif

#define CCN_IRIBU_DEFAULT_MAX_CACHE_ENTRIES  0   // means: no content caching
#ifdef CCN_IRIBU_RIOT
#define CCN_IRIBU_MAX_NONCES                 -1 // -1 --> detect dups by PIT
#else //!CCN_IRIBU_RIOT
#define CCN_IRIBU_MAX_NONCES                 256 // for detected dups
#endif //CCN_IRIBU_RIOT

enum {
#ifdef USE_SUITE_CCNB
  CCN_IRIBU_SUITE_CCNB = 1,
#endif
#ifdef USE_SUITE_CCNTLV
  CCN_IRIBU_SUITE_CCNTLV = 2,
#endif
#ifdef USE_SUITE_LOCALRPC
  CCN_IRIBU_SUITE_LOCALRPC = 5,
#endif
#ifdef USE_SUITE_NDNTLV
  CCN_IRIBU_SUITE_NDNTLV = 6,
#endif
  CCN_IRIBU_SUITE_LAST = 7
};

#define CCN_IRIBU_SUITE_DEFAULT (CCN_IRIBU_SUITE_LAST - 1)

// ----------------------------------------------------------------------
// our own packet format extension for switching encodings:
// 0x80 followed by:
// (add new encodings at the end)

/**
 * @brief Provides an (internal) mapping to the supported packet types
 *
 * Note: Previous versions of CCN-lite supported Cisco's IOT packet format
 * which has since be removed. In previous versions, this enum had a 
 * member CCN_IRIBU_ENC_IOT2014 (with an implictly assigned value of 3).
 */
typedef enum ccn_iribu_enc_e {
  CCN_IRIBU_ENC_CCNB,     /**< encoding for CCN */
  CCN_IRIBU_ENC_NDN2013,  /**< NDN encoding (version 2013) */
  CCN_IRIBU_ENC_CCNX2014, /**< CCNx encoding (version 2014) */
  CCN_IRIBU_ENC_LOCALRPC  /**< encoding type for local rpc mechanism */
} ccn_iribu_enc;

// ----------------------------------------------------------------------
// our own CCN-lite extensions for the ccnb encoding:

// management protocol: (ccn-iribu-ext-mgmt.c)
#define CCN_IRIBU_DTAG_MACSRC        99001 // newface: which L2 interface
#define CCN_IRIBU_DTAG_IP4SRC        99002 // newface: which L3 interface
#define CCN_IRIBU_DTAG_IP6SRC        99003 // newface: which L3 interface
#define CCN_IRIBU_DTAG_UNIXSRC       99004 // newface: which UNIX path
#define CCN_IRIBU_DTAG_FRAG          99005 // fragmentation protocol, see core.h
#define CCN_IRIBU_DTAG_FACEFLAGS     99006 //
#define CCN_IRIBU_DTAG_DEVINSTANCE   99007 // adding/removing a device/interface
#define CCN_IRIBU_DTAG_DEVNAME       99008 // name of interface (eth0, wlan0)
#define CCN_IRIBU_DTAG_DEVFLAGS      99009 //
#define CCN_IRIBU_DTAG_MTU           99010 //
#define CCN_IRIBU_DTAG_WPANADR       99011 // newface: WPAN 
#define CCN_IRIBU_DTAG_WPANPANID     99012 // newface: WPAN 

#define CCN_IRIBU_DTAG_DEBUGREQUEST  99100 //
#define CCN_IRIBU_DTAG_DEBUGACTION   99101 // dump, halt, dump+halt

//FOR THE DEBUG_REPLY MSG
#define CCN_IRIBU_DTAG_DEBUGREPLY    99201 // dump reply
#define CCN_IRIBU_DTAG_INTERFACE     99202 // interface list
#define CCN_IRIBU_DTAG_NEXT          99203 // next pointer e.g. for faceinstance
#define CCN_IRIBU_DTAG_PREV          99204 // prev pointer e.g. for faceinstance
#define CCN_IRIBU_DTAG_IFNDX         99205
#define CCN_IRIBU_DTAG_IP            99206
#define CCN_IRIBU_DTAG_ETH           99207
#define CCN_IRIBU_DTAG_UNIX          99208
#define CCN_IRIBU_DTAG_PEER          99209
#define CCN_IRIBU_DTAG_FWD           99210
#define CCN_IRIBU_DTAG_FACE          99211
#define CCN_IRIBU_DTAG_ADDRESS       99212
#define CCN_IRIBU_DTAG_SOCK          99213
#define CCN_IRIBU_DTAG_REFLECT       99214
#define CCN_IRIBU_DTAG_PREFIX        99215
#define CCN_IRIBU_DTAG_INTERESTPTR   99216
#define CCN_IRIBU_DTAG_LAST          99217
#define CCN_IRIBU_DTAG_MIN           99218
#define CCN_IRIBU_DTAG_MAX           99219
#define CCN_IRIBU_DTAG_RETRIES       99220
#define CCN_IRIBU_DTAG_PUBLISHER     99221
#define CCN_IRIBU_DTAG_CONTENTPTR    99222
#define CCN_IRIBU_DTAG_LASTUSE       99223
#define CCN_IRIBU_DTAG_SERVEDCTN     99224
#define CCN_IRIBU_DTAG_VERIFIED      99225
#define CCN_IRIBU_DTAG_CALLBACK      99226
#define CCN_IRIBU_DTAG_SUITE         99300
#define CCN_IRIBU_DTAG_COMPLENGTH    99301
#define CCN_IRIBU_DTAG_CHUNKNUM      99302
#define CCN_IRIBU_DTAG_CHUNKFLAG     99303


// ----------------------------------------------------------------------
// fragmentation protocol: (ccn-iribu-ext-frag.c, FRAG_SEQUENCED2012)
#define CCN_IRIBU_DTAG_FRAGMENT2012  144144 // http://redmine.ccnx.org/issues/100803

#define CCN_IRIBU_DTAG_FRAG2012_TYPE         (CCN_IRIBU_DTAG_FRAGMENT2012+1)
#define CCN_IRIBU_DTAG_FRAG2012_FLAGS        (CCN_IRIBU_DTAG_FRAGMENT2012+2)
#define CCN_IRIBU_DTAG_FRAG2012_SEQNR        (CCN_IRIBU_DTAG_FRAGMENT2012+3)  // our seq number

#define CCN_IRIBU_DTAG_FRAG2012_OLOSS        (CCN_IRIBU_DTAG_FRAGMENT2012+5)  // our loss count
#define CCN_IRIBU_DTAG_FRAG2012_YSEQN        (CCN_IRIBU_DTAG_FRAGMENT2012+6)  // your (highest) seq no

// fragmentation protocol: (ccn-iribu-ext-frag.c, FRAG_CCNx2013)
#define CCN_IRIBU_DTAG_FRAGMENT2013          CCN_DTAG_FragP // requested 2013-07-24, assigned 2013-08-12

#define CCN_IRIBU_DTAG_FRAG2013_TYPE         CCN_DTAG_FragA
#define CCN_IRIBU_DTAG_FRAG2013_SEQNR        CCN_DTAG_FragB  // our seq number
#define CCN_IRIBU_DTAG_FRAG2013_FLAGS        CCN_DTAG_FragC

#define CCN_IRIBU_DTAG_FRAG2013_OLOSS        CCN_IRIBU_DTAG_FRAG2012_OLOSS  // our loss count
#define CCN_IRIBU_DTAG_FRAG2013_YSEQN        CCN_IRIBU_DTAG_FRAG2012_YSEQN  // your (highest) seq no


#define CCN_IRIBU_DTAG_FRAG_FLAG_MASK        0x03
#define CCN_IRIBU_DTAG_FRAG_FLAG_FIRST       0x01
#define CCN_IRIBU_DTAG_FRAG_FLAG_MID         0x00
#define CCN_IRIBU_DTAG_FRAG_FLAG_LAST        0x02
#define CCN_IRIBU_DTAG_FRAG_FLAG_SINGLE      0x03

// echo "FHBH" | base64 -d | hexdump -v -e '/1 "@x%02x"'| tr @ '\\'; echo
#define CCN_IRIBU_FRAG_TYPE_CCNx2013_VAL     "\x14\x70\x47"

// ----------------------------------------------------------------------
// face mgmt protocol:
#define CCN_IRIBU_DTAG_FRAG_FLAG_STATUSREQ   0x04

// ----------------------------------------------------------------------
// begin-end fragmentation protocol:
#define CCN_IRIBU_BEFRAG_FLAG_MASK        0x03
#define CCN_IRIBU_BEFRAG_FLAG_FIRST       0x01
#define CCN_IRIBU_BEFRAG_FLAG_MID         0x00
#define CCN_IRIBU_BEFRAG_FLAG_LAST        0x02
#define CCN_IRIBU_BEFRAG_FLAG_SINGLE      0x03

//#define USE_SIGNATURES


#define EXACT_MATCH 1
#define PREFIX_MATCH 0

#define CMP_EXACT   0 // used to compare interests among themselves
#define CMP_MATCH   1 // used to match interest and content
#define CMP_LONGEST 2 // used to lookup the FIB

#define CCN_IRIBU_FACE_FLAGS_STATIC  1
#define CCN_IRIBU_FACE_FLAGS_REFLECT 2
#define CCN_IRIBU_FACE_FLAGS_SERVED  4
#define CCN_IRIBU_FACE_FLAGS_FWDALLI 8 // forward all interests, also known ones

#define CCN_IRIBU_FRAG_NONE          0
#define CCN_IRIBU_FRAG_SEQUENCED2012 1
#define CCN_IRIBU_FRAG_CCNx2013      2
#define CCN_IRIBU_FRAG_SEQUENCED2015 3
#define CCN_IRIBU_FRAG_BEGINEND2015  4

#if defined(CCN_IRIBU_RIOT) || defined(USE_WPAN)
#define CCN_IRIBU_LLADDR_STR_MAX_LEN    (3 * 8)
#else
/* unless a platform supports a link layer with longer addresses than Ethernet,
 * 6 is enough */
#define CCN_IRIBU_LLADDR_STR_MAX_LEN    (3 * 6)
#endif
// ----------------------------------------------------------------------


#ifdef USE_CCNxDIGEST
#  define compute_ccnx_digest(buf) SHA256(buf->data, buf->datalen, NULL)
#else
#  define compute_ccnx_digest(b) NULL
#endif

#endif //CCN_IRIBU_DEFS_H

//define true / false
#define true 1
#define false 0


// eof
