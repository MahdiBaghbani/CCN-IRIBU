/*
 * @f util/ccn-iribu-common.c
 * @b common functions for the CCN-lite utilities
 *
 * Copyright (C) 2013-15, Christian Tschudin, University of Basel
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
 * 2013-07-22 created
 * 2013-10-17 extended <christopher.scherb@unibas.ch>
 */


#ifndef CCN_IRIBU_UAPI_H_    // if CCN_IRIBU_UAPI_H_ is defined then the following config is taken care elsewhere in the code composite


#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _SVID_SOURCE

//#if defined(USE_FRAG) || defined(USE_MGMT) || defined(USE_SIGNATURES)
//# define NEEDS_PACKET_CRAFTING
//#endif

// ----------------------------------------------------------------------

//#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

//extern int getline(char **lineptr, size_t *n, FILE *stream);

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "base64.h"
//#include "base64.c"

#include "ccn-iribu-os-includes.h"
#include "ccn-iribu-defs.h"
#include "ccn-iribu-core.h"
#include "ccn-iribu-pkt-builder.h"
//#include "ccn-iribu-ext.h"
#include "ccn-iribu-malloc.h"
#include "ccn-iribu-os-time.h"
#include "ccn-iribu-logging.h"
#include "ccn-iribu-pkt-builder.h"

int debug_level = WARNING;
#ifndef USE_DEBUG_MALLOC
#define ccn_iribu_malloc(s)                  malloc(s)
#define ccn_iribu_calloc(n,s)                calloc(n,s)
#define ccn_iribu_realloc(p,s)               realloc(p,s)
#define ccn_iribu_free(p)                    free(p)
#endif //USE_DEBUG_MALLOC
#define free_2ptr_list(a,b)     ccn_iribu_free(a), ccn_iribu_free(b)

struct ccn_iribu_prefix_s* ccn_iribu_prefix_new(char suite, uint32_t cnt);
int ccn_iribu_pkt_prependComponent(int suite, char *src, int *offset, unsigned char *buf);

//#include "../ccn-iribu-pkt-switch.c"
#include "ccn-iribu-core.h"
#include "ccn-iribu-pkt-ccnb.h"
#include "ccn-iribu-pkt-ccntlv.h"
#include "ccn-iribu-pkt-localrpc.h"
#include "ccn-iribu-pkt-ndntlv.h"
#include "ccn-iribu-pkt-switch.h"

#include "ccn-iribu-socket.c"

// include only the utils, not the core routines:
#ifdef USE_FRAG
#include "../ccn-iribu-frag.h"
#endif

#else // CCN_IRIBU_UAPI_H_ is defined

#include "base64.c"
#ifdef RIOT_VERSION
#include "ccn-iribu-defs.h"
#include "net/packet.h"
#include <unistd.h>
#include "sys/socket.h"
#include "ccn-lite-riot.h"
#include "ccn-iribu-headers.h"
#include "ccn-iribu-pkt-ndntlv.h"
#include "ccn-iribu-pkt-ccntlv.h"
#include "ccn-iribu-pkt-ccnb.h"

int debug_level = WARNING;

extern int ccn_iribu_suite2defaultPort(int suite);
#endif

#endif // CCN_IRIBU_UAPI_H_


// ----------------------------------------------------------------------

const char*
ccn_iribu_enc2str(int enc)
{
    switch(enc) {
    case CCN_IRIBU_ENC_CCNB:      return CONSTSTR("ccnb");
    case CCN_IRIBU_ENC_NDN2013:   return CONSTSTR("ndn2013");
    case CCN_IRIBU_ENC_CCNX2014:  return CONSTSTR("ccnbx2014");
    case CCN_IRIBU_ENC_LOCALRPC:  return CONSTSTR("localrpc");
    default:
        break;
    }

    return CONSTSTR("?");
}

// ----------------------------------------------------------------------

#define extractStr(VAR,DTAG) \
    if (typ == CCN_TT_DTAG && num == DTAG) { \
        char *s; unsigned char *valptr; int vallen; \
        if (ccn_iribu_ccnb_consume(typ, num, &buf, &buflen, &valptr, &vallen) < 0) \
                goto Bail; \
        s = ccn_iribu_malloc(vallen+1); if (!s) goto Bail; \
        memcpy(s, valptr, vallen); s[vallen] = '\0'; \
        ccn_iribu_free(VAR); \
        VAR = (unsigned char*) s; \
        continue; \
    } do {} while(0)

#define extractStr2(VAR,DTAG) \
    if (typ == CCN_TT_DTAG && num == DTAG) { \
        char *s; unsigned char *valptr; int vallen; \
        if (ccn_iribu_ccnb_consume(typ, num, buf, buflen, &valptr, &vallen) < 0) \
                goto Bail; \
        s = ccn_iribu_malloc(vallen+1); if (!s) goto Bail; \
        memcpy(s, valptr, vallen); s[vallen] = '\0'; \
        ccn_iribu_free(VAR); \
    VAR = (unsigned char*) s; \
        continue; \
    } do {} while(0)

// ----------------------------------------------------------------------

struct key_s {
    struct key_s *next;
    unsigned char* key;
    int keylen;
};

struct key_s*
load_keys_from_file(char *path)
{
    FILE *fp = fopen(path, "r");
    char line[256];
    int cnt = 0;
    struct key_s *klist = NULL, *kend = NULL;

    if (!fp) {
        perror("file open");
        return NULL;
    }
    while (fgets(line, sizeof(line), fp)) {
        unsigned char *key;
        size_t keylen;
        int read = strlen(line);
        DEBUGMSG(TRACE, "  read %d bytes\n", read);
        if (line[read-1] == '\n')
            line[--read] = '\0';
        key = base64_decode(line, read, &keylen);
        if (key && keylen > 0) {
            struct key_s *k = (struct key_s *) calloc(1, sizeof(struct key_s));
            k->keylen = keylen;
            k->key = key;
            if (kend)
                kend->next = k;
            else
                klist = k;
            kend = k;
            cnt++;
            DEBUGMSG(VERBOSE, "  key #%d: %d bytes\n", cnt, (int)keylen);
            if (keylen < 32) {
                DEBUGMSG(WARNING, "key #%d: should choose a longer key!\n", cnt);
            }
        }
    }
    fclose(fp);
    DEBUGMSG(DEBUG, "read %d keys from file %s\n", cnt, optarg);
    return klist;
}

// ----------------------------------------------------------------------

int
ccn_iribu_parseUdp(char *udp, int suite, char **addr, int *port)
{
    char *tmpAddr = NULL;
    char *tmpPortStr = NULL;
    char *end = NULL;
    int tmpPort;

    if (!udp) {
        *addr = "127.0.0.1";
        *port = ccn_iribu_suite2defaultPort(suite);
        return 0;
    }

    if (!strchr(udp, '/')) {
        DEBUGMSG(ERROR, "invalid UDP destination, missing port: %s\n", udp);
        return -1;
    }
    tmpAddr = strtok(udp, "/");
    tmpPortStr = strtok(NULL, "/");
    if (!tmpPortStr) {
        DEBUGMSG(ERROR, "invalid UDP destination, empty UDP port: %s/\n", udp);
        return -1;
    }
    tmpPort = strtol(tmpPortStr, &end, 10);
    if (*end != '\0') {
        DEBUGMSG(ERROR, "invalid UDP destination, cannot parse port as number: %s\n", tmpPortStr);
        return -1;
    }

    *addr = tmpAddr;
    *port = tmpPort;
    return 0;
}

// eof
