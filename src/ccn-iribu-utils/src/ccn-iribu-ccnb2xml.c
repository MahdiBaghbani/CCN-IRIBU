/*
 * @f util/ccn-iribu-ccnb2xml.c
 * @b pretty print CCNB content to XML
 *
 * Copyright (C) 2013, Christopher Scherb, University of Basel
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
 * 2012-07-01  created
 */

#include "ccn-iribu-common.h"
#include "ccn-iribu-crypto.h"

// ----------------------------------------------------------------------

#define MAX_DEPTH 30

const char *dtag2str(uint64_t dtag)
{
    switch (dtag) {

    // Try DTAGs defined in ccn-iribu-pkt-ccnb.h
    case CCN_DTAG_ANY:
        return "ANY";
    case CCN_DTAG_NAME:
        return "NAME";
    case CCN_DTAG_COMPONENT:
        return "COMPONENT";
    case CCN_DTAG_CERTIFICATE:
        return "CERTIFICATE";
    case CCN_DTAG_CONTENT:
        return "CONTENT";
    case CCN_DTAG_SIGNEDINFO:
        return "SIGNEDINFO";
    case CCN_DTAG_CONTENTDIGEST:
        return "CONTENTDIGEST";
    case CCN_DTAG_INTEREST:
        return "INTEREST";
    case CCN_DTAG_KEY:
        return "KEY";
    case CCN_DTAG_KEYLOCATOR:
        return "KEYLOCATOR";
    case CCN_DTAG_KEYNAME:
        return "KEYNAME";
    case CCN_DTAG_SIGNATURE:
        return "SIGNATURE";
    case CCN_DTAG_TIMESTAMP:
        return "TIMESTAMP";
    case CCN_DTAG_TYPE:
        return "TYPE";
    case CCN_DTAG_NONCE:
        return "NONCE";
    case CCN_DTAG_SCOPE:
        return "SCOPE";
    case CCN_DTAG_EXCLUDE:
        return "EXCLUDE";
    case CCN_DTAG_ANSWERORIGKIND:
        return "ANSWERORIGKIND";
    case CCN_DTAG_WITNESS:
        return "WITNESS";
    case CCN_DTAG_SIGNATUREBITS:
        return "SIGNATUREBITS";
    case CCN_DTAG_DIGESTALGO:
        return "DIGESTALGO";
    case CCN_DTAG_FRESHNESS:
        return "FRESHNESS";
    case CCN_DTAG_FINALBLOCKID:
        return "FINALBLOCKID";
    case CCN_DTAG_PUBPUBKDIGEST:
        return "PUBPUBKDIGEST";
    case CCN_DTAG_PUBCERTDIGEST:
        return "PUBCERTDIGEST";
    case CCN_DTAG_CONTENTOBJ:
        return "CONTENTOBJ";
    case CCN_DTAG_ACTION:
        return "ACTION";
    case CCN_DTAG_FACEID:
        return "FACEID";
    case CCN_DTAG_IPPROTO:
        return "IPPROTO";
    case CCN_DTAG_HOST:
        return "HOST";
    case CCN_DTAG_PORT:
        return "PORT";
    case CCN_DTAG_FWDINGFLAGS:
        return "FWDINGFLAGS";
    case CCN_DTAG_FACEINSTANCE:
        return "FACEINSTANCE";
    case CCN_DTAG_FWDINGENTRY:
        return "FWDINGENTRY";
    case CCN_DTAG_MINSUFFCOMP:
        return "MINSUFFCOMP";
    case CCN_DTAG_MAXSUFFCOMP:
        return "MAXSUFFCOMP";
    case CCN_DTAG_SEQNO:
        return "SEQNO";
    case CCN_DTAG_FragA:
        return "FragA";
    case CCN_DTAG_FragB:
        return "FragB";
    case CCN_DTAG_FragC:
        return "FragC";
    case CCN_DTAG_FragD:
        return "FragD";
    case CCN_DTAG_FragP:
        return "FragP";
    case CCN_DTAG_CCNPDU:
        return "CCNPDU";

    // Try DTAGs defined in ccn-iribu-defs.h
    case CCN_IRIBU_DTAG_MACSRC:
        return "MACSRC";
    case CCN_IRIBU_DTAG_IP4SRC:
        return "IP4SRC";
    case CCN_IRIBU_DTAG_IP6SRC:
        return "IP6SRC";
    case CCN_IRIBU_DTAG_UNIXSRC:
        return "UNIXSRC";
    case CCN_IRIBU_DTAG_FRAG:
        return "FRAG";
    case CCN_IRIBU_DTAG_FACEFLAGS:
        return "FACEFLAGS";
    case CCN_IRIBU_DTAG_DEVINSTANCE:
        return "DEVINSTANCE";
    case CCN_IRIBU_DTAG_DEVNAME:
        return "DEVNAME";
    case CCN_IRIBU_DTAG_DEVFLAGS:
        return "DEVFLAGS";
    case CCN_IRIBU_DTAG_MTU:
        return "MTU";
    case CCN_IRIBU_DTAG_DEBUGREQUEST:
        return "DEBUGREQUEST";
    case CCN_IRIBU_DTAG_DEBUGACTION:
        return "DEBUGACTION";
    case CCN_IRIBU_DTAG_DEBUGREPLY:
        return "DEBUGREPLY";
    case CCN_IRIBU_DTAG_INTERFACE:
        return "INTERFACE";
    case CCN_IRIBU_DTAG_NEXT:
        return "NEXT";
    case CCN_IRIBU_DTAG_PREV:
        return "PREV";
    case CCN_IRIBU_DTAG_IFNDX:
        return "IFNDX";
    case CCN_IRIBU_DTAG_IP:
        return "IP";
    case CCN_IRIBU_DTAG_ETH:
        return "ETH";
    case CCN_IRIBU_DTAG_UNIX:
        return "UNIX";
    case CCN_IRIBU_DTAG_PEER:
        return "PEER";
    case CCN_IRIBU_DTAG_FWD:
        return "FWD";
    case CCN_IRIBU_DTAG_FACE:
        return "FACE";
    case CCN_IRIBU_DTAG_ADDRESS:
        return "ADDRESS";
    case CCN_IRIBU_DTAG_SOCK:
        return "SOCK";
    case CCN_IRIBU_DTAG_REFLECT:
        return "REFLECT";
    case CCN_IRIBU_DTAG_PREFIX:
        return "PREFIX";
    case CCN_IRIBU_DTAG_INTERESTPTR:
        return "INTERESTPTR";
    case CCN_IRIBU_DTAG_LAST:
        return "LAST";
    case CCN_IRIBU_DTAG_MIN:
        return "MIN";
    case CCN_IRIBU_DTAG_MAX:
        return "MAX";
    case CCN_IRIBU_DTAG_RETRIES:
        return "RETRIES";
    case CCN_IRIBU_DTAG_PUBLISHER:
        return "PUBLISHER";
    case CCN_IRIBU_DTAG_CONTENTPTR:
        return "CONTENTPTR";
    case CCN_IRIBU_DTAG_LASTUSE:
        return "LASTUSE";
    case CCN_IRIBU_DTAG_SERVEDCTN:
        return "SERVEDCTN";
    case CCN_IRIBU_DTAG_VERIFIED:
        return "VERIFIED";
    case CCN_IRIBU_DTAG_CALLBACK:
        return "CALLBACK";
    case CCN_IRIBU_DTAG_SUITE:
        return "SUITE";
    case CCN_IRIBU_DTAG_COMPLENGTH:
        return "COMPLENGTH";
    }

    // DEBUGMSG(WARNING, "DTAG '%d' is missing in %s of %s:%d\n", dtag, __func__,
    // __FILE__, __LINE__);
    return "?";
}

const char *tag2str(uint64_t tag, uint64_t num)
{
    switch (tag) {
    case CCN_TT_TAG:
        return "TAG";
    case CCN_TT_DTAG:
        return dtag2str(num);
    case CCN_TT_ATTR:
        return "ATTR";
    case CCN_TT_DATTR:
        return "DATTR";
    case CCN_TT_BLOB:
        return "BLOB";
    case CCN_TT_UDATA:
        return "UDATA";
    }

    // DEBUGMSG(WARNING, "CCN_TT tag '%d' is missing in %s of %s:%d\n", tag, __func__,
    // __FILE__, __LINE__);
    return "?";
}

int8_t is_ccn_tt(uint64_t tag, uint64_t num)
{
    return strcmp("?", tag2str(tag, num)) != 0;
}

int8_t is_ccn_blob(uint64_t tag)
{
    return tag == CCN_TT_BLOB || tag == CCN_TT_UDATA;
}

int8_t lookahead(uint8_t **buf, size_t *len, uint64_t *num, uint8_t *typ,
                 uint8_t ignoreBlobTag, int depth)
{
    int8_t rc, rc2;
    uint64_t look_num;
    uint8_t look_typ;
    uint8_t *old_buf = *buf;
    size_t old_len   = *len;

    if (depth > MAX_DEPTH) {
        return 0;
    }

    rc = ccn_iribu_ccnb_dehead(buf, len, num, typ);
    if (ignoreBlobTag && rc == 0 && is_ccn_blob(*typ)) {
        rc2 = ccn_iribu_ccnb_dehead(buf, len, &look_num, &look_typ);
        if (rc2 == 0 && is_ccn_tt(look_typ, look_num)) {
            *num = look_num;
            *typ = look_typ;
            rc   = rc2;
        }
    }

    *buf = old_buf;
    *len = old_len;
    return rc;
}

int8_t dehead(uint8_t **buf, size_t *len, uint64_t *num, uint8_t *typ,
              uint8_t ignoreBlobTag, int depth)
{
    uint64_t look_num;
    uint8_t look_typ;
    int8_t rc_dehead, rc_lookahead;

    if (depth > MAX_DEPTH) {
        return 0;
    }

    rc_dehead = ccn_iribu_ccnb_dehead(buf, len, num, typ);
    if (ignoreBlobTag && rc_dehead == 0 && is_ccn_blob(*typ)) {
        rc_lookahead =
            lookahead(buf, len, &look_num, &look_typ, ignoreBlobTag, depth + 1);
        if (rc_lookahead == 0 && is_ccn_tt(look_typ, look_num)) {
            // If we found BLOB data and inside there is a valid tag, just ignore BLOB and
            // advance
            return dehead(buf, len, num, typ, ignoreBlobTag, depth + 1);
        }
    }

    return rc_dehead;
}

void print_offset(size_t offset)
{
    size_t i;
    for (i = 0; i < offset; ++i) {
        printf(" ");
    }
}

void print_value(size_t offset, uint8_t *valptr, size_t vallen, int depth)
{
    if (depth > MAX_DEPTH) {
        return;
    }
    size_t i;
    (void) offset;
    if (vallen == 1 && ccn_iribu_isSuite(valptr[0])) {
        printf("%u", valptr[0]);
    } else {
        for (i = 0; i < vallen; ++i) {
            printf("%c", valptr[i]);
        }
    }
}

void print_tag(size_t offset, uint64_t typ, uint64_t num, uint8_t openTag,
               uint8_t withNewlines, int depth)
{
    if (depth > MAX_DEPTH) {
        return;
    }
    if (openTag || withNewlines) {
        print_offset(offset);
    }

    printf("<");
    if (!openTag) {
        printf("/");
    }
    printf("%s", tag2str(typ, num));
    printf(">");

    if (!openTag || withNewlines) {
        printf("\n");
    }
}

void print_blob(uint8_t **buf, size_t *len, uint8_t typ, uint64_t num, size_t offset,
                uint8_t ignoreBlobTag, int depth)
{
    size_t vallen;
    uint8_t *valptr;
    if (depth > MAX_DEPTH) {
        return;
    }

    if (!ignoreBlobTag) {
        print_tag(offset, typ, num, true, false, depth + 1);
    }
    ccn_iribu_ccnb_consume(typ, num, buf, len, &valptr, &vallen);
    if (vallen > *len) {
        return;
    }
    print_value(offset, valptr, vallen, depth + 1);
    if (!ignoreBlobTag) {
        print_tag(offset, typ, num, false, false, depth + 1);
    }
}

void print_ccnb(uint8_t **buf, size_t *len, size_t offset, uint8_t ignoreBlobTag,
                int depth)
{
    uint64_t num, look_num;
    uint8_t typ, look_typ;
    int8_t rc;

    if (depth > MAX_DEPTH) {
        return;
    }

    while (dehead(buf, len, &num, &typ, ignoreBlobTag, depth + 1) == 0) {
        if (num == 0 && typ == 0) {
            break;
        }

        rc = lookahead(buf, len, &look_num, &look_typ, ignoreBlobTag, depth + 1);
        if (is_ccn_blob(typ) && (rc != 0 || !is_ccn_tt(look_typ, look_num))) {
            print_blob(buf, len, typ, num, offset, ignoreBlobTag, depth + 1);
        } else {
            uint8_t withNewlines = true;
            if (ignoreBlobTag && rc == 0 && is_ccn_blob(look_typ)) {
                withNewlines = false;
            }

            print_tag(offset, typ, num, true, withNewlines, depth + 1);
            print_ccnb(buf, len, offset + 4, ignoreBlobTag, depth + 1);
            print_tag(offset, typ, num, false, withNewlines, depth + 1);
        }
    }
}

int main(int argc, char *argv[])
{
    unsigned char out[64000];
    unsigned char *p_out;
    size_t len;
    ssize_t len_s;
    int opt;
    uint8_t ignoreBlobTag = true;

    while ((opt = getopt(argc, argv, "hb")) != -1) {
        switch (opt) {
        case 'b':
            ignoreBlobTag = false;
            break;
        case 'h':
        default:
            fprintf(stderr,
                    "usage: %s [option]\n"
                    "Parses ccn-iribu-ctrl/ccn-iribu-ext-mgmt messages (CCNB) and shows "
                    "them in XML format.\n"
                    "  -b include blob tags in the XML tree\n"
                    "  -h print this message\n",
                    argv[0]);
            exit(-1);
        }
    }

    len_s = read(0, out, sizeof(out));
    if (len_s < 0) {
        perror("read");
        exit(-1);
    }
    len = (size_t) len_s;

    p_out = out;
    print_ccnb(&p_out, &len, 0, ignoreBlobTag, 0);
    return 0;
}
