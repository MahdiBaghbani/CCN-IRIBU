/*
 * @f ccn-iribu-if.c
 * @b CCN lite, core CCNx protocol logic
 *
 * Copyright (C) 2011-18 University of Basel
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
 * 2017-06-16 created
 */


#ifndef CCN_IRIBU_LINUXKERNEL
#include "ccn-iribu-if.h"
#include "ccn-iribu-os-time.h"
#include "ccn-iribu-malloc.h"
#include "ccn-iribu-logging.h"
#include <sys/socket.h>
#ifndef CCN_IRIBU_RIOT
#include <sys/un.h>
#else
#include "net/packet.h"
#endif
#include <unistd.h>
#else
#include "../include/ccn-iribu-if.h"
#include "../include/ccn-iribu-os-time.h"
#include "../include/ccn-iribu-malloc.h"
#include "../include/ccn-iribu-logging.h"
#endif

void
ccn_iribu_interface_cleanup(struct ccn_iribu_if_s *i)
{
    size_t j;
    DEBUGMSG_CORE(TRACE, "ccn_iribu_interface_cleanup\n");

    ccn_iribu_sched_destroy(i->sched);
    for (j = 0; j < i->qlen; j++) {
        struct ccn_iribu_txrequest_s *r = i->queue + (i->qfront+j)%CCN_IRIBU_MAX_IF_QLEN;
        ccn_iribu_free(r->buf);
    }
#if !defined(CCN_IRIBU_RIOT) && !defined(CCN_IRIBU_ANDROID) && !defined(CCN_IRIBU_LINUXKERNEL)
    ccn_iribu_close_socket(i->sock);
#endif
}

#if !defined(CCN_IRIBU_RIOT) && !defined(CCN_IRIBU_ANDROID) && !defined(CCN_IRIBU_LINUXKERNEL)
int
ccn_iribu_close_socket(int s)
{
    struct sockaddr_un su;
    socklen_t len = sizeof(su);

    if (!getsockname(s, (struct sockaddr*) &su, &len) &&
                                        su.sun_family == AF_UNIX) {
        unlink(su.sun_path);
    }
    return close(s);
}
#endif
