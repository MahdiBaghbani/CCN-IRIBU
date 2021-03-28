/*
 * @f ccn-iribu-unix.h
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

#ifndef CCN_IRIBU_UNIX_H
#define CCN_IRIBU_UNIX_H

#include <dirent.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ccn-iribu-sockunion.h"
#include <netinet/in.h>

#include "ccn-iribu-buf.h"
#include "ccn-iribu-if.h"
#include "ccn-iribu-relay.h"

#ifdef USE_LINKLAYER
#    if !(defined(__FreeBSD__) || defined(__APPLE__))
int ccn_iribu_open_ethdev(char *devname, struct sockaddr_ll *sll, uint16_t ethtype);
#    endif
#endif

#ifdef USE_WPAN
int ccn_iribu_open_wpandev(char *devname, struct sockaddr_ieee802154 *swpan);
#endif

#ifdef USE_UNIXSOCKET
int ccn_iribu_open_unixpath(char *path, struct sockaddr_un *ux);
#endif

#ifdef USE_IPV4
int ccn_iribu_open_udpdev(uint16_t port, struct sockaddr_in *si);
#endif

#ifdef USE_IPV6
int ccn_iribu_open_udp6dev(uint16_t port, struct sockaddr_in6 *sin);
#endif

#ifdef USE_LINKLAYER
ssize_t ccn_iribu_eth_sendto(int sock, uint8_t *dst, uint8_t *src, uint8_t *data,
                             size_t datalen);
#endif

#ifdef USE_WPAN
int ccn_iribu_wpan_sendto(int sock, unsigned char *data, int datalen,
                          struct sockaddr_ieee802154 *dst);
#endif

#ifdef USE_SCHEDULER
struct ccn_iribu_sched_s *
ccn_iribu_relay_defaultFaceScheduler(struct ccn_iribu_relay_s *ccn_iribu,
                                     void (*cb)(void *, void *));
struct ccn_iribu_sched_s *
ccn_iribu_relay_defaultInterfaceScheduler(struct ccn_iribu_relay_s *ccn_iribu,
                                          void (*cb)(void *, void *));
#endif    // USE_SCHEDULER

void ccn_iribu_ageing(void *relay, void *aux);

#if defined(USE_IPV4) || defined(USE_IPV6)
void ccn_iribu_relay_udp(struct ccn_iribu_relay_s *relay, int32_t port, int af,
                         int suite);
#endif

void ccn_iribu_ll_TX(struct ccn_iribu_relay_s *ccn_iribu, struct ccn_iribu_if_s *ifc,
                     sockunion *dest, struct ccn_iribu_buf_s *buf);

void ccn_iribu_relay_config(struct ccn_iribu_relay_s *relay, char *ethdev, char *wpandev,
                            int32_t udpport1, int32_t udpport2, int32_t udp6port1,
                            int32_t udp6port2, int32_t httpport, char *uxpath, int suite,
                            int max_cache_entries, char *crypto_face_path);

int ccn_iribu_io_loop(struct ccn_iribu_relay_s *ccn_iribu);

void ccn_iribu_populate_cache(struct ccn_iribu_relay_s *ccn_iribu, char *path);

#endif    // CCN_IRIBU_UNIX_H
