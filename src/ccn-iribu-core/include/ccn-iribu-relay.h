/**
 * @ingroup CCNL-core
 * @{
 * @file ccn-iribu-relay.h
 * @brief CCN lite (CCNL) data structure ccn-iribu-relay. contains all important
 * datastructures for CCN-lite forwarding
 *
 * @author Christopher Scherb <christopher.scherb@unibas.ch>
 * @author Christian Tschudin <christian.tschudin@unibas.ch>
 *
 * @copyright (C) 2011-17, University of Basel
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

#ifndef CCN_IRIBU_RELAY_H
#    define CCN_IRIBU_RELAY_H

#    include "ccn-iribu-defs.h"
#    include "ccn-iribu-face.h"
#    include "ccn-iribu-if.h"
#    include "ccn-iribu-pkt.h"
#    include "ccn-iribu-sched.h"

struct ccn_iribu_relay_s {
    void (*ccn_iribu_ll_TX_ptr)(struct ccn_iribu_relay_s *, struct ccn_iribu_if_s *,
                                sockunion *, struct ccn_iribu_buf_s *);
#    ifndef CCN_IRIBU_ARDUINO
    time_t startup_time;
#    endif
    int id;
    struct ccn_iribu_face_s *faces;  /**< The existing forwarding faces */
    struct ccn_iribu_forward_s *fib; /**< The Forwarding Information Base (FIB) */

    struct ccn_iribu_interest_s *pit;     /**< The Pending Interest Table (PIT) */
    struct ccn_iribu_content_s *contents; /**< contentsend; */
    struct ccn_iribu_buf_s *nonces;       /**< The nonces that are currently in use */
    int contentcnt;                       /**< number of cached items */
    int max_cache_entries;                /**< max number of cached items -1: unlimited */
    int pitcnt;                           /**< Number of entries in the PIT */
    int max_pit_entries;                  /**< max number of pit entries; -1: unlimited */
    struct ccn_iribu_if_s ifs[CCN_IRIBU_MAX_INTERFACES];
    int ifcount;    /**< number of active interfaces */
    char halt_flag; /**< Flag to interrupt the IO_Loop and to exit the relay */
    struct ccn_iribu_sched_s *(*defaultFaceScheduler)(
        struct ccn_iribu_relay_s *,
        void (*cts_done)(void *, void *)); /**< FuncPoint to the scheduler for faces*/
    struct ccn_iribu_sched_s *(*defaultInterfaceScheduler)(
        struct ccn_iribu_relay_s *,
        void (*cts_done)(void *,
                         void *)); /**< FuncPoint to the scheduler for interfaces*/
#    ifdef USE_HTTP_STATUS
    struct ccn_iribu_http_s *http; /**< http server for status information*/
#    endif
    void *aux;
    /*
      struct ccn_iribu_face_s *crypto_face;
      struct ccn_iribu_pendcrypt_s *pendcrypt;
      char *crypto_path;
    */
};

/**
 * @brief Function pointer type for caching strategy function
 */
typedef int (*ccn_iribu_cache_strategy_func)(struct ccn_iribu_relay_s *relay,
                                             struct ccn_iribu_content_s *c);

/**
 * @brief Broadcast an interest message to all available interfaces
 *
 * @param[in] ccn_iribu          The CCN-IRIBU relay used to send the interest
 * @param[in] interest          The interest which should be sent
 */
void ccn_iribu_interest_broadcast(struct ccn_iribu_relay_s *ccn_iribu,
                                  struct ccn_iribu_interest_s *interest);

void ccn_iribu_face_CTS(struct ccn_iribu_relay_s *ccn_iribu, struct ccn_iribu_face_s *f);

struct ccn_iribu_face_s *ccn_iribu_get_face_or_create(struct ccn_iribu_relay_s *ccn_iribu,
                                                      int ifndx, struct sockaddr *sa,
                                                      size_t addrlen);

struct ccn_iribu_face_s *ccn_iribu_face_remove(struct ccn_iribu_relay_s *ccn_iribu,
                                               struct ccn_iribu_face_s *f);

void ccn_iribu_interface_enqueue(void(tx_done)(void *, int, int),
                                 struct ccn_iribu_face_s *f,
                                 struct ccn_iribu_relay_s *ccn_iribu,
                                 struct ccn_iribu_if_s *ifc, struct ccn_iribu_buf_s *buf,
                                 sockunion *dest);

struct ccn_iribu_buf_s *ccn_iribu_face_dequeue(struct ccn_iribu_relay_s *ccn_iribu,
                                               struct ccn_iribu_face_s *f);

void ccn_iribu_face_CTS_done(void *ptr, int cnt, int len);

/**
 * @brief Send a packet to the face @p to
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] to            face to send to
 * @param[in] pkt           packet to be sent
 *
 * @return   0 on success
 * @return   < 0 on failure
 */
int ccn_iribu_send_pkt(struct ccn_iribu_relay_s *ccn_iribu, struct ccn_iribu_face_s *to,
                       struct ccn_iribu_pkt_s *pkt);

/**
 * @brief Send a buffer to the face @p to
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] to            face to send to
 * @param[in] buf           buffer to be sent
 *
 * @return   0 on success
 * @return   < 0 on failure
 */
int ccn_iribu_face_enqueue(struct ccn_iribu_relay_s *ccn_iribu,
                           struct ccn_iribu_face_s *to, struct ccn_iribu_buf_s *buf);

struct ccn_iribu_interest_s *
ccn_iribu_interest_remove(struct ccn_iribu_relay_s *ccn_iribu,
                          struct ccn_iribu_interest_s *i);

/**
 * @brief Forwards interest message according to FIB rules
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] i             interest message to be forwarded
 */
void ccn_iribu_interest_propagate(struct ccn_iribu_relay_s *ccn_iribu,
                                  struct ccn_iribu_interest_s *i);

struct ccn_iribu_content_s *ccn_iribu_content_remove(struct ccn_iribu_relay_s *ccn_iribu,
                                                     struct ccn_iribu_content_s *c);

/**
 * @brief add content @p c to the content store
 *
 * @note adding content with this function bypasses pending interests
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] c             content to be added to the content store
 *
 * @return   reference to the content @p c
 * @return   NULL, if @p c cannot be added
 */
struct ccn_iribu_content_s *
ccn_iribu_content_add2cache(struct ccn_iribu_relay_s *ccn_iribu,
                            struct ccn_iribu_content_s *c);

/**
 * @brief deliver new content @p c to all clients with (loosely) matching interest
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] c             content to be sent
 *
 * @return   number of faces to which the content was sent to
 */
int ccn_iribu_content_serve_pending(struct ccn_iribu_relay_s *ccn_iribu,
                                    struct ccn_iribu_content_s *c);

void ccn_iribu_do_ageing(void *ptr, void *dummy);

int ccn_iribu_nonce_find_or_append(struct ccn_iribu_relay_s *ccn_iribu,
                                   struct ccn_iribu_buf_s *nonce);

int ccn_iribu_nonce_isDup(struct ccn_iribu_relay_s *relay, struct ccn_iribu_pkt_s *pkt);

void ccn_iribu_core_cleanup(struct ccn_iribu_relay_s *ccn_iribu);

#    ifdef NEEDS_PREFIX_MATCHING
/**
 * @brief Add entry to the FIB
 *
 * @par[in] relay   Local relay struct
 * @par[in] pfx     Prefix of the FIB entry
 * @par[in] face    Face for the FIB entry
 *
 * @return 0    on success
 * @return -1   on error
 */
int ccn_iribu_fib_add_entry(struct ccn_iribu_relay_s *relay,
                            struct ccn_iribu_prefix_s *pfx,
                            struct ccn_iribu_face_s *face);

/**
 * @brief Remove entry from the FIB
 *
 * @par[in] relay   Local relay struct
 * @par[in] pfx     Prefix of the FIB entry, may be NULL
 * @par[in] face    Face for the FIB entry, may be NULL
 *
 * @return 0    on success
 * @return -1   on error
 */
int ccn_iribu_fib_rem_entry(struct ccn_iribu_relay_s *relay,
                            struct ccn_iribu_prefix_s *pfx,
                            struct ccn_iribu_face_s *face);
#    endif    // NEEDS_PREFIX_MATCHING

/**
 * @brief Prints the current FIB
 *
 * @par[in] relay   Local relay struct
 */
void ccn_iribu_fib_show(struct ccn_iribu_relay_s *relay);

/**
 * @brief Prints the content of the content store
 *
 * @par[in] ccn_iribu Local relay struct
 */
void ccn_iribu_cs_dump(struct ccn_iribu_relay_s *ccn_iribu);

void ccn_iribu_interface_CTS(void *aux1, void *aux2);

#    define DBL_LINKED_LIST_ADD(l, e) \
        do {                          \
            if ((l))                  \
                (l)->prev = (e);      \
            (e)->next = (l);          \
            (l)       = (e);          \
        } while (0)

#    define DBL_LINKED_LIST_REMOVE(l, e)     \
        do {                                 \
            if ((l) == (e))                  \
                (l) = (e)->next;             \
            if ((e)->prev)                   \
                (e)->prev->next = (e)->next; \
            if ((e)->next)                   \
                (e)->next->prev = (e)->prev; \
        } while (0)

#    ifdef CCN_IRIBU_APP_RX
int ccn_iribu_app_RX(struct ccn_iribu_relay_s *ccn_iribu, struct ccn_iribu_content_s *c);
#    endif

/**
 * @brief Add content @p c to the Content Store and serve pending Interests
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] c             content to add to the content store
 *
 * @return   0,  if @p c was added to the content store
 * @return   -1, otherwise
 */
int ccn_iribu_cs_add(struct ccn_iribu_relay_s *ccn_iribu, struct ccn_iribu_content_s *c);

/**
 * @brief Remove content with @p prefix from the Content Store
 *
 * @param[in] ccn_iribu         pointer to current ccn iribu relay
 * @param[in] prefix            prefix of the content to remove from the Content Store
 *
 * @return    0, if content with @p prefix was removed
 * @return   -1, if @p ccn_iribu or @p prefix are NULL
 * @return   -2, if no memory could be allocated
 * @return   -3, if no content with @p prefix was found to be removed
 */
int ccn_iribu_cs_remove(struct ccn_iribu_relay_s *ccn_iribu, char *prefix);

/**
 * @brief Lookup content from the Content Store with prefix @p prefix
 *
 * @param[in] ccn_iribu     pointer to current ccn iribu relay
 * @param[in] prefix        prefix of the content to lookup from the Content Store
 *
 * @return              pointer to the content, if found
 * @return              NULL, if @p ccn_iribu or @p prefix are NULL
 * @return              NULL, on memory allocation failure
 * @return              NULL, if not found
 */
struct ccn_iribu_content_s *ccn_iribu_cs_lookup(struct ccn_iribu_relay_s *ccn_iribu,
                                                char *prefix);

/**
 * @brief Set a function to control the cache replacement strategy
 *
 * The given function will be called if the cache is full and a new content
 * chunk arrives. It shall remove (at least) one entry from the cache.
 *
 * If the return value of @p func is 0, the default caching strategy will be
 * applied by the CCN-lite stack. If the return value is 1, it is assumed that
 * (at least) one entry has been removed from the cache.
 *
 * @param[in] func  The function to be called for an incoming content chunk if
 *                  the cache is full.
 */
void ccn_iribu_set_cache_strategy_remove(ccn_iribu_cache_strategy_func func);

/**
 * @brief Set a function to control the caching decision strategy
 *
 * The given function will be called when a new content chunk arrives.
 * It decides whether or not to cache the new content.
 *
 * If the return value of @p func is 1, the content chunk will be cached;
 * otherwise, it will be discarded. If no caching decision strategy is
 * implemented, all content chunks will be cached.
 *
 * @param[in] func  The function to be called for an incoming content
 *                  chunk.
 */
void ccn_iribu_set_cache_strategy_cache(ccn_iribu_cache_strategy_func func);

/**
 * @brief May be defined for a particular caching strategy
 */
int cache_strategy_remove(struct ccn_iribu_relay_s *relay, struct ccn_iribu_content_s *c);

/**
 * @brief May be defined for a particular caching decision strategy
 */
int cache_strategy_cache(struct ccn_iribu_relay_s *relay, struct ccn_iribu_content_s *c);

#endif    // CCN_IRIBU_RELAY_H
/** @} */
