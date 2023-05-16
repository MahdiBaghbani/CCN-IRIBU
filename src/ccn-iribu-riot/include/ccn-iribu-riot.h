/*
 * Copyright (C) 2015, 2016 INRIA
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef CCN_LITE_RIOT_H
#    define CCN_LITE_RIOT_H

/**
 * @defgroup    pkg_ccniribu CCN-IRIBU stack
 * @ingroup     pkg
 * @ingroup     net
 * @brief       Provides a NDN implementation
 *
 * This package provides the CCN-IRIBU stack as a port of NDN for RIOT.
 *
 * @{
 */

#    include "arpa/inet.h"
#    include "ccn-iribu-core.h"
#    include "ccn-iribu-dispatch.h"
#    include "ccn-iribu-pkt-ndntlv.h"
#    include "net/ethernet/hdr.h"
#    include "net/gnrc/netreg.h"
#    include "net/packet.h"
#    include "sched.h"
#    include "sys/socket.h"
#    include <unistd.h>
//#include "ccn-iribu-pkt-builder.h"

#    include "evtimer.h"
#    include "evtimer_msg.h"
#    include "irq.h"
#    include "thread.h"

#    ifdef __cplusplus
extern "C" {
#    endif

/**
 * @name Dynamic memory allocation used in CCN-IRIBU
 *
 * @{
 */
#    define ccn_iribu_malloc(s)     malloc(s)
#    define ccn_iribu_calloc(n, s)  calloc(n, s)
#    define ccn_iribu_realloc(p, s) realloc(p, s)
#    define ccn_iribu_free(p)       free(p)
/**
 * @}
 */

/**
 * Constant string
 */
#    define CONSTSTR(s) s

/**
 * Stack size for CCN-IRIBU event loop
 */
#    ifndef CCN_IRIBU_STACK_SIZE
#        define CCN_IRIBU_STACK_SIZE (THREAD_STACKSIZE_MAIN)
#    endif

/**
 * Size of the message queue of CCN-IRIBU's event loop
 */
#    ifndef CCN_IRIBU_QUEUE_SIZE
#        define CCN_IRIBU_QUEUE_SIZE (8)
#    endif

/**
 * Interest retransmission interval in milliseconds
 */
#    ifndef CCN_IRIBU_INTEREST_RETRANS_TIMEOUT
#        define CCN_IRIBU_INTEREST_RETRANS_TIMEOUT (1000)
#    endif

/**
 * @brief Data structure for interest packet
 */
typedef struct {
    struct ccn_iribu_prefix_s *prefix; /**< requested prefix */
    unsigned char *buf;                /**< buffer to store the interest packet */
    size_t buflen;                     /**< size of the buffer */
} ccn_iribu_interest_t;

/**
 * PID of the eventloop thread
 */
extern kernel_pid_t ccn_iribu_event_loop_pid;

/**
 * Maximum string length for prefix representation
 */
#    define CCN_IRIBU_PREFIX_BUFSIZE (50)

/**
 * Message type for signalling a timeout while waiting for a content chunk
 */
#    define CCN_IRIBU_MSG_TIMEOUT (0x1701)

/**
 * Message type for advancing the ageing timer
 */
#    define CCN_IRIBU_MSG_AGEING (0x1702)

/**
 * Message type for Interest retransmissions
 */
#    define CCN_IRIBU_MSG_INT_RETRANS (0x1703)

/**
 * Message type for adding content store entries
 */
#    define CCN_IRIBU_MSG_CS_ADD (0x1704)

/**
 * Message type for deleting content store entries
 */
#    define CCN_IRIBU_MSG_CS_DEL (0x1705)

/**
 * Message type for performing a content store lookup
 */
#    define CCN_IRIBU_MSG_CS_LOOKUP (0x1706)

/**
 * Message type for Interest timeouts
 */
#    define CCN_IRIBU_MSG_INT_TIMEOUT (0x1707)

/**
 * Message type for Face timeouts
 */
#    define CCN_IRIBU_MSG_FACE_TIMEOUT (0x1708)

/**
 * Maximum number of elements that can be cached
 */
#    ifndef CCN_IRIBU_CACHE_SIZE
#        define CCN_IRIBU_CACHE_SIZE (5)
#    endif
#    ifdef DOXYGEN
#        define CCN_IRIBU_CACHE_SIZE
#    endif

#    ifndef CCN_IRIBU_THREAD_PRIORITY
#        define CCN_IRIBU_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 1)
#    endif

/**
 * Struct holding CCN-IRIBU's central relay information
 */
extern struct ccn_iribu_relay_s ccn_iribu_relay;

/**
 * Struct Evtimer for various ccn iribu events
 */
extern evtimer_msg_t ccn_iribu_evtimer;

/**
 * @brief   Start the main CCN-IRIBU event-loop
 *
 * @return  The PID of the event-loop's thread
 */
kernel_pid_t ccn_iribu_start(void);

/**
 * @brief Opens a @ref net_gnrc_netif device for use with CCN-IRIBU
 *
 * @param[in] if_pid        The pid of the @ref net_gnrc_netif device driver
 * @param[in] netreg_type   The @ref net_gnrc_nettype @p if_pid should be
 *                          configured to use
 *
 * @return 0 on success,
 * @return -EINVAL if eventloop could not be registered for @p netreg_type
 */
int ccn_iribu_open_netif(kernel_pid_t if_pid, gnrc_nettype_t netreg_type);

/**
 * @brief Sends out an Interest
 *
 * @param[in] prefix    The name that is requested
 * @param[out] buf      Buffer to write the content chunk to
 * @param[in] buf_len   Size of @p buf
 * @param[in] int_opts  Interest options (@ref ccn_iribu_interest_opts_u)
 *
 * @return 0 on success
 * @return -1, packet format not supported
 * @return -2, prefix is NULL
 * @return -3, packet deheading failed
 * @return -4, parsing failed
 */
int ccn_iribu_send_interest(struct ccn_iribu_prefix_s *prefix, unsigned char *buf,
                            int buf_len, ccn_iribu_interest_opts_u *int_opts);

/**
 * @brief Wait for incoming content chunk
 *
 * @pre The thread has to register for CCN_IRIBU_CONT_CHUNK in @ref net_gnrc_netreg
 *      first
 *
 * @post The thread should unregister from @ref net_gnrc_netreg after this
 *       function returns
 *
 * @param[out] buf      Buffer to stores the received content
 * @param[in]  buf_len  Size of @p buf
 * @param[in]  timeout  Maximum to wait for the chunk, set to a default value if 0
 *
 * @return 0 if a content was received
 * @return -ETIMEDOUT if no chunk was received until timeout
 */
int ccn_iribu_wait_for_chunk(void *buf, size_t buf_len, uint64_t timeout);

/**
 * @brief Send a message to the CCN-lite thread to add @p to the content store
 *
 * @param[in] content   The content to add to the content store
 */
static inline void ccn_iribu_msg_cs_add(struct ccn_iribu_content_s *content)
{
    msg_t ms = {.type = CCN_IRIBU_MSG_CS_ADD, .content.ptr = content};
    msg_send(&ms, ccn_iribu_event_loop_pid);
}

/**
 * @brief Send a message to the CCN-lite thread to remove a content with
 * the @p prefix from the content store
 *
 * @param[in] content   The prefix of the content to remove from the content store
 */
static inline void ccn_iribu_msg_cs_remove(struct ccn_iribu_prefix_s *prefix)
{
    msg_t ms = {.type = CCN_IRIBU_MSG_CS_DEL, .content.ptr = prefix};
    msg_send(&ms, ccn_iribu_event_loop_pid);
}

/**
 * @brief Send a message to the CCN-lite thread to perform a content store
 * lookup for the @p prefix
 *
 * @param[in] content   The prefix of the content to perform a lookup for
 *
 * @return              pointer to the content, if found
 * @reutn               NULL, if not found
 */
static inline struct ccn_iribu_content_s *
ccn_iribu_msg_cs_lookup(struct ccn_iribu_prefix_s *prefix)
{
    msg_t mr, ms = {.type = CCN_IRIBU_MSG_CS_LOOKUP, .content.ptr = prefix};
    msg_send_receive(&ms, &mr, ccn_iribu_event_loop_pid);
    return (struct ccn_iribu_content_s *) mr.content.ptr;
}

/**
 * @brief Reset Interest retransmissions
 *
 * @param[in] i         The interest to update
 */
static inline void
ccn_iribu_evtimer_reset_interest_retrans(struct ccn_iribu_interest_s *i)
{
    evtimer_del((evtimer_t *) (&ccn_iribu_evtimer),
                (evtimer_event_t *) &i->evtmsg_retrans);
    i->evtmsg_retrans.msg.type                       = CCN_IRIBU_MSG_INT_RETRANS;
    i->evtmsg_retrans.msg.content.ptr                = i;
    ((evtimer_event_t *) &i->evtmsg_retrans)->offset = CCN_IRIBU_INTEREST_RETRANS_TIMEOUT;
    evtimer_add_msg(&ccn_iribu_evtimer, &i->evtmsg_retrans, ccn_iribu_event_loop_pid);
}

/**
 * @brief Reset Interest timeout
 *
 * @param[in] i         The interest to update
 */
static inline void
ccn_iribu_evtimer_reset_interest_timeout(struct ccn_iribu_interest_s *i)
{
    evtimer_del((evtimer_t *) (&ccn_iribu_evtimer),
                (evtimer_event_t *) &i->evtmsg_timeout);
    i->evtmsg_timeout.msg.type                       = CCN_IRIBU_MSG_INT_TIMEOUT;
    i->evtmsg_timeout.msg.content.ptr                = i;
    ((evtimer_event_t *) &i->evtmsg_timeout)->offset = i->lifetime * 1000;    // ms
    evtimer_add_msg(&ccn_iribu_evtimer, &i->evtmsg_timeout, ccn_iribu_event_loop_pid);
}

/**
 * @brief Reset Face timeout
 *
 * @param[in] f         The face to update
 */
static inline void ccn_iribu_evtimer_reset_face_timeout(struct ccn_iribu_face_s *f)
{
    evtimer_del((evtimer_t *) (&ccn_iribu_evtimer),
                (evtimer_event_t *) &f->evtmsg_timeout);
    f->evtmsg_timeout.msg.type        = CCN_IRIBU_MSG_FACE_TIMEOUT;
    f->evtmsg_timeout.msg.content.ptr = f;
    ((evtimer_event_t *) &f->evtmsg_timeout)->offset =
        CCN_IRIBU_FACE_TIMEOUT * 1000;    // ms
    evtimer_add_msg(&ccn_iribu_evtimer, &f->evtmsg_timeout, ccn_iribu_event_loop_pid);
}

/**
 * @brief Set content timeout
 *
 * @param[in] c         The content to timeout
 */
static inline void ccn_iribu_evtimer_set_cs_timeout(struct ccn_iribu_content_s *c)
{
    evtimer_del((evtimer_t *) (&ccn_iribu_evtimer),
                (evtimer_event_t *) &c->evtmsg_cstimeout);
    c->evtmsg_cstimeout.msg.type        = CCN_IRIBU_MSG_CS_DEL;
    c->evtmsg_cstimeout.msg.content.ptr = c->pkt->pfx;
    ((evtimer_event_t *) &c->evtmsg_cstimeout)->offset =
        CCN_IRIBU_CONTENT_TIMEOUT * 1000UL;    // ms
    evtimer_add_msg(&ccn_iribu_evtimer, &c->evtmsg_cstimeout, ccn_iribu_event_loop_pid);
}

/**
 * @brief Remove RIOT related structures for Interests
 *
 * @param[in] et        RIOT related event queue that holds timer events
 * @param[in] i         The Interest structure
 */
static inline void ccn_iribu_riot_interest_remove(evtimer_t *et,
                                                  struct ccn_iribu_interest_s *i)
{
    evtimer_del(et, (evtimer_event_t *) &i->evtmsg_retrans);
    evtimer_del(et, (evtimer_event_t *) &i->evtmsg_timeout);

    unsigned state = irq_disable();
    /* remove messages that relate to this interest from the message queue */
    thread_t *me = thread_get_active();
    for (unsigned j = 0; j <= me->msg_queue.mask; j++) {
        if (me->msg_array[j].content.ptr == i) {
            /* removing is done by setting to zero */
            memset(&(me->msg_array[j]), 0, sizeof(me->msg_array[j]));
        }
    }
    irq_restore(state);
}

#    ifdef __cplusplus
}
#    endif
#endif /* CCN_LITE_RIOT_H */
/** @} */
