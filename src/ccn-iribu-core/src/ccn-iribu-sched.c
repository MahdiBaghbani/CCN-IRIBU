/*
 * @f ccn-iribu-sched.c
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
#include "ccn-iribu-sched.h"
#include "ccn-iribu-malloc.h"
#include "ccn-iribu-os-time.h"
#include "ccn-iribu-logging.h"
#include <string.h>
#else
#include "../include/ccn-iribu-sched.h"
#include "../include/ccn-iribu-malloc.h"
#include "../include/ccn-iribu-os-time.h"
#include "../include/ccn-iribu-logging.h"
#endif


int ccn_iribu_sched_init(void)
{
    DEBUGMSG(TRACE, "%s()\n", __func__);
#ifdef USE_CHEMFLOW
    cf_debug_level = 0;
    // create chemflow core
    core = cf_core_create("ccn-iribu-core");
    if (!core)
        goto err_out;
    cfl_connect_external(core, ccn_iribu_cf_now, &core_lock);
    // create and start chemflow engine
    engine = cfl_engine_create(core, "ccn-iribu-engine");
    if (!engine)
        goto err_out;
    if (cf_engine_set_op_callback(engine, &ecb, NULL) ||
        cfl_engine_start(engine))
        goto err_out;
    // create TCP server and connect to the core
    server = cfs_start("ccn-iribu-server", core, core_lock, 1974);
    if (!server)
        goto err_out;
    return 0;

err_out:
    if (core) {
        cf_core_destroy(core);
        core = NULL;
        engine = NULL;
    }
    return -1;
#else
    return 0;
#endif
}

void ccn_iribu_sched_cleanup(void)
{
    DEBUGMSG(TRACE, "cfnl_sched_cleanup()\n");
#ifdef USE_CHEMFLOW
    if (server) {
        cfs_stop(server);
        server = NULL;
    }
    if (core) {
        cf_core_destroy(core);
        core = NULL;
        engine = NULL;
    }
#endif
}

struct ccn_iribu_sched_s*
ccn_iribu_sched_dummy_new(void (cts)(void *aux1, void *aux2),
                     struct ccn_iribu_relay_s *ccn_iribu)
{
    struct ccn_iribu_sched_s *s;

    DEBUGMSG(TRACE, "ccn_iribu_sched_dummy_new()\n");

    s = (struct ccn_iribu_sched_s*) ccn_iribu_calloc(1, sizeof(struct ccn_iribu_sched_s));
    if (s) {
    s->cts = cts;
    s->ccn_iribu = ccn_iribu;
    }
    return s;
}

struct ccn_iribu_sched_s*
ccn_iribu_sched_pktrate_new(void (cts)(void *aux1, void *aux2),
                       struct ccn_iribu_relay_s *ccn_iribu, int inter_packet_interval)
{
    struct ccn_iribu_sched_s *s;

    DEBUGMSG(TRACE, "ccn_iribu_sched_pktrate_new()\n");

    s = (struct ccn_iribu_sched_s*) ccn_iribu_calloc(1, sizeof(struct ccn_iribu_sched_s));
    if (!s)
        return NULL;
    s->mode = 1;
    s->cts = cts;
    s->ccn_iribu = ccn_iribu;
#ifdef USE_CHEMFLOW
    if (cfnl_sched_create_default_rnet(s, inter_packet_interval)) {
        ccn_iribu_free(s);
        return NULL;
    }
#else
    ccn_iribu_get_timeval(&(s->nextTX));
    s->ipi = inter_packet_interval;
#endif

    return s;
}

void
ccn_iribu_sched_destroy(struct ccn_iribu_sched_s *s)
{
  DEBUGMSG(TRACE, "ccn_iribu_sched_destroy %p\n", (void*)s);

    if (s) {
#ifdef USE_CHEMFLOW
        if (s->mode) {
            s->q->minput->obj.destroylock = 0;
            s->q->moutput->obj.destroylock = 0;
            s->q->obj.destroylock = 0;
            s->rn->obj.destroylock = 0;
            cf_rnet_destroy(s->rn);
        }
#endif
        ccn_iribu_free(s);
    }
}


void
ccn_iribu_sched_RTS(struct ccn_iribu_sched_s *s, int cnt, int len,
               void *aux1, void *aux2)
{
#ifdef USE_CHEMFLOW
    cf_time now = ccn_iribu_cf_now();
#else
    struct timeval now;
    long since;
#endif

    if (!s) {
        DEBUGMSG(VERBOSE, "ccn_iribu_sched_RTS sched=%p len=%d aux1=%p aux2=%p\n",
             (void*)s, len, (void*)aux1, (void*)aux2);
        return;
    }
    DEBUGMSG(VERBOSE, "ccn_iribu_sched_RTS sched=%p/%d len=%d aux1=%p aux2=%p\n",
             (void*)s, s->mode, len, (void*)aux1, (void*)aux2);

    s->cnt += cnt;
    s->aux1 = aux1;
    s->aux2 = aux2;

    if (s->mode == 0) {
        s->cts(aux1, aux2);
        return;
    }

#ifdef USE_CHEMFLOW
    for (; cnt; --cnt) {
        DEBUGMSG(VERBOSE, "  cf_enqueuen");
        if (CF_OK == cf_queue_enqueue_packet(s->q, 1)) {
            cf_queue_update_concentrations(s->q, now);
            cf_engine_reschedule_and_set_timer(engine, now);
        }
    }
#else
    ccn_iribu_get_timeval(&now);
    since = timevaldelta(&(s->nextTX), &now);
    if (since <= 0) {
        now.tv_sec += s->ipi / 1000000;
        now.tv_usec += s->ipi % 1000000;
        memcpy(&(s->nextTX), &now, sizeof(now));
        s->cts(aux1, aux2);
        return;
    }
    DEBUGMSG(VERBOSE, "since=%ld\n", since);
//    ccn_iribu_set_timer(since, (void(*)(void*,int))signal_cts, ccn_iribu, ifndx);
    s->pendingTimer = ccn_iribu_set_timer(since, s->cts, aux1, aux2);
    s->nextTX.tv_sec += s->ipi / 1000000;;
    s->nextTX.tv_usec += s->ipi % 1000000;;
#endif
}

void
ccn_iribu_sched_CTS_done(struct ccn_iribu_sched_s *s, int cnt, int len)
{
#ifdef USE_CHEMFLOW
    cf_time now = ccn_iribu_cf_now();
#else
    struct timeval now;
    long since;
#endif

    if (!s) {
        DEBUGMSG(VERBOSE, "ccn_iribu_sched_CTS_done sched=%p cnt=%d len=%d\n",
             (void*)s, cnt, len);
        return;
    }
    DEBUGMSG(VERBOSE, "ccn_iribu_sched_CTS_done sched=%p/%d cnt=%d len=%d (mycnt=%d)\n",
             (void*)s, s->mode, cnt, len, s->cnt);

    s->cnt -= cnt;
    if (s->cnt <= 0)
        return;

    if (s->mode == 0) {
        s->cts(s->aux1, s->aux2);
        return;
    }

#ifdef USE_CHEMFLOW
    if (CF_OK == cf_queue_dequeue_packet(s->q, 1)) {
        DEBUGMSG(VERBOSE, "  cf_dequeue successful; CTS\n");
        cf_queue_update_concentrations(s->q, now);
        cf_engine_reschedule_and_set_timer(engine, now);
        s->cts(s->aux1, s->aux2);
    }
#else
    ccn_iribu_get_timeval(&now);

    since = timevaldelta(&(s->nextTX), &now);
    if (since <= 0) {
        now.tv_sec += s->ipi / 1000000;
        now.tv_usec += s->ipi % 1000000;
        memcpy(&(s->nextTX), &now, sizeof(now));
        s->cts(s->aux1, s->aux2);
        return;
    }
    DEBUGMSG(VERBOSE, "since=%ld\n", since);
//    ccn_iribu_set_timer(since, (void(*)(void*,int))signal_cts, ccn_iribu, ifndx);
    s->pendingTimer = ccn_iribu_set_timer(since, s->cts, s->aux1, s->aux2);
    s->nextTX.tv_sec += s->ipi / 1000000;;
    s->nextTX.tv_usec += s->ipi % 1000000;;

//    s->cts();
#endif
}

void
ccn_iribu_sched_RX_ok(struct ccn_iribu_relay_s *ccn_iribu, int ifndx, int cnt)
{
    (void)ccn_iribu;
    (void)ifndx;
    (void)cnt;
    DEBUGMSG(TRACE, "ccn_iribu_sched_X_ok()\n");
    // here a chemflow reaction NW could act on pkt reception events
}


void
ccn_iribu_sched_RX_loss(struct ccn_iribu_relay_s *ccn_iribu, int ifndx, int cnt)
{
    (void)ccn_iribu;
    (void)ifndx;
    (void)cnt;
    DEBUGMSG(TRACE, "ccn_iribu_sched_RX_loss()\n");
    // here a chemflow reaction NW could act on pkt loss events
}

// ----------------------------------------------------------------------

struct ccn_iribu_sched_s*
ccn_iribu_sched_packetratelimiter_new(int inter_packet_interval,
                                 void (*cts)(void *aux1, void *aux2),
                                 void *aux1, void *aux2)
{
    struct ccn_iribu_sched_s *s;
    DEBUGMSG(TRACE, "ccn_iribu_rate:limiter_new()\n");

    s = (struct ccn_iribu_sched_s*) ccn_iribu_calloc(1, sizeof(struct ccn_iribu_sched_s));
    if (s) {
        s->cts = cts;
        s->aux1 = aux1;
        s->aux2 = aux2;
#ifndef USE_CHEMFLOW
        ccn_iribu_get_timeval(&s->nextTX);
        s->ipi = inter_packet_interval;
#endif
    }
    return s;
}




// ----------------------------------------------------------------------
#ifdef USE_CHEMFLOW
int cfnl_sched_create_default_rnet(struct ccn_iribu_sched_s *sched, int inter_packet_interval)
{
    char name[32];
    int law, k1, k2, e0;
    struct cf_molecule *s, *e, *es, *p;
    struct cf_reaction *r1, *r2;
    cf_time now;

    DEBUGMSG(TRACE, "%s()\n", __func__);

    if (inter_packet_interval) {
        law = CF_LAW_MASS_ACTION;
        k1 = 100;
        k2 = 10;
        e0 = 1000000 / (k2 * inter_packet_interval);
    } else {
        law = CF_LAW_IMMEDIATE;
        k1 = 0;
        k2 = 0;
        e0 = 1;
    }

    // create reaction network
    snprintf(name, sizeof(name), "%p", sched);
    sched->rn = cf_rnet_create(engine, name, cf_handle_null);
    if (!sched->rn)
        goto err_out;

    // create the queue abstraction
    sched->q = cf_queue_create(sched->rn, "Q", cf_handle_null);
    if (!sched->q)
        goto err_out;
    if (cf_queue_set_molecules_per_packet(sched->q, 1) ||
        cf_queue_set_op_callback(sched->q, &qcb, sched))
        goto err_out;

    // create molecules, and reactions
    s = cf_molecule_create(sched->rn, "S", cf_handle_null);
    e = cf_molecule_create(sched->rn, "E", cf_handle_null);
    es = cf_molecule_create(sched->rn, "ES", cf_handle_null);
    p = cf_molecule_create(sched->rn, "P", cf_handle_null);
    r1 = cf_reaction_create(sched->rn, "r1", cf_handle_null);
    r2 = cf_reaction_create(sched->rn, "r2", cf_handle_null);
    if (!s || !e || !es || !p || !r1 || !r2)
        goto err_out;

    // configure molecules and reactions
    if (cf_molecule_set_initial_concentration(e, e0) ||
        cf_reaction_set_law(r1, law, cf_uint_to_dfp(k1), 0) ||
        cf_reaction_add_reactant(r1, s) ||
        cf_reaction_add_reactant(r1, e) ||
        cf_reaction_add_product(r1, es) ||
        cf_reaction_set_law(r2, law, cf_uint_to_dfp(k2), 0) ||
        cf_reaction_add_reactant(r2, es) ||
        cf_reaction_add_product(r2, e) ||
        cf_reaction_add_product(r2, p))
        goto err_out;

    /* set workbench position */
    cf_object_set_pos(&s->obj, 10, 170);
    cf_object_set_pos(&e->obj, 220, 90);
    cf_object_set_pos(&es->obj, 220, 170);
    cf_object_set_pos(&p->obj, 430, 170);
    cf_object_set_pos(&r1->obj, 130, 170);
    cf_object_set_pos(&r2->obj, 320, 170);
    cf_object_set_pos(&sched->q->obj, 220, 280);

    // link queue to input and output molecule
    if (cf_queue_set_input_molecule(sched->q, s) ||
        cf_queue_set_output_molecule(sched->q, p))
        goto err_out;

    // prevent destruction of the created reaction network, queue and
    // linked molecules by the user via the chemflow configuration interface
    sched->rn->obj.destroylock = 1;
    sched->q->obj.destroylock = 1;
    s->obj.destroylock = 1;
    p->obj.destroylock = 1;

    now = ccn_iribu_cf_now();
    cf_rnet_reset(sched->rn, now);
    cf_engine_reschedule_and_set_timer(engine, now);

    return 0;

err_out:
    // destroy reaction network and all its children
    if (sched->rn) {
        cf_rnet_destroy(sched->rn);
        sched->rn = NULL;
        sched->q = NULL;
    }
    return -1;
}
#endif // USE_CHEMFLOW

#ifdef USE_CHEMFLOW

static cf_time ccn_iribu_cf_now()
{
    struct timeval now;

    ccn_iribu_get_timeval(&now);
    return ((cf_time)now.tv_sec) * 1000000000 + now.tv_usec * 1000;
}

static struct cf_core *core = NULL;
static pthread_mutex_t core_lock = PTHREAD_MUTEX_INITIALIZER;
static struct cf_engine *engine = NULL;
static void *engine_timer = NULL;
static struct cf_server *server = NULL;

// callback from the CCNL timer; execute pending reactions
static void ccn_iribu_sched_cf_timeout(void *aux1, void *aux2)
{
    DEBUGMSG(TRACE, "%s()\n", __func__);

    cf_engine_execute_pending_reactions_and_set_timer(engine, ccn_iribu_cf_now());
}

// callback from the chemflow engine when a timer for the first reaction shall be set/changed/canceled
static int ccn_iribu_sched_cf_engine_set_timer(struct cf_engine *e, void *userptr, cf_time time)
{
    struct timeval tv;

    DEBUGMSG(TRACE, "%s()\n", __func__);

    // stop the currently running timer
    if (engine_timer) {
        ccn_iribu_rem_timer(engine_timer);
        engine_timer = NULL;
    }
    // start the timer
    if (time < CF_TIME_INF) {
        tv.tv_sec = cf_u64_div(time, 1000000000);
        tv.tv_usec = cf_u64_mod(time, 1000000000) / 1000;
        engine_timer = ccn_iribu_set_absolute_timer(tv, ccn_iribu_sched_cf_timeout, NULL, NULL);
    }

    return CF_OK;
}

static struct cf_engine_op_cb ecb = {
    .set_timer = ccn_iribu_sched_cf_engine_set_timer
};

// callback from the chemflow queue when the next packet shall be dequeued; CTS
static void ccn_iribu_sched_cf_queue_serve_cb(struct cf_queue *q, void *userptr, cf_time now)
{
    struct ccn_iribu_sched_s *s = userptr;

    DEBUGMSG(TRACE, "%s()\n", __func__);

    if (CF_OK == cf_queue_dequeue_packet(q, 1)) {
        DEBUGMSG(VERBOSE, "  cf_dequeue successful; CTS\n");
        cf_queue_update_concentrations(q, now);
        cf_engine_reschedule_and_set_timer(engine, now);
        s->cts(s->aux1, s->aux2);
    }
}

static struct cf_queue_op_cb qcb = {
    .serve = ccn_iribu_sched_cf_queue_serve_cb,
    .drop = NULL,
    .reset = NULL
};

#endif // USE_CHEMFLOW

// ----------------------------------------------------------------------
