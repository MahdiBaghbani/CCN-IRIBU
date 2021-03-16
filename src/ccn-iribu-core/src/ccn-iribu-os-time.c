/*
 * @f ccn-iribu-os-time.c
 * @b CCN lite (CCNL), core source file (internal data structures)
 *
 * Copyright (C) 2011-17, University of Basel
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
#include "ccn-iribu-os-time.h"
#include "ccn-iribu-malloc.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#else
#include "../include/ccn-iribu-os-time.h"
#include "../include/ccn-iribu-malloc.h"
#endif




struct ccn_iribu_timer_s *eventqueue;


#if defined(CCN_IRIBU_RIOT) && !(defined(__FreeBSD__) || defined(__APPLE__) || defined(__linux__))
#include <xtimer.h>

int gettimeofday(struct timeval *__restrict __p, void *__restrict __tz)
{
    (void) __tz;
    uint64_t now = xtimer_now_usec64();
    __p->tv_sec = div_u64_by_1000000(now);
    __p->tv_usec = now - (__p->tv_sec * US_PER_SEC);

    return 0;
}
#endif

#ifdef CCN_IRIBU_ARDUINO

double CCN_IRIBU_NOW(void) { return (double) millis() / Hz; }

void
gettimeofday(struct timeval *tv, void *dummy)
{
    uint32_t t = millis();
    tv->tv_sec = t / Hz;
    tv->tv_usec = (t % Hz) * (1000000 / Hz);
}

char*
timestamp(void)
{
    static char ts[12];
    uint32_t m = millis();

    sprintf_P(ts, PSTR("%lu.%03d"), m / 1000, (int)(m % 1000));

    return ts;
}

#else // !CCN_IRIBU_ARDUINO

#ifndef CCN_IRIBU_LINUXKERNEL
double
current_time(void)
{
    struct timeval tv;
    static time_t start;
    static time_t start_usec;

    gettimeofday(&tv, NULL);

    if (!start) {
        start = tv.tv_sec;
        start_usec = tv.tv_usec;
    }

    return (double)(tv.tv_sec) - start +
                ((double)(tv.tv_usec) - start_usec) / 1000000;
}

char*
timestamp(void)
{
    static char ts[16], *cp;

    snprintf(ts, sizeof(ts), "%.4g", CCN_IRIBU_NOW());
    cp = strchr(ts, '.');
    if (!cp)
        strcat(ts, ".0000");
    else if (strlen(cp) > 5)
        cp[5] = '\0';
    else while (strlen(cp) < 5)
        strcat(cp, "0");
        
    return ts;
}

#endif

#endif // !CCN_IRIBU_ARDUINO

long
timevaldelta(struct timeval *a, struct timeval *b) {
    return 1000000*(a->tv_sec - b->tv_sec) + a->tv_usec - b->tv_usec;
}

#if defined(CCN_IRIBU_UNIX) || defined (CCN_IRIBU_RIOT) || defined (CCN_IRIBU_ARDUINO)

void
ccn_iribu_get_timeval(struct timeval *tv)
{
    gettimeofday(tv, NULL);
}

void*
ccn_iribu_set_timer(uint64_t usec, void (*fct)(void *aux1, void *aux2),
                 void *aux1, void *aux2)
{
    struct ccn_iribu_timer_s *t, **pp;
    //    static int handlercnt;

    t = (struct ccn_iribu_timer_s *) ccn_iribu_calloc(1, sizeof(*t));
    if (!t)
        return 0;
    t->fct2 = fct;
    gettimeofday(&t->timeout, NULL);
    usec += t->timeout.tv_usec;
    t->timeout.tv_sec += usec / 1000000;
    t->timeout.tv_usec = usec % 1000000;
    t->aux1 = aux1;
    t->aux2 = aux2;

    for (pp = &eventqueue; ; pp = &((*pp)->next)) {
    if (!*pp || (*pp)->timeout.tv_sec > t->timeout.tv_sec ||
        ((*pp)->timeout.tv_sec == t->timeout.tv_sec &&
         (*pp)->timeout.tv_usec > t->timeout.tv_usec)) {
        t->next = *pp;
        //        t->handler = handlercnt++;
        *pp = t;
        return t;
    }
    }
    return NULL; // ?
}

void
ccn_iribu_rem_timer(void *h)
{
    struct ccn_iribu_timer_s **pp;

    for (pp = &eventqueue; *pp; pp = &((*pp)->next)) {
        if ((void*)*pp == h) {
            struct ccn_iribu_timer_s *e = *pp;
            *pp = e->next;
            ccn_iribu_free(e);
            break;
        }
    }
}

#endif

#ifdef CCN_IRIBU_LINUXKERNEL

inline void
ccn_iribu_get_timeval(struct timeval *tv)
{
    jiffies_to_timeval(jiffies, tv);
}

int
current_time2(void)
{
    struct timeval tv;

    ccn_iribu_get_timeval(&tv);
    return tv.tv_sec;
}

static void
ccn_iribu_timer_callback(unsigned long data)
{
    struct ccn_iribu_timerlist_s *t = (struct ccn_iribu_timerlist_s*) data;
    void (*fct)(void*,void*) = t->fct;
    void *ptr = t->ptr, *aux = t->aux;

    if (!spare_timer)
        spare_timer = t;
    else
        kfree(t);
    (fct)(ptr, aux);
}

static void*
ccn_iribu_set_timer(int usec, void(*fct)(void*,void*), void *ptr, void *aux)
{
    struct ccn_iribu_timerlist_s *t;

    if (spare_timer) {
        t = spare_timer;
        spare_timer = NULL;
    } else {
        t = kmalloc(sizeof(struct ccn_iribu_timerlist_s), GFP_ATOMIC);
        if (!t)
            return NULL;
    }
    #if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
    timer_setup(&t->tl.t,legacy_timer_emu_func,0);
#else
    init_timer(&t->tl);
#endif
    t->tl.function = ccn_iribu_timer_callback;
    t->tl.data = (unsigned long) t;
    t->fct = fct;
    t->ptr = ptr;
    t->aux = aux;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
    t->tl.t.expires = jiffies + usecs_to_jiffies(usec);
#else
    t->tl.expires = jiffies + usecs_to_jiffies(usec);
#endif
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
    add_timer(&t->tl.t);
#else
    add_timer(&t->tl);
#endif
    return t;
}

static void
ccn_iribu_rem_timer(void *p)
{
    struct ccn_iribu_timerlist_s *t = (struct ccn_iribu_timerlist_s*) p;

    if (!p)
        return;
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0))
    del_timer(&t->tl.t);
    #else
    del_timer(&t->tl);
    #endif
    if (!spare_timer)
        spare_timer = t;
    else
        kfree(t);
}

#else// we have to work through the pending timer requests ourself

// "looper": serves all pending events and returns the number of microseconds
// when the next event should be triggered.
int
ccn_iribu_run_events(void)
{
    static struct timeval now;
    long usec;

    gettimeofday(&now, 0);
    while (eventqueue) {
        struct ccn_iribu_timer_s *t = eventqueue;

        usec = timevaldelta(&(t->timeout), &now);
        if (usec >= 0)
            return usec;

        if (t->fct)
            (t->fct)(t->node, t->intarg);
        else if (t->fct2)
            (t->fct2)(t->aux1, t->aux2);
        eventqueue = t->next;
        ccn_iribu_free(t);
    }

    return -1;
}

#endif // CCN_IRIBU_LINUXKERNEL

// ----------------------------------------------------------------------

#ifdef USE_SCHEDULER

void*
ccn_iribu_set_absolute_timer(struct timeval abstime, void (*fct)(void *aux1, void *aux2),
         void *aux1, void *aux2)
{
    struct ccn_iribu_timer_s *t, **pp;
    //    static int handlercnt;

    t = (struct ccn_iribu_timer_s *) ccn_iribu_calloc(1, sizeof(*t));
    if (!t)
    return 0;
    t->fct2 = fct;
    t->timeout = abstime;
    t->aux1 = aux1;
    t->aux2 = aux2;

    for (pp = &eventqueue; ; pp = &((*pp)->next)) {
    if (!*pp || (*pp)->timeout.tv_sec > t->timeout.tv_sec ||
        ((*pp)->timeout.tv_sec == t->timeout.tv_sec &&
         (*pp)->timeout.tv_usec > t->timeout.tv_usec)) {
        t->next = *pp;
        //        t->handler = handlercnt++;
        *pp = t;
        return t;
    }
    }
    return NULL; // ?
}

#endif
