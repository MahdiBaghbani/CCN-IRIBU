/*
 * @f ccn-iribu-os-time.h
 * @b CCN lite (CCNL), core header file (internal data structures)
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

 #ifndef CCN_IRIBU_OS_TIME_H
 #define CCN_IRIBU_OS_TIME_H

#ifndef CCN_IRIBU_LINUXKERNEL
#include <stdint.h>
#else
#include <linux/types.h>
#endif

 #ifdef CCN_IRIBU_ARDUINO

 // typedef int time_t;
#define Hz 1000

double CCN_IRIBU_NOW(void);

 struct timeval {
    uint32_t tv_sec;
    uint32_t tv_usec;
};

void
gettimeofday(struct timeval *tv, void *dummy);

char*
timestamp(void);

#else // !CCN_IRIBU_ARDUINO
#ifndef CCN_IRIBU_LINUXKERNEL
 #include <sys/time.h>
#endif

#ifndef CCN_IRIBU_LINUXKERNEL
double
current_time(void);

char*
timestamp(void);

#endif

#endif // !CCN_IRIBU_ARDUINO

// ----------------------------------------------------------------------
#ifdef CCN_IRIBU_UNIX

#ifndef CCN_IRIBU_OMNET
#  define CCN_IRIBU_NOW()                    current_time()
#endif //CCN_IRIBU_OMNET

#endif // CCN_IRIBU_UNIX

#if defined(CCN_IRIBU_UNIX) || defined (CCN_IRIBU_RIOT) || defined (CCN_IRIBU_ARDUINO)

// ----------------------------------------------------------------------

struct ccn_iribu_timer_s {
    struct ccn_iribu_timer_s *next;
    struct timeval timeout;
    void (*fct)(char,int);
    void (*fct2)(void*,void*);
    char node;
    int intarg;
    void *aux1;
    void *aux2;
  //    int handler;
};

void
ccn_iribu_get_timeval(struct timeval *tv);

long
timevaldelta(struct timeval *a, struct timeval *b);

void*
ccn_iribu_set_timer(uint64_t usec, void (*fct)(void *aux1, void *aux2),
                 void *aux1, void *aux2);

void
ccn_iribu_rem_timer(void *h);

#endif

#ifdef CCN_IRIBU_LINUXKERNEL
struct ccn_iribu_timerlist_s {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
        struct legacy_timer_emu {
            struct timer_list t;
            void (*function)(unsigned long);
            unsigned long data;
    }tl;
#else
struct timer_list tl;
#endif
    void (*fct)(void *ptr, void *aux);
    void *ptr, *aux;
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0))
static void legacy_timer_emu_func(struct timer_list *t)
{
	struct legacy_timer_emu *lt = from_timer(lt, t, t);
	lt->function(lt->data);
}
#endif

static struct ccn_iribu_timerlist_s *spare_timer;

inline void
ccn_iribu_get_timeval(struct timeval *tv);

int
current_time2(void);

long
timevaldelta(struct timeval *a, struct timeval *b);

#  define CCN_IRIBU_NOW()                    current_time2()

static void
ccn_iribu_timer_callback(unsigned long data);

static void*
ccn_iribu_set_timer(int usec, void(*fct)(void*,void*), void *ptr, void *aux);

static void
ccn_iribu_rem_timer(void *p);

#else

int
ccn_iribu_run_events(void);

#endif // CCN_IRIBU_LINUXKERNEL

#ifdef USE_SCHEDULER

void*
ccn_iribu_set_absolute_timer(struct timeval abstime, void (*fct)(void *aux1, void *aux2),
         void *aux1, void *aux2)

#endif

#endif // CCN_IRIBU_OS_TIME_H
