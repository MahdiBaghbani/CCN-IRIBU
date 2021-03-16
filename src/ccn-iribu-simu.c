/*
 * @f ccn-lite-simu.c
 * @b prog with multiple CCNL relays, running a standalone simulation
 *
 * Copyright (C) 2011-13, Christian Tschudin, University of Basel
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
 * 2011-11-22 created
 * 2011-12 simulation scenario and logging support s.braun@stud.unibas.ch
 * 2013-03-19 updated (ms): replacement code after renaming the field
 *              ccn_iribu_relay_s.client to ccn_iribu_relay_s.aux
 * 2014-12-18 removed log generation (cft)
 */


#define CCN_IRIBU_SIMULATION
#define CCN_IRIBU_UNIX

#define USE_DEBUG
#define USE_DEBUG_MALLOC
#define USE_DUP_CHECK
#define USE_LINKLAYER
#define USE_FRAG
#define USE_IPV4
#define USE_LOGGING
//#define USE_SCHEDULER
#define USE_SUITE_CCNB
#define USE_SUITE_CCNTLV
#define USE_SUITE_NDNTLV

#define NEEDS_PREFIX_MATCHING
#define NEEDS_PACKET_CRAFTING


#include <inttypes.h>
#include "ccn-iribu-os-includes.h"

#include "ccn-iribu-defs.h"
#include "ccn-iribu-core.h"
#include "ccn-iribu-ext.h"

#define local_producer(...) 0
#define cache_strategy_remove(...)      0
#define cache_strategy_cache(...)       0

#include "ccn-iribu-ext-debug.c"
#include "ccn-iribu-os-time.c"
#include "ccn-iribu-ext-logging.c"

int ccn_iribu_app_RX(struct ccn_iribu_relay_s *ccnl, struct ccn_iribu_content_s *c);

struct ccn_iribu_prefix_s* ccn_iribu_prefix_new(int suite, int cnt);
int ccn_iribu_pkt_prependComponent(int suite, char *src, int *offset, unsigned char *buf);

#include "ccn-iribu-core.c"

#include "ccn-iribu-ext-mgmt.c"
#include "ccn-iribu-ext-sched.c"

#include "ccn-iribu-ext-frag.c"


char theSuite = CCN_IRIBU_SUITE_DEFAULT;

// ----------------------------------------------------------------------

#define SIMU_NUMBER_OF_CHUNKS   10
// #define SIMU_CHUNK_SIZE              4096
#define SIMU_CHUNK_SIZE         1600
// #define SIMU_CHUNK_SIZE              1340

static struct ccn_iribu_relay_s* char2relay(char node);
static char relay2char(struct ccn_iribu_relay_s *relay);
void ccn_iribu_simu_fini(void *ptr, int aux);

void ccn_iribu_simu_phase_two(void *ptr, void *dummy);


extern void ccn_iribu_simu_client_RX(struct ccn_iribu_relay_s *relay, char *name,
                                int seqn, char *data, int len);
extern void ccn_iribu_simu_ll_TX(struct ccn_iribu_relay_s *relay, unsigned char *dst,
                           unsigned char *src, unsigned char *data, int len);
extern void ccn_iribu_simu_LOG(struct ccn_iribu_relay_s *relay, char *s);

void ccn_iribu_simu_client(char node); // sending side

void ccn_iribu_simu_ethernet(void *dummy, void *dummy2); // implements the media

void ccn_iribu_simu_client_endlog(struct ccn_iribu_relay_s *relay);

// ----------------------------------------------------------------------

struct ccn_iribu_relay_s relays[5];

#define relayChars "ABC12"

static struct ccn_iribu_relay_s*
char2relay(char node)
{
    unsigned int i;

    for (i = 0; i < strlen(relayChars); i++) {
        if (node == relayChars[i])
            return relays + i;
    }
    fprintf(stderr, "unknown node %c\n", node);
    return 0;
}

static char
relay2char(struct ccn_iribu_relay_s *relay)
{
    unsigned int i;

    for (i = 0; i < strlen(relayChars); i++) {
        if (relay == (relays + i))
            return relayChars[i];
    }
    fprintf(stderr, "unknown node %p\n", (void *) relay);
    return '?';
}

void
ccn_iribu_simu_add2cache(char node, const char *name, int seqn, void *data, int len)
{
    struct ccn_iribu_relay_s *relay;
    char tmp[100];
    int dataoffset;
    struct ccn_iribu_content_s *c;
    struct ccn_iribu_pkt_s *pkt;

    relay = char2relay(node);
    if (!relay)
        return;

    snprintf(tmp, sizeof(tmp), "%s/.%d", name, seqn);
    DEBUGMSG(VERBOSE, "  %s\n", tmp);
    //    p = ccn_iribu_path_to_prefix(tmp);
    //    p->suite = suite;
    pkt = ccn_iribu_calloc(1, sizeof(*pkt));
    pkt->pfx = ccn_iribu_URItoPrefix(tmp, theSuite, NULL, NULL);
    DEBUGMSG(VERBOSE, "  %s\n", ccn_iribu_prefix_to_path(pkt->pfx));
    pkt->buf = ccn_iribu_mkSimpleContent(pkt->pfx, data, len, &dataoffset, NULL);
    pkt->content = pkt->buf->data + dataoffset;
    pkt->contlen = len;
    c = ccn_iribu_content_new(relay, &pkt);
    if (c)
        ccn_iribu_content_add2cache(relay, c);
    return;
}

// ----------------------------------------------------------------------

void
ccn_iribu_client_TX(char node, char *name, int seqn, int nonce)
{
    char tmp[512];
    struct ccn_iribu_prefix_s *p;
    struct ccn_iribu_buf_s *buf;
    struct ccn_iribu_relay_s *relay = char2relay(node);
    ccn_iribu_interets_opts_u opts;

    DEBUGMSG(TRACE, "ccn_iribu_client_tx node=%c: request %s #%d\n",
             node, name, seqn);

    if (!relay)
        return;

    snprintf(tmp, sizeof(tmp), "%s/.%d", name, seqn);
    //    p = ccn_iribu_path_to_prefix(tmp);
    //    p->suite = suite;
    p = ccn_iribu_URItoPrefix(tmp, theSuite, NULL, NULL);

    if (theSuite == CCN_IRIBU_SUITE_NDNTLV) {
        opts.ndntlv.nonce = nonce;
    }

    DEBUGMSG(TRACE, "  create interest for %s\n", ccn_iribu_prefix_to_path(p));
    buf = ccn_iribu_mkSimpleInterest(p, &opts);
    ccn_iribu_prefix_free(p);

    // inject it into the relay:
    if (buf) {
        ccn_iribu_core_RX(relay, -1, buf->data, buf->datalen, 0, 0);
        ccn_iribu_free(buf);
    }
}

// ----------------------------------------------------------------------
// simulated ethernet segment

struct ccn_iribu_ethernet_s {
    struct ccn_iribu_ethernet_s *next;
    unsigned char *dst, *src;
    unsigned short protocol;
    unsigned char *data;
    int len;
};
struct ccn_iribu_ethernet_s *etherqueue;

void
ccn_iribu_simu_ethernet(void *dummy, void *dummy2)
{
    if (etherqueue) {
        int i, qlen;
        struct ccn_iribu_ethernet_s **pp, *p;

        // pick the last element in the queue
        for (qlen = 1, pp = &etherqueue; (*pp)->next; pp = &((*pp)->next))
            qlen++;
        p = *pp;
        *pp = NULL;

        for (i = 0; i < 5; i++) {
            if (!memcmp(p->dst, &relays[i].ifs[0].addr.linklayer.sll_addr, ETH_ALEN)) {
                break;
            }
        }
        if (i < 5) {
            sockunion sun;

            sun.sa.sa_family = AF_PACKET;
            memcpy(sun.linklayer.sll_addr, p->src, ETH_ALEN);

            DEBUGMSG(DEBUG, "simu_ethernet: sending %d Bytes to %s, (qlen=%d)\n",
                     p->len, ll2ascii(p->dst, 6), qlen);

            ccn_iribu_core_RX(relays + i, 0, (unsigned char*) p->data,
                        p->len, &sun.sa, sizeof(sun.linklayer));
        } else {
            DEBUGMSG(WARNING, "simu_ethernet: dest %s not found\n",
                     ll2ascii(etherqueue->dst, 6));
        }
        ccn_iribu_free(p);
    }
    ccn_iribu_set_timer(2000, ccn_iribu_simu_ethernet, dummy, dummy2);
}

// ----------------------------------------------------------------------
// the two functions called by the CCNL's core and frag code:

int
ccn_iribu_app_RX(struct ccn_iribu_relay_s *ccnl, struct ccn_iribu_content_s *c)
{
    int i;
    char tmp[200], tmp2[10];
    struct ccn_iribu_prefix_s *p = c->pkt->pfx;

    if (theSuite == CCN_IRIBU_SUITE_CCNTLV ) {
        tmp[0] = '\0';
        for (i = 0; i < p->compcnt-1; i++) {
            strcat((char*)tmp, "/");
            tmp[strlen(tmp) + p->complen[i] - 4] = '\0';
            memcpy(tmp + strlen(tmp), p->comp[i]+4, p->complen[i]-4);
        }
        memcpy(tmp2, p->comp[p->compcnt-1]+4, p->complen[p->compcnt-1]-4);
        tmp2[p->complen[p->compcnt-1]-4] = '\0';
    } else {
        tmp[0] = '\0';
        for (i = 0; i < p->compcnt-1; i++) {
            strcat((char*)tmp, "/");
            tmp[strlen(tmp) + p->complen[i]] = '\0';
            memcpy(tmp + strlen(tmp), p->comp[i], p->complen[i]);
        }
        memcpy(tmp2, p->comp[p->compcnt-1], p->complen[p->compcnt-1]);
        tmp2[p->complen[p->compcnt-1]] = '\0';
    }

    DEBUGMSG(INFO, "app delivery at node %c, name=%s%s\n",
             relay2char(ccnl), tmp, tmp2);

    ccn_iribu_simu_client_RX(ccnl, tmp, atoi(tmp2+1),
                       (char*) c->pkt->content, c->pkt->contlen);
    return 0;
}


void
ccn_iribu_ll_TX(struct ccn_iribu_relay_s *relay, struct ccn_iribu_if_s *ifc,
           sockunion *dst, struct ccn_iribu_buf_s *buf)
{
    struct ccn_iribu_ethernet_s *p;
    int cnt;

    for (cnt = 0, p = etherqueue; p; p = p->next, cnt++);

    DEBUGMSG(TRACE, "eth(simu)_ll_TX to %s len=%zd (qlen=%d) [0x%02x 0x%02x]\n",
             ccn_iribu_addr2ascii(dst), buf->datalen, cnt,
             buf->data[0], buf->data[1]);
    DEBUGMSG(TRACE, "  src=%s\n", ccn_iribu_addr2ascii(&ifc->addr));

    p = ccn_iribu_calloc(1, sizeof(*p) + 2*ETH_ALEN + buf->datalen);
    p->dst = (unsigned char*)p + sizeof(*p);
    p->src = (unsigned char*)p + sizeof(*p) + ETH_ALEN;
    p->data = (unsigned char*)p + sizeof(*p) + 2*ETH_ALEN;
    p->len = buf->datalen;
    memcpy(p->dst, dst->linklayer.sll_addr, ETH_ALEN);
    p->protocol = dst->linklayer.sll_protocol;
    memcpy(p->src, ifc->addr.linklayer.sll_addr, ETH_ALEN);
    memcpy(p->data, buf->data, buf->datalen);

    // prepend
    p->next = etherqueue;
    etherqueue = p;
}

int
ccn_iribu_close_socket(int s)
{
    return close(s);
}

// ----------------------------------------------------------------------


void ccn_iribu_simu_cleanup(void *dummy, void *dummy2);
#include "ccn-iribu-simu-client.c"

// ----------------------------------------------------------------------

static int inter_ccn_interval = 0; // in usec
static int inter_packet_interval = 0; // in usec

#ifdef USE_SCHEDULER
struct ccn_iribu_sched_s*
ccn_iribu_simu_defaultFaceScheduler(struct ccn_iribu_relay_s *ccnl,
                                    void(*cb)(void*,void*))
{
    return ccn_iribu_sched_pktrate_new(cb, ccnl, inter_ccn_interval);
}
#endif

void ccn_iribu_ageing(void *relay, void *aux)
{
    ccn_iribu_do_ageing(relay, aux);
    ccn_iribu_set_timer(1000000, ccn_iribu_ageing, relay, 0);
}

void
ccn_iribu_simu_init_node(char node, const char *addr,
                    int max_cache_entries, int mtu)
{
    struct ccn_iribu_relay_s *relay = char2relay(node);
    struct ccn_iribu_if_s *i;

    DEBUGMSG(TRACE, "ccn_iribu_simu_init_node\n");

    relay->id = relay - relays;
    relay->max_cache_entries = node == 'C' ? -1 : max_cache_entries;
    relay->max_pit_entries = CCN_IRIBU_DEFAULT_MAX_PIT_ENTRIES;

    // add (fake) eth0 interface with index 0:
    i = &relay->ifs[0];
    i->addr.linklayer.sll_family = AF_PACKET;
    memcpy(i->addr.linklayer.sll_addr, addr, ETH_ALEN);
    if (mtu)
        i->mtu = mtu;
    else
        i->mtu = 4096;
    i->reflect = 1;
    i->fwdalli = 1;
    relay->ifcount++;

#ifdef USE_SCHEDULER
    i->sched = ccn_iribu_sched_pktrate_new(ccn_iribu_interface_CTS, relay,
                                      inter_packet_interval);
    relay->defaultFaceScheduler = ccn_iribu_simu_defaultFaceScheduler;
#endif

    if (node == 'A' || node == 'B') {

        struct ccn_iribu_client_s *client = ccn_iribu_calloc(1,
                                           sizeof(struct ccn_iribu_client_s));
        client->lastseq = SIMU_NUMBER_OF_CHUNKS-1;
        client->last_received = -1;
        client->name = node == 'A' ?
            "/ccnl/simu/movie1" : "/ccnl/simu/movie2";
        relay->aux = (void *) client;
    }

    ccn_iribu_set_timer(1000000, ccn_iribu_ageing, relay, 0);
}


void
ccn_iribu_simu_add_fwd(char node, const char *name, char dstnode, int mtu)
{
    struct ccn_iribu_relay_s *relay = char2relay(node), *dst = char2relay(dstnode);
    struct ccn_iribu_forward_s *fwd;
    sockunion sun;
    char *cp;

    DEBUGMSG(TRACE, "ccn_iribu_simu_add_fwd\n");

    sun.linklayer.sll_family = AF_PACKET;
    memcpy(sun.linklayer.sll_addr, dst->ifs[0].addr.linklayer.sll_addr, ETH_ALEN);
    fwd = (struct ccn_iribu_forward_s *) ccn_iribu_calloc(1, sizeof(*fwd));
    //    fwd->prefix = ccn_iribu_path_to_prefix(name);
    cp = ccn_iribu_strdup(name);
    fwd->prefix = ccn_iribu_URItoPrefix(cp, theSuite, NULL, NULL);
    ccn_iribu_free(cp);
    fwd->suite = theSuite;
    fwd->face = ccn_iribu_get_face_or_create(relay, 0, &sun.sa, sizeof(sun.linklayer));
#ifdef USE_FRAG
    if (mtu)
        fwd->face->frag = ccn_iribu_frag_new(CCN_IRIBU_FRAG_BEGINEND2015, mtu);
#endif
    fwd->face->flags |= CCN_IRIBU_FACE_FLAGS_STATIC;
    fwd->next = relay->fib;
    relay->fib = fwd;
}


int
ccn_iribu_simu_init(int max_cache_entries, int mtu)
{
    static char dat[SIMU_CHUNK_SIZE];
    static char init_was_visited;
    int i;

    if (init_was_visited)
        return 0;
    init_was_visited = 1;

    DEBUGMSG(TRACE, "ccn_iribu_simu_init\n");

 #ifdef USE_SCHEDULER
    // initialize the scheduling subsystem
    ccn_iribu_sched_init();
#endif

    // define each node's eth address:
    ccn_iribu_simu_init_node('A', "\x00\x00\x00\x00\x00\x0a",
                        max_cache_entries, mtu);
    ccn_iribu_simu_init_node('B', "\x00\x00\x00\x00\x00\x0b",
                        max_cache_entries, mtu);
    ccn_iribu_simu_init_node('C', "\x00\x00\x00\x00\x00\x0c",
                        max_cache_entries, mtu);
    ccn_iribu_simu_init_node('1', "\x00\x00\x00\x00\x00\x01",
                        max_cache_entries, mtu);
    ccn_iribu_simu_init_node('2', "\x00\x00\x00\x00\x00\x02",
                        max_cache_entries, mtu);

    // install the system's forwarding pointers:
    ccn_iribu_simu_add_fwd('A', "/ccnl/simu", '2', mtu);
    ccn_iribu_simu_add_fwd('B', "/ccnl/simu", '2', mtu);
    ccn_iribu_simu_add_fwd('2', "/ccnl/simu", '1', mtu);
    ccn_iribu_simu_add_fwd('1', "/ccnl/simu", 'C', mtu);

/*
    for (i = 0; i < 5; i++)
        ccn_iribu_dump(0, CCN_IRIBU_RELAY, relays+i);
*/

    // turn node 'C' into a repository for three movies
    snprintf(dat, SIMU_CHUNK_SIZE, "%d", (int) sizeof(dat));
    for (i = 0; i < SIMU_NUMBER_OF_CHUNKS; i++) {
        ccn_iribu_simu_add2cache('C', "/ccnl/simu/movie1", i, dat, sizeof(dat));
        ccn_iribu_simu_add2cache('C', "/ccnl/simu/movie2", i, dat, sizeof(dat));
        ccn_iribu_simu_add2cache('C', "/ccnl/simu/movie3", i, dat, sizeof(dat));
    }

    ccn_iribu_set_timer(5000, ccn_iribu_simu_ethernet, 0, 0);

    // start clients:
    ccn_iribu_set_timer( 500000, ccn_iribu_simu_client_start, char2relay('A'), 0);
    ccn_iribu_set_timer(1000000, ccn_iribu_simu_client_start, char2relay('B'), 0);
    phaseOne = 1;

    printf("Press ENTER to start the simulation\n");
    while (getchar() != '\n');

    return 0;
}

void
ccn_iribu_simu_phase_two(void *ptr, void *dummy)
{
    phaseOne = 0;
    ccn_iribu_set_timer(0, ccn_iribu_simu_client_start, char2relay('A'), 0);
    ccn_iribu_set_timer(500000, ccn_iribu_simu_client_start, char2relay('B'), 0);
}


// ----------------------------------------------------------------------

void
simu_eventloop()
{
    static struct timeval now;
    long usec;

    while (eventqueue) {
        struct ccn_iribu_timer_s *t = eventqueue;
        // printf("  looping now %g\n", CCN_IRIBU_NOW());
        gettimeofday(&now, 0);
        usec = timevaldelta(&(t->timeout), &now);
        if (usec >= 0) {
            // usleep(usec);
            struct timespec ts;
            ts.tv_sec = usec / 1000000;
            ts.tv_nsec = 1000 * (usec % 1000000);
            nanosleep(&ts, NULL);
        }
        t = eventqueue;
        eventqueue = t->next;
        if (t->fct) {
            void (*fct)(char,int) = t->fct;
            char c = t->node;
            int i = t->intarg;
            ccn_iribu_free(t);
            (fct)(c, i);
        } else if (t->fct2) {
            void (*fct2)(void*,void*) = t->fct2;
            void *aux1 = t->aux1;
            void *aux2 = t->aux2;
            ccn_iribu_free(t);
            (fct2)(aux1, aux2);
        }
    }
    DEBUGMSG(ERROR, "simu event loop: no more events to handle\n");
}

void
ccn_iribu_simu_cleanup(void *dummy, void *dummy2)
{
    printf("Simulation ended; press ENTER to terminate\n");
    while (getchar() != '\n');

    int i;
    for (i = 0; i < 5; i++) {
        struct ccn_iribu_relay_s *relay = relays + i;

        if (relay->aux) {
            ccn_iribu_free(relay->aux);
            relay->aux = NULL;
        }
        ccn_iribu_core_cleanup(relay);
    }

    while(eventqueue)
        ccn_iribu_rem_timer(eventqueue);

    while(etherqueue) {
        struct ccn_iribu_ethernet_s *e = etherqueue->next;
        ccn_iribu_free(etherqueue);
        etherqueue = e;
    }

#ifdef USE_SCHEDULER
    ccn_iribu_sched_cleanup();
#endif
#ifdef USE_DEBUG_MALLOC
    debug_memdump();
#endif
}

// ----------------------------------------------------------------------

int
main(int argc, char **argv)
{
  int opt, mtu = 0;
    int max_cache_entries = CCN_IRIBU_DEFAULT_MAX_CACHE_ENTRIES;

    //    srand(time(NULL));
    srandom(time(NULL));

    while ((opt = getopt(argc, argv, "hc:g:i:m:s:v:")) != -1) {
        switch (opt) {
        case 'c':
            max_cache_entries = atoi(optarg);
            break;
        case 'g':
            inter_packet_interval = atoi(optarg);
            break;
        case 'i':
            inter_ccn_interval = atoi(optarg);
            break;
        case 'm':
            mtu = atoi(optarg);
            break;
        case 'v':
            if (isdigit(optarg[0]))
                debug_level = atoi(optarg);
            else
                debug_level = ccn_iribu_debug_str2level(optarg);
            break;
        case 's':
            theSuite = ccn_iribu_str2suite(optarg);
            if (theSuite >= 0 && theSuite < CCN_IRIBU_SUITE_LAST)
                break;
        case 'h':
        default:
            fprintf(stderr, "Xusage: %s [-h]\n"
                    "  [-c MAX_CONTENT_ENTRIES]\n"
                    "  [-g MIN_INTER_PACKET_INTERVAL]\n"
                    "  [-i MIN_INTER_CCNMSG_INTERVAL]\n"
                    "  [-m MTU]\n"
                    "  [-s SUITE (ccnb, ccnx2015, ndn2013)]\n"
                    "  [-v DEBUG_LEVEL]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    time(&relays[0].startup_time);

    ccn_iribu_core_init();

    DEBUGMSG(INFO, "This is ccn-lite-simu, starting at %s",
             ctime(&relays[0].startup_time) + 4);
    DEBUGMSG(INFO, "  ccn-iribu-core: %s\n", CCN_IRIBU_VERSION);
    DEBUGMSG(INFO, "  compile time: %s %s\n", __DATE__, __TIME__);
    DEBUGMSG(INFO, "  compile options: %s\n", compile_string);
    DEBUGMSG(INFO, "using suite %s\n", ccn_iribu_suite2str(theSuite));

    ccn_iribu_simu_init(max_cache_entries, mtu);

    DEBUGMSG(INFO, "simulation starts\n");
    simu_eventloop();
    DEBUGMSG(INFO, "simulation ends\n");

    return -1;
}


// eof
