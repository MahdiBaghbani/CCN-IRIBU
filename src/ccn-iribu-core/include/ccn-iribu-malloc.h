/**
 * @addtogroup CCNL-core
 * @{
 *
 * @file ccn-iribu-malloc.h
 * @brief Malloc (re-)definition of CCN-lite
 *
 * Copyright (C) 2011-18, University of Basel
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
 */
#ifndef CCN_IRIBU_MALLOC_H
#define CCN_IRIBU_MALLOC_H

#ifndef CCN_IRIBU_LINUXKERNEL
#include <stdlib.h>
#include <string.h>
#include "ccn-iribu-os-time.h"
#endif //CCN_IRIBU_LINUXKERNEL


#ifdef USE_DEBUG_MALLOC
struct mhdr {
    struct mhdr *next;
    char *fname;
    int lineno;
    size_t size;
#ifdef CCN_IRIBU_ARDUINO
    double tstamp;
#else
    char *tstamp; // Linux kernel (no double), also used for CCN_IRIBU_UNIX
#endif // CCN_IRIBU_ARDUINO
} *mem;
#endif // USE_DEBUG_MALLOC


#ifdef USE_DEBUG_MALLOC

void *debug_realloc(void *p, size_t s, const char *fn, int lno);
void debug_free(void *p, const char *fn, int lno);

#ifdef CCN_IRIBU_ARDUINO
void*
debug_malloc(size_t num, size_t size, const char *fn, int lno, double tstamp);
void*
debug_calloc(size_t num, size_t size, const char *fn, int lno, double tstamp);
void*
debug_strdup(const char *s, const char *fn, int lno, double tstamp);

#  define ccn_iribu_malloc(s)        debug_malloc(s, PSTR(__FILE__), __LINE__, CCN_IRIBU_NOW())
#  define ccn_iribu_calloc(n,s)      debug_calloc(n, s, PSTR(__FILE__), __LINE__, CCN_IRIBU_NOW())
#  define ccn_iribu_realloc(p,s)     debug_realloc(p, s, PSTR(__FILE__), __LINE__)
#  define ccn_iribu_strdup(s)        debug_strdup(s, PSTR(__FILE__), __LINE__, CCN_IRIBU_NOW())
#  define ccn_iribu_free(p)          debug_free(p, PSTR(__FILE__), __LINE__)

#else 
void*
debug_malloc(size_t s, const char *fn, int lno, char *tstamp);
void* 
debug_calloc(size_t num, size_t size, const char *fn, int lno, char *tstamp);
void*
debug_strdup(const char *s, const char *fn, int lno, char *tstamp);

#  define ccn_iribu_malloc(s)        debug_malloc(s, __FILE__, __LINE__,timestamp())
#  define ccn_iribu_calloc(n,s)      debug_calloc(n, s, __FILE__, __LINE__,timestamp())
#  define ccn_iribu_realloc(p,s)     debug_realloc(p, s, __FILE__, __LINE__)
#  define ccn_iribu_strdup(s)        debug_strdup(s, __FILE__, __LINE__,timestamp())
#  define ccn_iribu_free(p)          debug_free(p, __FILE__, __LINE__)

#endif // CCN_IRIBU_ARDUINO

#else // !USE_DEBUG_MALLOC


# ifndef CCN_IRIBU_LINUXKERNEL
#  define ccn_iribu_malloc(s)        malloc(s)
    #ifdef __linux__ 
    char* strdup(const char* str);// {
    //    return strcpy( ccn_iribu_malloc( strlen(str)+1), str );
    //}
    #endif
#  define ccn_iribu_calloc(n,s)      calloc(n,s)
#  define ccn_iribu_realloc(p,s)     realloc(p,s)
#  define ccn_iribu_strdup(s)        strdup(s)
#  define ccn_iribu_free(p)          free(p)
# endif

#endif// USE_DEBUG_MALLOC

#ifdef CCN_IRIBU_LINUXKERNEL


/**
 * @brief Allocates a block of size bytes of memory, returning a pointer to the beginning of the block.
 *
 * @param[in] size Size of the memory block, in bytes
 *
 * @return Upon failure, the function returns NULL
 * @return Upon success, a pointer to the memory block allocated by the function
 */
/*
static inline void*
ccn_iribu_malloc(size_t s);

static inline void*
ccn_iribu_calloc(size_t num, size_t size);

static inline void
ccn_iribu_free(void *ptr);*/
#endif

#endif 
/** @} */
