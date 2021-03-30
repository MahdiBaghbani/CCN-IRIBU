#ifndef CCN_IRIBU_CCN_IRIBU_PEEK_H
#define CCN_IRIBU_CCN_IRIBU_PEEK_H

#include "ccn-iribu-common.h"
#include <unistd.h>
#ifndef assert
#    define assert(...) \
        do {            \
        } while (0)
#endif

struct peek_output {
    unsigned char *data;
    int data_length;
};

struct peek_output *ccn_iribu_peek(char *uri, char *udp, char *ux,
                                   unsigned int chunk_number, float wait);

#endif    // CCN_IRIBU_CCN_IRIBU_PEEK_H
