/**
 * Filename:    sha512.h
 * Author:      Brandon Koerner (brandon@getdiscreet.org)
 * Disclaimer:  Code is presented "as is" without guarantees.
 * Details:     Defines SHA512 implementation for Discreet.
 * 
 * Protected under GNU general public license v3.
 */

#ifndef SHA512_H
#define SHA512_H


#include <stddef.h>
#include <stdint.h>

#include "export.h"

/* CONSTANTS */
#define SHA512_BLOCK_SIZE 128           // SHA512 uses a 128 byte block
#define SHA512_DIGEST_SIZE 64           // SHA512 uses 64 bytes for digest

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* context */
typedef struct {
    uint64_t count[2];
    unsigned char buf[SHA512_BLOCK_SIZE];
    uint64_t s[8];
} sha512_ctx;

EXPORT int sha512_init(sha512_ctx *state);
EXPORT int sha512_update(sha512_ctx *state, const unsigned char *in, unsigned long long inlen);
EXPORT int sha512_final(sha512_ctx *state, unsigned char *out);
EXPORT int sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SHA512_H