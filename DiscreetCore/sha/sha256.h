/**
 * Filename:    sha256.h
 * Author:      Brandon Koerner (brandon@getdiscreet.org)
 * Disclaimer:  Code is presented "as is" without guarantees.
 * Details:     Defines SHA256 implementation for Discreet.
 * 
 * Protected under GNU general public license v3.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

/* CONSTANTS */
#define SHA256_BLOCK_SIZE 64            // SHA256 uses a 64 byte block
#define SHA256_DIGEST_SIZE 32           // SHA256 uses 32 bytes for digest

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* context */
typedef struct {
    unsigned int count;
    unsigned char buf[SHA256_BLOCK_SIZE];
    uint32_t s[8];
} sha256_ctx;

// Depracated for now. 
/* hash algos */
enum sha256_opt {
    SHA256_4WAY,            // parallel SSE2
    SHA256_SSE2_32,         // SSE2 for x86_32
    SHA256_SSE2_64,         // SSE2 for x86_64
    SHA256_SSE4_64,         // SSE4 for x86_64
    SHA256_INTEL_EXT,       // Intel SHA-256 extension
    SHA256_GENERIC,         // portable version
};

// Also depracated for now.
/* api */
typedef struct {
    enum sha256_opt opt;
    void (*sha256)(const unsigned char*, unsigned int, unsigned char*);
} sha256_api;

/* generic algorithm is automatically provided */
int sha256_init(sha256_ctx *state);
int sha256_update(sha256_ctx *state, const unsigned char *in, unsigned long long inlen);
int sha256_final(sha256_ctx *state, unsigned char *out);
int sha256(unsigned char *out, const unsigned char *in, unsigned long long len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SHA256_H