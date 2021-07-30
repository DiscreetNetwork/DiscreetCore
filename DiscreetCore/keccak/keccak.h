#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>

#include "export.h"

#define KECCAK_ROUNDS 24

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif 

#define KECCAK_FINALIZED 0x80000000
#define KECCAK_BLOCKLEN 136
#define KECCAK_WORDS 17
#define KECCAK_DIGESTSIZE 32
#define KECCAK_PROCESS_BLOCK(st, block) { \
    for (int i_ = 0; i_ < KECCAK_WORDS; i_++){ \
        ((st))[i_] ^= swap64le(((block))[i_]); \
    }; \
    keccakf(st, KECCAK_ROUNDS); }

typedef struct keccak_ctx {
    uint64_t st[25]; //1600 bits hashstate
    uint64_t msg[17]; //1088 bits buffer (136 for 256 bit hash)
    unsigned int rest; //count of bytes in msg[]
} keccak_ctx;

// gets KECCAK(in) digest of given byte length.
EXPORT void keccak(const unsigned char *in, unsigned int inlen, unsigned char *digest, unsigned int dlen);
EXPORT void keccakf(uint64_t st[25], int nrounds);
EXPORT void keccak1600(const uint8_t *in, size_t inlen, uint8_t *md);

EXPORT void keccak_init(keccak_ctx *ctx);
EXPORT void keccak_update(keccak_ctx *ctx, const unsigned char *in, unsigned int inlen);
EXPORT void keccak_final(keccak_ctx *ctx, unsigned char *digest);

#endif // KECCAK_H
