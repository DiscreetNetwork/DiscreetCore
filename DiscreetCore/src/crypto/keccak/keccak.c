#include <stdio.h>
#include <stdlib.h>

#include "keccak/keccak.h"
#include "util.h"

// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// A baseline Keccak (3rd round) implementation
// code modified by Brandon Koerner (brandon@getdiscreet.org)

const uint64_t keccakf_rndc[24] = 
{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

const int keccakf_rotc[24] =
{
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

const int keccakf_piln[24] =
{
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

void keccakf(uint64_t st[25], int nrounds) {
    int i, j, round;
    uint64_t t, bc[5];

    for (round = 0; round < nrounds; round++) {
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }

            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        st[0] ^= keccakf_rndc[round];
    }
}

void keccak(const unsigned char *in, unsigned int inlen, 
            unsigned char *digest, unsigned int dlen) {
    uint64_t st[25];
    unsigned char tmp[144];
    unsigned int i, rsiz, rsizw;

    if (dlen <= 0 || (dlen > 100 && sizeof(st) != dlen)) {
        fprintf(stderr, "%s\n", "Bad keccak preconditions");
        abort();
    }

    rsiz = sizeof(unsigned int) == dlen ? 136 : 200 - 2 * dlen;
    rsizw = rsiz / 8;

    memset(st, 0, sizeof(st));

    for (; inlen > rsiz; inlen -= rsiz, in += rsiz) {
        for (i = 0; i < rsizw; i++) {
            uint64_t ind;
            memcpy(&ind, in + i * 8, 8);
            st[i] ^= swap64le(ind);
        }

        keccakf(st, KECCAK_ROUNDS);
    }

    if (inlen + 1 >= sizeof(tmp) 
        || inlen > rsiz || rsiz - inlen + inlen + 1 >= sizeof(tmp) 
        || rsiz == 0 || rsiz - 1 >= sizeof(tmp) 
        || rsizw * 8 > sizeof(tmp))
    {
        fprintf(stderr, "%s\n", "Bad keccak use");
        abort();
    }

    if (inlen > 0) {
        memcpy(tmp, in, inlen);
    }

    tmp[inlen++] = 1;
    memset(tmp + inlen, 0, rsiz - inlen);
    tmp[rsiz - 1] |= 0x80;

    for (i = 0; i < rsizw; i++) {
        st[i] ^= swap64le(((uint64_t *) tmp)[i]);
    }

    keccakf(st, KECCAK_ROUNDS);

    if ((dlen % sizeof(uint64_t)) != 0) {
        fprintf(stderr, "%s\n", "Bad keccak use");
        abort();
    }

    memcpy_swap64le(digest, st, dlen/sizeof(uint64_t));
}

void keccak1600(const uint8_t *in, size_t inlen, uint8_t *md)
{
    keccak(in, inlen, md, sizeof(uint64_t[25]));
}

void keccak_init(keccak_ctx *ctx) {
    memset(ctx, 0, sizeof(keccak_ctx));
}

void keccak_update(keccak_ctx *ctx, const unsigned char *in, unsigned int inlen) {
    if (ctx->rest & KECCAK_FINALIZED) {
        fprintf(stderr, "%s\n", "Bad keccak use");
        abort();
    }

    const unsigned int idx = ctx->rest;
    ctx->rest = (ctx->rest + inlen) % KECCAK_BLOCKLEN;

    if (idx) {
        unsigned int left = KECCAK_BLOCKLEN - idx;
        memcpy((char*)ctx->msg + idx, in, (inlen < left ? inlen : left));

        if (inlen < left) {
            return;
        }

        KECCAK_PROCESS_BLOCK(ctx->st, ctx->msg);

        in += left;
        inlen -= left;
    }

    while (inlen >= KECCAK_BLOCKLEN) {
        memcpy(ctx->msg, in, KECCAK_BLOCKLEN);

        KECCAK_PROCESS_BLOCK(ctx->st, ctx->msg);

        in += KECCAK_BLOCKLEN;
        inlen -= KECCAK_BLOCKLEN;
    }

    if (inlen) {
        memcpy(ctx->msg, in, inlen);
    }
}

void keccak_final(keccak_ctx *ctx, unsigned char *digest) {
    if (!(ctx->rest & KECCAK_FINALIZED)) {
        memset((char*)ctx->msg + ctx->rest, 0, KECCAK_BLOCKLEN- ctx->rest);
        ((char*)ctx->msg)[ctx->rest] |= 0x01;
        ((char*)ctx->msg)[KECCAK_BLOCKLEN - 1] |= 0x80;

        KECCAK_PROCESS_BLOCK(ctx->st, ctx->msg);
        ctx->rest = KECCAK_FINALIZED;
    }

    if (digest) {
        memcpy_swap64le(digest, ctx->st, KECCAK_DIGESTSIZE / sizeof(uint64_t));
    }
}
