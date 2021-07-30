#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hmac/hmacsha512.h"
#include "sha/sha512.h"
#include "verify.h"
#include "random/random.h"
#include "util.h"

size_t hmacsha512_bytes(void)
{
    return hmacsha512_BYTES;
}

size_t hmacsha512_keybytes(void)
{
    return hmacsha512_KEYBYTES;
}

size_t hmacsha512_ctxbytes(void)
{
    return sizeof(hmacsha512_ctx);
}

void hmacsha512_keygen(unsigned char k[hmacsha512_KEYBYTES])
{
    generate_randombytes(hmacsha512_KEYBYTES, k);
}

int hmacsha512_init(hmacsha512_ctx *state,
                    const unsigned char *key, size_t keylen)
{
    unsigned char pad[128];
    unsigned char khash[64];
    size_t i;

    if (keylen > 128) {
        sha512_init(&state->ictx);
        sha512_update(&state->ictx, key, keylen);
        sha512_final(&state->ictx, khash);
        key    = khash;
        keylen = 64;
    }
    sha512_init(&state->ictx);
    memset(pad, 0x36, 128);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    sha512_update(&state->ictx, pad, 128);

    sha512_init(&state->octx);
    memset(pad, 0x5c, 128);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    sha512_update(&state->octx, pad, 128);

    buf_memzero((unsigned char *) pad, sizeof pad);
    buf_memzero((unsigned char *) khash, sizeof khash);

    return 0;
}

int hmacsha512_update(hmacsha512_ctx *state,
                      const unsigned char *in, unsigned long long inlen)
{
    sha512_update(&state->ictx, in, inlen);

    return 0;
}

int hmacsha512_final(hmacsha512_ctx *state, unsigned char *out)
{
    unsigned char ihash[64];

    sha512_final(&state->ictx, ihash);
    sha512_update(&state->octx, ihash, 64);
    sha512_final(&state->octx, out);

    buf_memzero((unsigned char *) ihash, sizeof ihash);

    return 0;
}

int hmacsha512(unsigned char *out, const unsigned char *in,
               unsigned long long inlen, const unsigned char *k)
{
    hmacsha512_ctx state;

    hmacsha512_init(&state, k, hmacsha512_KEYBYTES);
    hmacsha512_update(&state, in, inlen);
    hmacsha512_final(&state, out);

    return 0;
}

int hmacsha512_verify(const unsigned char *h, const unsigned char *in,
                      unsigned long long inlen, const unsigned char *k)
{
    unsigned char correct[64];

    hmacsha512(correct, in, inlen, k);

    return crypto_verify_64(h, correct) | (-(h == correct)) |
           buf_memcmp(correct, h, 64);
}