#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hmac/hmacsha256.h"
#include "sha/sha256.h"
#include "verify.h"
#include "random/random.h"
#include "util.h"

size_t hmacsha256_bytes(void)
{
    return hmacsha256_BYTES;
}

size_t hmacsha256_keybytes(void)
{
    return hmacsha256_KEYBYTES;
}

size_t hmacsha256_ctxbytes(void)
{
    return sizeof(hmacsha256_ctx);
}

void hmacsha256_keygen(unsigned char k[hmacsha256_KEYBYTES])
{
    generate_randombytes(hmacsha256_KEYBYTES, k);
}

int hmacsha256_init(hmacsha256_ctx *state,
                    const unsigned char *key, size_t keylen)
{
    unsigned char pad[64];
    unsigned char khash[32];
    size_t i;

    if (keylen > 64) {
        sha256_init(&state->ictx);
        sha256_update(&state->ictx, key, keylen);
        sha256_final(&state->ictx, khash);
        key    = khash;
        keylen = 32;
    }
    sha256_init(&state->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    sha256_update(&state->ictx, pad, 64);

    sha256_init(&state->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    sha256_update(&state->octx, pad, 64);

    buf_memzero((unsigned char *) pad, sizeof pad);
    buf_memzero((unsigned char *) khash, sizeof khash);

    return 0;
}

int hmacsha256_update(hmacsha256_ctx *state,
                      const unsigned char *in, unsigned long long inlen)
{
    sha256_update(&state->ictx, in, inlen);

    return 0;
}

int hmacsha256_final(hmacsha256_ctx *state, unsigned char *out)
{
    unsigned char ihash[32];

    sha256_final(&state->ictx, ihash);
    sha256_update(&state->octx, ihash, 32);
    sha256_final(&state->octx, out);

    buf_memzero((unsigned char *) ihash, sizeof ihash);

    return 0;
}

int hmacsha256(unsigned char *out, const unsigned char *in,
               unsigned long long inlen, const unsigned char *k)
{
    hmacsha256_ctx state;

    hmacsha256_init(&state, k, hmacsha256_KEYBYTES);
    hmacsha256_update(&state, in, inlen);
    hmacsha256_final(&state, out);

    return 0;
}

int hmacsha256_verify(const unsigned char *h, const unsigned char *in,
                      unsigned long long inlen, const unsigned char *k)
{
    unsigned char correct[32];

    hmacsha256(correct, in, inlen, k);

    return crypto_verify_32(h, correct) | (-(h == correct)) |
           buf_memcmp(correct, h, 32);
}