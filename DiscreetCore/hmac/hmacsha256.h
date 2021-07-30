#ifndef HMACSHA256_H
#define HMACSHA256_H

#include <stddef.h>
#include "sha/sha256.h"

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define hmacsha256_BYTES 32U

size_t hmacsha256_bytes(void);

#define hmacsha256_KEYBYTES 32U

size_t hmacsha256_keybytes(void);


int hmacsha256(unsigned char *out, const unsigned char *in,
               unsigned long long inlen, const unsigned char *k);


int hmacsha256_verify(const unsigned char *h, const unsigned char *in,
                      unsigned long long inlen, const unsigned char *k);

typedef struct hmacsha256_ctx {
    sha256_ctx ictx;
    sha256_ctx octx;
} hmacsha256_ctx;


size_t hmacsha256_ctxbytes(void);


int hmacsha256_init(hmacsha256_ctx *state,
                    const unsigned char *key, size_t keylen);
int hmacsha256_update(hmacsha256_ctx *state,
                      const unsigned char *in,
                      unsigned long long inlen);
int hmacsha256_final(hmacsha256_ctx *state, unsigned char *out);
void hmacsha256_keygen(unsigned char k[hmacsha256_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif // HMACSHA256_H