#ifndef HMACSHA512_H
#define HMACSHA512_H

#include <stddef.h>
#include "sha/sha512.h"

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define hmacsha512_BYTES 64U

EXPORT size_t hmacsha512_bytes(void);

#define hmacsha512_KEYBYTES 64U

EXPORT size_t hmacsha512_keybytes(void);


EXPORT int hmacsha512(unsigned char *out, const unsigned char *in,
               unsigned long long inlen, const unsigned char *k);


EXPORT int hmacsha512_verify(const unsigned char *h, const unsigned char *in,
                      unsigned long long inlen, const unsigned char *k);

typedef struct hmacsha512_ctx {
    sha512_ctx ictx;
    sha512_ctx octx;
} hmacsha512_ctx;


EXPORT size_t hmacsha512_ctxbytes(void);


EXPORT int hmacsha512_init(hmacsha512_ctx *state,
                    const unsigned char *key, size_t keylen);
EXPORT int hmacsha512_update(hmacsha512_ctx *state,
                      const unsigned char *in,
                      unsigned long long inlen);
EXPORT int hmacsha512_final(hmacsha512_ctx *state, unsigned char *out);
EXPORT void hmacsha512_keygen(unsigned char k[hmacsha512_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif // HMACSHA512_H