#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>

#define RIPEMD160_DIGEST_SIZE 20
#define BLOCK_SIZE 64

typedef struct {
  uint64_t length;
  union {
    uint32_t w[16];
    uint8_t  b[64];
  } buf;
  uint32_t h[5];
  uint8_t bufpos;
} ripemd160_ctx;

void ripemd160_init(ripemd160_ctx * md);
void ripemd160_update(ripemd160_ctx *self, const unsigned char *p, unsigned long length);
void ripemd160_final(ripemd160_ctx *self, unsigned char *out);
void ripemd160(const void *in, unsigned long inlen, void *out);

#endif // RIPEMD160_H