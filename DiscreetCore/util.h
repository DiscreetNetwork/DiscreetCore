
#ifndef UTIL_H
#define UTIL_H

#ifndef def_C99
# if defined(__cplusplus) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#  define def_C99(X)
# else
#  define def_C99(X) X
# endif
#endif

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* following code comes from int-util.h. */
#ifndef _MSC_VER
#include <sys/param.h>
#endif

#if defined(__ANDROID__)
#include <byteswap.h>
#endif

#if defined(__sun) && defined(__SVR4)
#include <endian.h>
#endif

#if defined(_MSC_VER)
#include <stdlib.h>

static inline uint32_t rol32(uint32_t x, int r) {
  static_assert(sizeof(uint32_t) == sizeof(unsigned int), "this code assumes 32-bit integers");
  return _rotl(x, r);
}

static inline uint64_t rol64(uint64_t x, int r) {
  return _rotl64(x, r);
}

#else

static inline uint32_t rol32(uint32_t x, int r) {
  return (x << (r & 31)) | (x >> (-r & 31));
}

static inline uint64_t rol64(uint64_t x, int r) {
  return (x << (r & 63)) | (x >> (-r & 63));
}

#endif

static inline uint64_t hi_dword(uint64_t val) {
  return val >> 32;
}

static inline uint64_t lo_dword(uint64_t val) {
  return val & 0xFFFFFFFF;
}

#define IDENT16(x) ((uint16_t) (x))
#define IDENT32(x) ((uint32_t) (x))
#define IDENT64(x) ((uint64_t) (x))

#define SWAP16(x) ((((uint16_t) (x) & 0x00ff) << 8) | \
  (((uint16_t) (x) & 0xff00) >> 8))
#define SWAP32(x) ((((uint32_t) (x) & 0x000000ff) << 24) | \
  (((uint32_t) (x) & 0x0000ff00) <<  8) | \
  (((uint32_t) (x) & 0x00ff0000) >>  8) | \
  (((uint32_t) (x) & 0xff000000) >> 24))
#define SWAP64(x) ((((uint64_t) (x) & 0x00000000000000ff) << 56) | \
  (((uint64_t) (x) & 0x000000000000ff00) << 40) | \
  (((uint64_t) (x) & 0x0000000000ff0000) << 24) | \
  (((uint64_t) (x) & 0x00000000ff000000) <<  8) | \
  (((uint64_t) (x) & 0x000000ff00000000) >>  8) | \
  (((uint64_t) (x) & 0x0000ff0000000000) >> 24) | \
  (((uint64_t) (x) & 0x00ff000000000000) >> 40) | \
  (((uint64_t) (x) & 0xff00000000000000) >> 56))

static inline uint16_t ident16(uint16_t x) { return x; }
static inline uint32_t ident32(uint32_t x) { return x; }
static inline uint64_t ident64(uint64_t x) { return x; }

#ifndef __OpenBSD__
#  if defined(__ANDROID__) && defined(__swap16) && !defined(swap16)
#      define swap16 __swap16
#  elif !defined(swap16)
static inline uint16_t swap16(uint16_t x) {
  return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
}
#  endif
#  if defined(__ANDROID__) && defined(__swap32) && !defined(swap32)
#      define swap32 __swap32
#  elif !defined(swap32)
static inline uint32_t swap32(uint32_t x) {
  x = ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >> 8);
  return (x << 16) | (x >> 16);
}
#  endif
#  if defined(__ANDROID__) && defined(__swap64) && !defined(swap64)
#      define swap64 __swap64
#  elif !defined(swap64)
static inline uint64_t swap64(uint64_t x) {
  x = ((x & 0x00ff00ff00ff00ff) <<  8) | ((x & 0xff00ff00ff00ff00) >>  8);
  x = ((x & 0x0000ffff0000ffff) << 16) | ((x & 0xffff0000ffff0000) >> 16);
  return (x << 32) | (x >> 32);
}
#  endif
#endif /* __OpenBSD__ */

#if defined(__GNUC__)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif
static inline void mem_inplace_ident(void *mem UNUSED, size_t n UNUSED) { }
#undef UNUSED

static inline void mem_inplace_swap16(void *mem, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    ((uint16_t *) mem)[i] = swap16(((const uint16_t *) mem)[i]);
  }
}
static inline void mem_inplace_swap32(void *mem, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    ((uint32_t *) mem)[i] = swap32(((const uint32_t *) mem)[i]);
  }
}
static inline void mem_inplace_swap64(void *mem, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    ((uint64_t *) mem)[i] = swap64(((const uint64_t *) mem)[i]);
  }
}

static inline void memcpy_ident16(void *dst, const void *src, size_t n) {
  memcpy(dst, src, 2 * n);
}
static inline void memcpy_ident32(void *dst, const void *src, size_t n) {
  memcpy(dst, src, 4 * n);
}
static inline void memcpy_ident64(void *dst, const void *src, size_t n) {
  memcpy(dst, src, 8 * n);
}

static inline void memcpy_swap16(void *dst, const void *src, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    ((uint16_t *) dst)[i] = swap16(((const uint16_t *) src)[i]);
  }
}
static inline void memcpy_swap32(void *dst, const void *src, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    ((uint32_t *) dst)[i] = swap32(((const uint32_t *) src)[i]);
  }
}
static inline void memcpy_swap64(void *dst, const void *src, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    ((uint64_t *) dst)[i] = swap64(((const uint64_t *) src)[i]);
  }
}

#ifdef _MSC_VER
# define LITTLE_ENDIAN	1234
# define BIG_ENDIAN	4321
# define BYTE_ORDER	LITTLE_ENDIAN
#endif

#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
static_assert(false, "BYTE_ORDER is undefined. Perhaps, GNU extensions are not enabled");
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define SWAP16LE IDENT16
#define SWAP16BE SWAP16
#define swap16le ident16
#define swap16be swap16
#define mem_inplace_swap16le mem_inplace_ident
#define mem_inplace_swap16be mem_inplace_swap16
#define memcpy_swap16le memcpy_ident16
#define memcpy_swap16be memcpy_swap16
#define SWAP32LE IDENT32
#define SWAP32BE SWAP32
#define swap32le ident32
#define swap32be swap32
#define mem_inplace_swap32le mem_inplace_ident
#define mem_inplace_swap32be mem_inplace_swap32
#define memcpy_swap32le memcpy_ident32
#define memcpy_swap32be memcpy_swap32
#define SWAP64LE IDENT64
#define SWAP64BE SWAP64
#define swap64le ident64
#define swap64be swap64
#define mem_inplace_swap64le mem_inplace_ident
#define mem_inplace_swap64be mem_inplace_swap64
#define memcpy_swap64le memcpy_ident64
#define memcpy_swap64be memcpy_swap64
#endif

#if BYTE_ORDER == BIG_ENDIAN
#define SWAP16BE IDENT16
#define SWAP16LE SWAP16
#define swap16be ident16
#define swap16le swap16
#define mem_inplace_swap16be mem_inplace_ident
#define mem_inplace_swap16le mem_inplace_swap16
#define memcpy_swap16be memcpy_ident16
#define memcpy_swap16le memcpy_swap16
#define SWAP32BE IDENT32
#define SWAP32LE SWAP32
#define swap32be ident32
#define swap32le swap32
#define mem_inplace_swap32be mem_inplace_ident
#define mem_inplace_swap32le mem_inplace_swap32
#define memcpy_swap32be memcpy_ident32
#define memcpy_swap32le memcpy_swap32
#define SWAP64BE IDENT64
#define SWAP64LE SWAP64
#define swap64be ident64
#define swap64le swap64
#define mem_inplace_swap64be mem_inplace_ident
#define mem_inplace_swap64le mem_inplace_swap64
#define memcpy_swap64be memcpy_ident64
#define memcpy_swap64le memcpy_swap64
#endif

/* end int-util.h */

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

#ifdef ROTL64
#undef ROTL64
#endif
#define ROTL64(X, B) rotl64((X), (B))
static inline uint64_t
rotl64(const uint64_t x, const int b)
{
    return (x << b) | (x >> (64 - b));
}

#define ROTR32(X, B) rotr32((X), (B))
static inline uint32_t
rotr32(const uint32_t x, const int b)
{
    return (x >> b) | (x << (32 - b));
}

#define ROTR64(X, B) rotr64((X), (B))
static inline uint64_t
rotr64(const uint64_t x, const int b)
{
    return (x >> b) | (x << (64 - b));
}

#define LOAD64_LE(SRC) load64_le(SRC)
static inline uint64_t
load64_le(const uint8_t src[8])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] <<  8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
#endif
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] <<  8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

/* ----- */

#define LOAD64_BE(SRC) load64_be(SRC)
static inline uint64_t
load64_be(const uint8_t src[8])
{
#ifdef NATIVE_BIG_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[7];
    w |= (uint64_t) src[6] <<  8;
    w |= (uint64_t) src[5] << 16;
    w |= (uint64_t) src[4] << 24;
    w |= (uint64_t) src[3] << 32;
    w |= (uint64_t) src[2] << 40;
    w |= (uint64_t) src[1] << 48;
    w |= (uint64_t) src[0] << 56;
    return w;
#endif
}

#define STORE64_BE(DST, W) store64_be((DST), (W))
static inline void
store64_be(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[7] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

#define LOAD32_BE(SRC) load32_be(SRC)
static inline uint32_t
load32_be(const uint8_t src[4])
{
#ifdef NATIVE_BIG_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[3];
    w |= (uint32_t) src[2] <<  8;
    w |= (uint32_t) src[1] << 16;
    w |= (uint32_t) src[0] << 24;
    return w;
#endif
}

#define STORE32_BE(DST, W) store32_be((DST), (W))
static inline void
store32_be(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

#define XOR_BUF(OUT, IN, N) xor_buf((OUT), (IN), (N))
static inline void
xor_buf(unsigned char *out, const unsigned char *in, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] ^= in[i];
    }
}

static inline int buf_is_zero(const unsigned char *buf, size_t len)
{
    unsigned int i;
    unsigned char v = 0;

    for (i = 0; i < len; i++) {
        v |= buf[i];
    }

    return v == 0;
}

static inline void buf_memzero(unsigned char *buf, size_t len)
{
    unsigned int i;

    for (i = 0; i < len; i++) {
        buf[i] = 0;
    }
}

static inline int buf_memcmp(const void *const b1_, const void *const b2_, 
                             size_t len)
{
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;

    size_t i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }

    return (1 & ((d - 1) >> 8)) - 1;
}

static inline void buf_add(unsigned char *a, const unsigned char *b, const size_t len)
{
    size_t        i;
    uint_fast16_t c = 0U;

    for (i = 0U; i < len; i++) {
        c += (uint_fast16_t) a[i] + (uint_fast16_t) b[i];
        a[i] = (unsigned char) c;
        c >>= 8;
    }
}

static inline void buf_sub(unsigned char *a, const unsigned char *b, const size_t len)
{
    size_t        i;
    uint_fast16_t c = 0U;

    for (i = 0U; i < len; i++) {
        c = (uint_fast16_t) a[i] - (uint_fast16_t) b[i] - c;
        a[i] = (unsigned char) c;
        c = (c >> 8) & 1U;
    }
}

#endif // UTIL_H