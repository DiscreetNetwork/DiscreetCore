/**
 * The following contains a MINIMAL chacha20 implementation 
 * for use with the internal random bytes library.  
 */

#ifndef CHACHA20_H
#define CHACHA20_H

#define rng_chacha20_KEYBYTES 32U
#define rng_chacha20_NONCEBYTES 8U
#define rng_chacha20_MESSAGEBYTES_MAX 0xFFFFFFFF
#define rng_chacha20_OUTPUTBYTES 32U

int rng_chacha20_xor(unsigned char *c, const unsigned char *m,
                     unsigned long long mlen, const unsigned char *n,
                     const unsigned char *k);
int rng_chacha20_stream_ietf_ext(unsigned char *c, unsigned long long clen,
                                 const unsigned char *n, 
                                 const unsigned char *k);
int rng_chacha20(unsigned char *c, unsigned long long clen,
                 const unsigned char *n, const unsigned char *k);

#endif // CHACHA20_H