#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#define SIG_C(x) (&x[0])
#define SIG_R(x) (&x[32])

/* all functions to export will be in here. */
typedef unsigned char curve_point[32];

typedef unsigned char curve_scalar[32];


/* 63..32 = r, 31..0 = c */
typedef unsigned char schnorr_sig[64];

typedef curve_point pubkey;
typedef curve_scalar seckey;

extern const pubkey null_pubkey;
extern const seckey null_seckey;

void hash_op(const void *data, size_t length, unsigned char *hash);
void generate_random_bytes_UNSAFE(uint8_t *bytes, size_t n);
void generate_random_bytes_thread_safe(uint8_t *bytes, size_t n);
void random32(unsigned char *bytes);
void hash_to_scalar(const void *data, size_t length, curve_scalar result);
void generate_keypair(pubkey pub, seckey sec);
void generate_keypair_recovery(pubkey pub, seckey sec, const seckey recovery_key);
void generate_keys(pubkey pub, seckey sec, const seckey recovery_key, bool recover);
bool check_key(const pubkey key);
bool secret_key_to_public_key(const seckey sec, pubkey pub);

void generate_signature(const unsigned char *hash, const pubkey pub,
                        const seckey sec, schnorr_sig sig);
bool check_signature(const unsigned char *hash, const pubkey pub, const schnorr_sig sig);
#endif // CRYPTO_H