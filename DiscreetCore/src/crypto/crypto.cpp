#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>

extern "C" {
#include "random/random.h"
#include "sha/sha256.h"
#include "crypto_curve.h"
}

#include "crypto.h"

const pubkey null_pubkey = {0};
const seckey null_seckey = {0};

void hash_op(const void *data, unsigned int length, unsigned char *hash)
{
    sha256(hash, (const unsigned char*)data, length);
}

/* NOTE: random function here is not thread safe. */
void generate_random_bytes_UNSAFE(uint8_t *bytes, unsigned int n)
{
    generate_randombytes(n, bytes);
}

boost::mutex& get_random_lock() {
    static boost::mutex random_lock;
    return random_lock;
}

void generate_random_bytes_thread_safe(uint8_t *bytes, unsigned int n)
{
    boost::lock_guard<boost::mutex> lock(get_random_lock());
    generate_randombytes(n, bytes);
}

static inline bool less32(const uint8_t *a, const uint8_t *b)
{
    int n;
    for (n = 31; n >= 0; n--)
    {
        if (a[n] == b[n]) continue;
        return a[n] < b[n];
    }

    return false;
}

void random32(unsigned char *bytes)
{
    // l = 2^252 + 27742317777372353535851937790883648493.
    // l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
    static const unsigned char limit[32] = { 0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0 };

    for(;;) {
        generate_random_bytes_thread_safe(bytes, 32);

        if (!less32(bytes, limit))
            continue;
        sc_reduce32(bytes);

        if (sc_isnonzero(bytes))
            break;
    }
}

static inline void sc_random(curve_scalar result)
{
    random32(result);
}

void hash_to_scalar(const void *data, unsigned int length, curve_scalar result)
{
    hash_op(data, length, result);
    sc_reduce32(result);
}

void generate_keypair(pubkey pub, seckey sec)
{
    ge_p3 point;

    sc_random(sec);
    sc_reduce32(sec);

    ge_scalarmult_base(&point, sec);
    ge_p3_tobytes(pub, &point);
}

void generate_keypair_recovery(pubkey pub, seckey sec, const seckey recovery_key)
{
    ge_p3 point;

    memcpy(sec, recovery_key, 32);
    sc_reduce32(sec);

    ge_scalarmult_base(&point, sec);
    ge_p3_tobytes(pub, &point);
}

void generate_keys(pubkey pub, seckey sec, const seckey recovery_key, bool recover)
{
    if (recover) {
        generate_keypair_recovery(pub, sec, recovery_key);
    }
    else {
        generate_keypair(pub, sec);
    }
}

bool check_key(const pubkey key)
{
    ge_p3 point;
    return ge_frombytes_vartime(&point, key) == 0;
}

bool secret_key_to_public_key(const seckey sec, pubkey pub)
{
    ge_p3 point;

    if (sc_check(sec) != 0) {
        return false;
    }

    ge_scalarmult_base(&point, sec);
    ge_p3_tobytes(pub, &point);

    return true;
}

void generate_signature(const unsigned char *hash, const pubkey pub,
                        const seckey sec, schnorr_sig sig)
{
    ge_p3 tmp3;
    curve_scalar k;
    unsigned char buf[96];

    memcpy(&buf[0], hash, 32);
    memcpy(&buf[32], pub, 32);

oncemore:
    sc_random(k);

    ge_scalarmult_base(&tmp3, k);
    ge_p3_tobytes(&buf[64], &tmp3);

    hash_to_scalar(buf, 96, SIG_C(sig));
    if (!sc_isnonzero(SIG_C(sig))) 
        goto oncemore;
    sc_mulsub(SIG_R(sig), SIG_C(sig), sec, k);

    if (!sc_isnonzero(SIG_R(sig)))
        goto oncemore;

    /* cleanup */
    memset(k, 0, 32);
}

bool check_signature(const unsigned char *hash, const pubkey pub, const schnorr_sig sig)
{
    ge_p2 tmp2;
    ge_p3 tmp3;
    curve_scalar c;
    unsigned char buf[96];

    assert(check_key(pub));

    memcpy(&buf[0], hash, 32);
    memcpy(&buf[32], pub, 32);

    if (ge_frombytes_vartime(&tmp3, pub) != 0) {
        return false;
    }

    if (sc_check(SIG_C(sig)) != 0 || sc_check(SIG_R(sig)) != 0 || !sc_isnonzero(SIG_C(sig))) {
        return false;
    }

    ge_double_scalarmult_base_vartime(&tmp2, SIG_C(sig), &tmp3, SIG_R(sig));
    ge_tobytes(&buf[64], &tmp2);

    static const curve_point infinity = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (memcmp(&buf[64], infinity, 32) == 0) {
        return false;
    }

    hash_to_scalar(buf, 96, c);
    sc_sub(c, c, SIG_C(sig));
    return sc_isnonzero(c) == 0;
}
