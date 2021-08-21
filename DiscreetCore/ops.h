#pragma once
#ifndef OPS_H
#define OPS_H

#include <cstddef>
#include <cstring>
#include <tuple>

extern "C" {
#include "crypto.h"
#include "crypto_curve.h"
}

#include "export.h"
#include "types.h"

namespace discore {
    /* Z = zero, I = identity, L = group order, G = generator */
    /* EIGHT and INV_EIGHT are useful for avoding subgroup shenanigans */
    static const key Z = { {0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } };
    static const key I = { {0x01, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } };
    static const key L = { {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 } };
    static const key G = { {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 } };
    static const key EIGHT = { {0x08, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } };
    static const key INV_EIGHT = { { 0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 } };

    inline key zero() {
        return Z;
    }

    inline void zero(key &z) {
        memset(&z, 0, 32);
    }

    inline key identity() {
        return I;
    }

    inline void identity(key &id) {
        memcpy(&id, &I, 32);
    }

    inline key curve_order() {
        return L;
    }

    inline void curve_order(key &l) {
        l = L;
    }

    inline void copy(key &a, const key &b) {
        memcpy(&a, &b, 32);
    }

    inline key copy(const key &a) {
        key b;
        memcpy(&b, &a, 32);
        return b;
    }

    keyM keyM_init(size_t r, size_t c);

    bool topoint_check_order(ge_p3 *p, const unsigned char *data);

    key skgen();
    EXPORT void skgen(key &);
    keyV skvgen(size_t r);
    key pkgen();
    void skpkgen(key &sk, key &pk);
    std::tuple<key, key> skpkgen();


    std::tuple<ctkey, ctkey> ctskpkgen(dis_amount amount);
    void gen_commitment(key &c, const key &a, dis_amount amount);
    std::tuple<ctkey, ctkey> ctskpkgen(const key &mask);
    key commit(dis_amount amount, const key &mask);
    key commit_to_zero(dis_amount amount);
    dis_amount random_dis_amount(dis_amount limit);


    /* ag = a * G (a := curve_scalar, G := group base point) */
    void scalarmult_base(key &ag, const key &a);
    key scalarmult_base(const key &a);
    /* ap = a * P (a := curve_scalar, P := group point) */
    void scalarmult_key(key &ap, const key &p, const key &a);
    key scalarmult_key(const key &p, const key &a);
    /* a * H, where H = topoint(keccak(G)) */
    key scalarmult_h(const key &a);
    /* 8P */
    void scalarmult_8(ge_p3 &res, const key &p);
    key scalarmult_8(const key &p);
    /* checks if a is in the main subgroup */
    bool in_main_subgroup(const key &a);
    

    void add_keys(key &ab, const key &a, const key &b);
    key add_keys(const key &a, const key &b);
    key add_keys(const keyV &a);
    /* agb = aG + b */
    void add_keys1(key &agb, const key &a, const key &b);
    /* agbp = aG + bP */
    void add_keys2(key &agbp, const key &a, const key &b, const key &p);
    /* precomp for add_keys3 */
    void precomp(ge_dsmp rv, const key &b);
    /* apbq = aP + bQ */
    void add_keys3(key &apbq, const key &a, const key &p, const key &b, const ge_dsmp q);
    void add_keys3(key &apbq, const key &a, const ge_dsmp p, const key &b, const ge_dsmp q);
    /* agbpcq = aG + bP + cQ */
    void add_keys4(key &agbpcq, const key &a, const key &b, const ge_dsmp p, const key &c, const ge_dsmp q);
    /* apbqcr = aP + bQ + cR */
    void add_keys5(key &apbqcr, const key &a, const ge_dsmp p, const key &b, const ge_dsmp q, const key &c, const ge_dsmp r);


    /* ab = A - B */
    void sub_keys(key &ab, const key &a, const key &b);
    /* A == B */
    bool equal_keys(const key &a, const key &b);


    /* arbitrary hashing data to l multiples of 32 bytes :) */
    void hash_data(key &hash, const void *data, const size_t l);
    void hash_to_scalar(key &hash, const void *data, const size_t l);
    /* hashing keys */
    void hash_data(key &hash, const key &data);
    void hash_to_scalar(key &hash, const key &data);
    key hash_data(const key &data);
    key hash_to_scalar(const key &data);
    /* hashes for MLSAGs */
    key hash_data128(const void *data);
    key hash_to_scalar128(const void *data);
    key hash_data(const ctkeyV &data);
    key hash_to_scalar(const ctkeyV &data);
    key hash_data(const keyV &data);
    key hash_to_scalar(const keyV &data);
    /* hashing key64 */
    key hash_data(const key64 data);
    key hash_to_scalar(const key64 data);

    void hash_to_p3(ge_p3 &hash8_p3, const key &k);

    /* sums a curve points */
    void sum_keys(key &sum, const key &k);

    /* ECDH: encodes and decodes mask (a) and amount (b) where C = aG + bH */
    key gen_commitment_mask(const key &sk);
    void ecdh_encode(ecdhtuple &unmasked, const key &secret, bool v2);
    void ecdh_decode(ecdhtuple &masked, const key &secret, bool v2);
}

#endif // OPS_H