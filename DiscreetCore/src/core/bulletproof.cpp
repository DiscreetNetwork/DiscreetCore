#include <cstdlib>
//#include <thread>
//#include <mutex>

#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>

extern "C" {
#include "crypto_curve.h"
} 

#include "bulletproof.h"
#include "multiexp.h"
#include "ops.h"
#include "types.h"

#include "util/span.h"
#include "util/varint.h"


#define STRAUS_SIZE_LIMIT 232
#define PIPPENGER_SIZE_LIMIT 0

namespace discore {
    static key vector_exponent(const keyV &a, const keyV &b);
    static keyV vector_powers(const key &x, size_t n);
    static keyV vector_dup(const key &x, size_t n);
    static key inner_product(const keyV &a, const keyV &b);

    static constexpr size_t maxN = 64;
    static constexpr size_t maxM = BULLETPROOF_MAX_OUTPUTS;

    static key Hi[maxN*maxM], Gi[maxN*maxM];
    static ge_p3 Hi_p3[maxN*maxM], Gi_p3[maxN*maxM];

    static std::shared_ptr<straus_cache> straus_HiGi_cache;
    static std::shared_ptr<pippenger_cache> pippenger_HiGi_cache;

    static const key TWO = { {0x02, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } };
    static const key MINUS_ONE = { { 0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 } };
    static const key MINUS_INV_EIGHT = { { 0x74, 0xa4, 0x19, 0x7a, 0xf0, 0x7d, 0x0b, 0xf7, 0x05, 0xc2, 0xda, 0x25, 0x2b, 0x5c, 0x0b, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a } };

    static const keyV oneN = vector_dup(identity(), maxN);
    static const keyV twoN = vector_powers(TWO, maxN);
    static const key ip12 = inner_product(oneN, twoN);


    static boost::mutex init_mutex;


    static inline key multiexp(const std::vector<multiexp_data> &data, size_t HiGi_size)
    {
        if (HiGi_size > 0) {
            static_assert(232 <= STRAUS_SIZE_LIMIT, "straus in precalculation mode must be under limit STRAUS_SIZE_LIMIT");
            return HiGi_size <= 232 && data.size() == HiGi_size ? straus(data, straus_HiGi_cache, 0) : pippenger(data, pippenger_HiGi_cache, HiGi_size, get_pippenger_c(data.size()));
        }
        else {
            return data.size() <= 95 ? straus(data, NULL, 0) : pippenger(data, NULL, 0, get_pippenger_c(data.size()));
        }
    }

    static inline bool is_reduced(const key &scalar)
    {
        return sc_check(scalar.bytes) == 0;
    }

    static key get_exponent(const key &base, size_t idx)
    {
        static const std::string domain_separator("bulletproof");
        std::string hashed = std::string((const char*)base.bytes, sizeof(base)) + domain_separator + tools::get_varint_data(idx);
        key e;
        ge_p3 e_p3;
        key h;

        hash_data(h, hashed.data(), hashed.size());
        hash_to_p3(e_p3, h);
        ge_p3_tobytes(e.bytes, &e_p3);
        CHECK_THROW_ERR(!(e == identity()), "Exponent is point at infinity");
        return e;
    }

    static void init_exponents()
    {
        boost::lock_guard<boost::mutex> lock(init_mutex);

        static bool init_done = false;

        if (init_done) {
            return;
        }

        std::vector<multiexp_data> data;
        data.reserve(maxN*maxM*2);

        for (size_t i = 0; i < maxN*maxM; i++) {
            Hi[i] = get_exponent(H, i * 2);
            CHECK_THROW_ERR(ge_frombytes_vartime(&Hi_p3[i], Hi[i].bytes) == 0, "ge_frombytes_vartime failed (init_exponents)");
            Gi[i] = get_exponent(H, i * 2 + 1);
            CHECK_THROW_ERR(ge_frombytes_vartime(&Gi_p3[i], Gi[i].bytes) == 0, "ge_frombytes_vartime failed (init_exponents)");
        
            data.push_back({zero(), Gi_p3[i]});
            data.push_back({zero(), Hi_p3[i]});
        }

        straus_HiGi_cache = straus_init(data, STRAUS_SIZE_LIMIT);
        pippenger_HiGi_cache = pippenger_init(data, 0, PIPPENGER_SIZE_LIMIT);

        size_t cache_size = (sizeof(Hi)+sizeof(Hi_p3))*2 + straus_get_cache_size(straus_HiGi_cache) + pippenger_get_cache_size(pippenger_HiGi_cache);

        init_done = true;
    }

    static key vector_exponent(const keyV &a, const keyV &b) 
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b (vector_exponent)");
        CHECK_THROW_ERR(a.size() <= maxN*maxM, "Incompatible sizes of a and maxN (vector_exponent)");

        std::vector<multiexp_data> multiexpdata;
        multiexpdata.reserve(a.size()*2);

        for (size_t i = 0; i < a.size(); i++) {
            multiexpdata.emplace_back(a[i], Gi_p3[i]);
            multiexpdata.emplace_back(b[i], Hi_p3[i]);
        }

        return multiexp(multiexpdata, 2*a.size());
    }

    static key cross_vector_exponent8(size_t size, const std::vector<ge_p3> &A, size_t Ao, const std::vector<ge_p3> &B, size_t Bo, const keyV &a, size_t ao, const keyV &b, size_t bo, const keyV *scale, const ge_p3 *extra_point, const key *extra_scalar)
    {
        CHECK_THROW_ERR(size + Ao <= A.size(), "Incompatible size for A (cross_vector_exponent8)");
        CHECK_THROW_ERR(size + Bo <= B.size(), "Incompatible size for B (cross_vector_exponent8)");
        CHECK_THROW_ERR(size + ao <= a.size(), "Incompatible size for a (cross_vector_exponent8)");
        CHECK_THROW_ERR(size + bo <= b.size(), "Incompatible size for b (cross_vector_exponent8)");
        CHECK_THROW_ERR(size <= maxN*maxM, "size is too large (cross_vector_exponent8)");
        CHECK_THROW_ERR(!scale || size == scale->size() / 2, "Incompatible size for scale (cross_vector_exponent8)");
        CHECK_THROW_ERR(!!extra_point == !!extra_scalar, "only one of extra point/scalar present (cross_vector_exponent8)");

        std::vector<multiexp_data> data;
        data.resize(size*2 + (!!extra_point));

        for (size_t i = 0; i < size; i++) {
            sc_mul(data[i*2].scalar.bytes, a[ao+i].bytes, INV_EIGHT.bytes);
            data[i*2].point = A[Ao+i];
            sc_mul(data[i*2+1].scalar.bytes, b[bo+i].bytes, INV_EIGHT.bytes);

            if (scale) {
                sc_mul(data[i*2+1].scalar.bytes, data[i*2+1].scalar.bytes, (*scale)[Bo+i].bytes);
            }

            data[i*2+1].point = B[Bo+i];
        }

        if (extra_point) {
            sc_mul(data.back().scalar.bytes, extra_scalar->bytes, INV_EIGHT.bytes);
            data.back().point = *extra_point;
        }

        return multiexp(data, 0);
    }

    static keyV vector_powers(const key &x, size_t n)
    {
        keyV res(n);

        if (n == 0) {
            return res;
        }

        res[0] = identity();

        if (n == 1) {
            return res;
        }

        res[1] = x;

        for (size_t i = 2; i < n; i++) {
            sc_mul(res[i].bytes, res[i-1].bytes, x.bytes);
        }

        return res;
    }

    static key vector_power_sum(key x, size_t n)
    {
        if (n == 0) {
            return zero();
        }
        
        key res = identity();

        if (n == 1) {
            return res;
        }

        const bool is_power_of_2 = (n & (n - 1)) == 0;

        if (is_power_of_2) {
            sc_add(res.bytes, res.bytes, x.bytes);

            while (n > 2) {
                sc_mul(x.bytes, x.bytes, x.bytes);
                sc_muladd(res.bytes, x.bytes, res.bytes, res.bytes);
                n /= 2;
            }
        }
        else {
            key prev = x;

            for (size_t i = 1; i < n; i++) {
                if (i > 1) {
                    sc_mul(prev.bytes, prev.bytes, x.bytes);
                }
                sc_add(res.bytes, res.bytes, prev.bytes);
            }
        }

        return res;
    }

    static key inner_product(const tools::span<const key> &a, const tools::span<const key> &b)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b (inner_product)");
        key res = zero();

        for (size_t i = 0; i < a.size(); ++i) {
            sc_muladd(res.bytes, a[i].bytes, b[i].bytes, res.bytes);
        }

        return res;
    }

    static key inner_product(const keyV &a, const keyV &b)
    {
        return inner_product(tools::span<const key>(a.data(), a.size()), tools::span<const key>(b.data(), b.size()));
    }

    static keyV hadamard(const keyV &a, const keyV &b)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b (hadamard)");
        keyV res(a.size());

        for (size_t i = 0; i < a.size(); ++i) {
            sc_mul(res[i].bytes, a[i].bytes, b[i].bytes);
        }

        return res;
    }

    static void hadamard_fold(std::vector<ge_p3> &v, const keyV *scale, const key &a, const key &b)
    {
        CHECK_THROW_ERR((v.size() & 1) == 0, "Vector size should be even (hadamard_fold)");
        const size_t sz = v.size() / 2;

        for (size_t n = 0; n < sz; n++) {
            ge_dsmp c[2];
            ge_dsm_precomp(c[0], &v[n]);
            ge_dsm_precomp(c[1], &v[sz + n]);

            key sa, sb;
            if (scale) sc_mul(sa.bytes, a.bytes, (*scale)[n].bytes); else sa = a;
            if (scale) sc_mul(sb.bytes, b.bytes, (*scale)[sz + n].bytes); else sb = b;

            ge_double_scalarmult_precomp_vartime2_p3(&v[n], sa.bytes, c[0], sb.bytes, c[1]);
        }

        v.resize(sz);
    }

    static keyV vector_add(const keyV &a, const keyV &b)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b (vector_add)");
        keyV res(a.size());

        for (size_t i = 0; i < a.size(); i++) {
            sc_add(res[i].bytes, a[i].bytes, b[i].bytes);
        }

        return res;
    }

    static keyV vector_add(const keyV &a, const key &b)
    {
        keyV res(a.size());

        for (size_t i = 0; i < a.size(); i++) {
            sc_add(res[i].bytes, a[i].bytes, b.bytes);
        }

        return res;
    }

    static keyV vector_subtract(const keyV &a, const key &b)
    {
        keyV res(a.size());

        for (size_t i = 0; i < a.size(); i++) {
            sc_sub(res[i].bytes, a[i].bytes, b.bytes);
        }

        return res;
    }

    static keyV vector_scalar(const tools::span<const key> &a, const key &x) 
    {
        keyV res(a.size());

        for (size_t i = 0; i < a.size(); i++) {
            sc_mul(res[i].bytes, a[i].bytes, x.bytes);
        }

        return res;
    }

    static keyV vector_scalar(const keyV &a, const key &x)
    {
        return vector_scalar(tools::span<const key>(a.data(), a.size()), x);
    }

    static keyV vector_dup(const key &x, size_t N)
    {
        return keyV(N, x);
    }

    static key sm(key y, int n, const key &x)
    {
        while (n--) {
            sc_mul(y.bytes, y.bytes, y.bytes);
        }

        sc_mul(y.bytes, y.bytes, x.bytes);

        return y;
    }

    static key invert(const key &x)
    {
        key _1, _10, _100, _11, _101, _111, _1001, _1011, _1111;

        _1 = x;
        sc_mul(_10.bytes, _1.bytes, _1.bytes);
        sc_mul(_100.bytes, _10.bytes, _10.bytes);
        sc_mul(_11.bytes, _10.bytes, _1.bytes);
        sc_mul(_101.bytes, _10.bytes, _11.bytes);
        sc_mul(_111.bytes, _10.bytes, _101.bytes);
        sc_mul(_1001.bytes, _10.bytes, _111.bytes);
        sc_mul(_1011.bytes, _10.bytes, _1001.bytes);
        sc_mul(_1111.bytes, _100.bytes, _1011.bytes);

        key inv;
        sc_mul(inv.bytes, _1111.bytes, _1.bytes);

        inv = sm(inv, 123 + 3, _101);
        inv = sm(inv, 2 + 2, _11);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 4, _1001);
        inv = sm(inv, 2, _11);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 1 + 3, _101);
        inv = sm(inv, 3 + 3, _101);
        inv = sm(inv, 3, _111);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 2 + 3, _111);
        inv = sm(inv, 2 + 2, _11);
        inv = sm(inv, 1 + 4, _1011);
        inv = sm(inv, 2 + 4, _1011);
        inv = sm(inv, 6 + 4, _1001);
        inv = sm(inv, 2 + 2, _11);
        inv = sm(inv, 3 + 2, _11);
        inv = sm(inv, 3 + 2, _11);
        inv = sm(inv, 1 + 4, _1001);
        inv = sm(inv, 1 + 3, _111);
        inv = sm(inv, 2 + 4, _1111);
        inv = sm(inv, 1 + 4, _1011);
        inv = sm(inv, 3, _101);
        inv = sm(inv, 2 + 4, _1111);
        inv = sm(inv, 3, _101);
        inv = sm(inv, 1 + 2, _11);

#ifdef DEBUG_BP
        key tmp;
        sc_mul(tmp.bytes, inv.bytes, x.bytes);
        CHECK_THROW_ERR(tmp == identity(), "invert failed");
#endif
        return inv;
    }

    static keyV invert(keyV x)
    {
        keyV scratch;
        scratch.reserve(x.size());

        key acc = identity();

        for (size_t n = 0; n < x.size(); n++) {
            scratch.push_back(acc);

            if (n == 0) {
                acc = x[0];
            }
            else {
                sc_mul(acc.bytes, acc.bytes, x[n].bytes);
            }
        }

        acc = invert(acc);

        key tmp;

        for (int i = x.size(); i-- > 0; ) {
            sc_mul(tmp.bytes, acc.bytes, x[i].bytes);
            sc_mul(x[i].bytes, acc.bytes, scratch[i].bytes);
            acc = tmp;
        }

        return x;
    }

    static tools::span<const key> slice(const keyV &a, size_t start, size_t stop)
    {
        CHECK_THROW_ERR(start < a.size(), "Invalid start index (slice)");
        CHECK_THROW_ERR(stop <= a.size(), "Invalid stop index (slice)");
        CHECK_THROW_ERR(start < stop, "Invalid start/stop indices (slice)");
        return tools::span<const key>(&a[start], stop - start);
    }

    static key hash_cache_mash(key &hash_cache, const key &mash0, const key &mash1)
    {
        key data[3];
        data[0] = hash_cache;
        data[1] = mash0;
        data[2] = mash1;

        hash_to_scalar(hash_cache, data, sizeof(data));

        return hash_cache;
    }

    static key hash_cache_mash(key &hash_cache, const key &mash0, const key &mash1, const key &mash2)
    {
        key data[4];
        data[0] = hash_cache;
        data[1] = mash0;
        data[2] = mash1;
        data[3] = mash2;

        hash_to_scalar(hash_cache, data, sizeof(data));

        return hash_cache;
    }

    static key hash_cache_mash(key &hash_cache, const key &mash0, const key &mash1, const key &mash2, const key &mash3)
    {
        key data[5];
        data[0] = hash_cache;
        data[1] = mash0;
        data[2] = mash1;
        data[3] = mash2;
        data[4] = mash3;

        hash_to_scalar(hash_cache, data, sizeof(data));

        return hash_cache;
    }

    bulletproof bulletproof_PROVE(const key &sv, const key &gamma)
    {
        return bulletproof_PROVE(keyV(1, sv), keyV(1, gamma));
    }

    bulletproof bulletproof_PROVE(uint64_t v, const key &gamma)
    {
        return bulletproof_PROVE(std::vector<uint64_t>(1, v), keyV(1, gamma));
    }

    bulletproof bulletproof_PROVE(const keyV &sv, const keyV &gamma)
    {
        CHECK_THROW_ERR(sv.size() == gamma.size(), "incompatible sizes of sv and gamma (bulletproof_PROVE)");
        CHECK_THROW_ERR(!sv.empty(), "sv is empty (bulletproof_PROVE)");
        
        for (const key &sve: sv) {
            CHECK_THROW_ERR(is_reduced(sve), "Invalid sv input (bulletproof_PROVE)");
        }

        for (const key &g: gamma) {
            CHECK_THROW_ERR(is_reduced(g), "Invalid gamma input (bulletproof_PROVE)");
        }

        init_exponents();

        constexpr size_t logN = 6;
        constexpr size_t N = 1<<logN;
        size_t M, logM;
        for (logM = 0; (M = 1<<logM) <= maxM && M < sv.size(); ++logM);

        CHECK_THROW_ERR(M <= maxM, "sv/gamma are too large (bulletproof_PROVE)");
        
        const size_t logMN = logM + logN;
        const size_t MN = M * N;

        keyV V(sv.size());
        keyV aL(MN), aR(MN);
        keyV aL8(MN), aR8(MN);
        key tmp, tmp2;

        for (size_t i = 0; i < sv.size(); i++) {
            key gamma8, sv8;
            sc_mul(gamma8.bytes, gamma[i].bytes, INV_EIGHT.bytes);
            sc_mul(sv8.bytes, sv[i].bytes, INV_EIGHT.bytes);
            add_keys2(V[i], gamma8, sv8, H);
        }

        for (size_t j = 0; j < M; j++) {
            for (size_t i = N; i-- > 0; ) {
                if (j < sv.size() && (sv[j][i/8] & (((uint64_t)1)<<(i%8)))) {
                    aL[j*N + i] = identity();
                    aL8[j*N + i] = INV_EIGHT;
                    aR[j*N + i] = aR8[j*N + i] = zero();
                }
                else {
                    aL[j*N + i] = aL8[j*N + i] = zero();
                    aR[j*N + i] = MINUS_ONE;
                    aR8[j*N + i] = MINUS_INV_EIGHT;
                }
            }
        }

#ifdef DEBUG_BP
        for (size_t j = 0; j < M; j++) {
            uint64_t test_aL = 0, test_aR = 0;

            for (size_t i = 0; i < N; i++) {
                if (aL[j*N+i] == identity()) {
                    test_aL += ((uint64_t)1)<<i;
                }

                if (aR[j*N+i] == zero()) {
                    test_aR += ((uint64_t)1)<<i;
                }
            }

            uint64_t v_test = 0;

            if (j < sv.size()) {
                for (int n = 0; n < 8; ++n) v_test |= (((uint64_t)sv[j][n]) << (8*n));
            }

            CHECK_THROW_ERR(test_aL == v_test, "test_aL failed (bulletproof_PROVE)");
            CHECK_THROW_ERR(test_aR == v_test, "test_aR failed (bulletproof_PROVE)");
        }
#endif

try_again:
        key hash_cache = hash_to_scalar(V);
        key alpha = skgen();
        key ve = vector_exponent(aL8, aR8);
        key A;

        sc_mul(tmp.bytes, alpha.bytes, INV_EIGHT.bytes);
        add_keys(A, ve, scalarmult_base(tmp));

        keyV sL = skvgen(MN), sR = skvgen(MN);
        key rho = vector_exponent(sL, sR);
        key S;

        add_keys(S, ve, scalarmult_base(rho));
        S = scalarmult_key(S, INV_EIGHT);

        key y = hash_cache_mash(hash_cache, A, S);

        if (y == zero()) {
            goto try_again;
        }

        key z = hash_cache = hash_to_scalar(y);

        if (z == zero()) {
            goto try_again;
        }

        keyV l0 = vector_subtract(aL, z);
        keyV &l1 = sL;

        keyV zero_twos(MN);
        const keyV zpow = vector_powers(z, M+2);

        for (size_t j = 0; j < M; j++) {
            for (size_t i = 0; i < N; i++) {
                CHECK_THROW_ERR(j+2 < zpow.size(), "invalid zpow index (bulletproof_PROVE)");
                CHECK_THROW_ERR(i < twoN.size(), "invalid twoN index (bulletproof_PROVE)");
                sc_mul(zero_twos[j*N+i].bytes,zpow[j+2].bytes,twoN[i].bytes);
            }
        }

        keyV r0 = vector_add(aR, z);
        const auto yMN = vector_powers(y, MN);
        r0 = hadamard(r0, yMN);
        r0 = vector_add(r0, zero_twos);
        keyV r1 = hadamard(yMN, sR);

        key t1_1 = inner_product(l0, r1);
        key t1_2 = inner_product(l1, r0);
        key t1;
        sc_add(t1.bytes, t1_1.bytes, t1_2.bytes);
        key t2 = inner_product(l1, r1);

        key tau1 = skgen(), tau2 = skgen();

        key T1, T2;
        ge_p3 p3;

        sc_mul(tmp.bytes, t1.bytes, INV_EIGHT.bytes);
        sc_mul(tmp2.bytes, tau1.bytes, INV_EIGHT.bytes);
        ge_double_scalarmult_base_vartime_p3(&p3, tmp.bytes, &ge_p3_H, tmp2.bytes);
        ge_p3_tobytes(T1.bytes, &p3);
        sc_mul(tmp.bytes, t2.bytes, INV_EIGHT.bytes);
        sc_mul(tmp2.bytes, tau2.bytes, INV_EIGHT.bytes);
        ge_double_scalarmult_base_vartime_p3(&p3, tmp.bytes, &ge_p3_H, tmp2.bytes);
        ge_p3_tobytes(T2.bytes, &p3);

        key x = hash_cache_mash(hash_cache, z, T1, T2);

        if (x == zero()) {
            goto try_again;
        }

        key taux;
        sc_mul(taux.bytes, tau1.bytes, x.bytes);

        key xsq;
        sc_mul(xsq.bytes, x.bytes, x.bytes);
        sc_muladd(taux.bytes, tau2.bytes, xsq.bytes, taux.bytes);

        for (size_t j = 1; j <= sv.size(); j++) {
            CHECK_THROW_ERR(j+1 < zpow.size(), "invalid zpow index (bulletproof_PROVE)");
            sc_muladd(taux.bytes, zpow[j+1].bytes, gamma[j-1].bytes, taux.bytes);
        }

        key mu;
        sc_muladd(mu.bytes, x.bytes, rho.bytes, alpha.bytes);

        keyV l = l0;
        l = vector_add(l, vector_scalar(l1, x));
        keyV r = r0;
        r = vector_add(r, vector_scalar(r1, x));

        key t = inner_product(l, r);

#ifdef DEBUG_BP
        key test_t;
        const key t0 = inner_product(l0, r0);
        sc_muladd(test_t.bytes, t1.bytes, x.bytes, t0.bytes);
        sc_muladd(test_t.bytes, t2.bytes, xsq.bytes, test_t.bytes);
        CHECK_THROW_ERR(test_t == t, "test_t check failed (bulletproof_PROVE)");
#endif

        key x_ip = hash_cache_mash(hash_cache, x, taux, mu, t);
        
        if (x_ip == zero()) {
            goto try_again;
        }

        size_t nprime = MN;
        std::vector<ge_p3> Gprime(MN);
        std::vector<ge_p3> Hprime(MN);
        keyV aprime(MN);
        keyV bprime(MN);

        const key yinv = invert(y);
        keyV yinvpow(MN);
        yinvpow[0] = identity();
        yinvpow[1] = yinv;

        for (size_t i = 0; i < MN; i++) {
            Gprime[i] = Gi_p3[i];
            Hprime[i] = Hi_p3[i];
            
            if (i > 1) {
                sc_mul(yinvpow[i].bytes, yinvpow[i-1].bytes, yinv.bytes);
            }
            
            aprime[i] = l[i];
            bprime[i] = r[i];
        }

        keyV L(logMN);
        keyV R(logMN);
        int round = 0;
        keyV w(logMN); 

        const keyV *scale = &yinvpow;

        while (nprime > 1) {
            nprime /= 2;

            key cL = inner_product(slice(aprime, 0, nprime), slice(bprime, nprime, bprime.size()));
            key cR = inner_product(slice(aprime, nprime, aprime.size()), slice(bprime, 0, nprime));

            sc_mul(tmp.bytes, cL.bytes, x_ip.bytes);
            L[round] = cross_vector_exponent8(nprime, Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, scale, &ge_p3_H, &tmp);
            sc_mul(tmp.bytes, cR.bytes, x_ip.bytes);
            R[round] = cross_vector_exponent8(nprime, Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, scale, &ge_p3_H, &tmp);

            w[round] = hash_cache_mash(hash_cache, L[round], R[round]);

            if (w[round] == zero()) {
                goto try_again;
            }

            const key winv = invert(w[round]);

            if (nprime > 1) {
                hadamard_fold(Gprime, NULL, winv, w[round]);
                hadamard_fold(Hprime, scale, w[round], winv);
            }

            aprime = vector_add(vector_scalar(slice(aprime, 0, nprime), w[round]), vector_scalar(slice(aprime, nprime, aprime.size()), winv));
            bprime = vector_add(vector_scalar(slice(bprime, 0, nprime), winv), vector_scalar(slice(bprime, nprime, bprime.size()), w[round]));
        
            scale = NULL;
            round++;
        }

        return bulletproof(std::move(V), A, S, T1, T2, taux, mu, std::move(L), std::move(R), aprime[0], bprime[0], t);
    }

    bulletproof bulletproof_PROVE(const std::vector<uint64_t> &v, const keyV &gamma)
    {
        CHECK_THROW_ERR(v.size() == gamma.size(), "Incompatible sizes of v and gamma (bulletproof_PROVE)");

        keyV sv(v.size());

        for (size_t i = 0; i < v.size(); i++) {
            sv[i] = zero();
            sv[i].bytes[0] = v[i] & 255;
            sv[i].bytes[1] = (v[i] >> 8) & 255;
            sv[i].bytes[2] = (v[i] >> 16) & 255;
            sv[i].bytes[3] = (v[i] >> 24) & 255;
            sv[i].bytes[4] = (v[i] >> 32) & 255;
            sv[i].bytes[5] = (v[i] >> 40) & 255;
            sv[i].bytes[6] = (v[i] >> 48) & 255;
            sv[i].bytes[7] = (v[i] >> 56) & 255;
        }

        return bulletproof_PROVE(sv, gamma);
    }

    struct proof_data_t {
        key x, y, z, x_ip;
        std::vector<key> w;
        size_t logM, inv_offset;
    };

    

    bool bulletproof_VERIFY(const std::vector<const bulletproof*> &proofs)
    {
        init_exponents();

        const size_t logN = 6;
        const size_t N = 1<<logN;

        size_t max_length = 0;
        size_t nV = 0;
        std::vector<proof_data_t> proof_data;
        proof_data.reserve(proofs.size());
        size_t inv_offset = 0;
        std::vector<key> to_invert;
        to_invert.reserve(11 * proofs.size());
        size_t max_logM = 0;

        for (const bulletproof *p: proofs) {
            const bulletproof &proof = *p;

            CHECK_ASSERT(is_reduced(proof.taux), false, "Input scalar not in range (bulletproof_VERIFY)");
            CHECK_ASSERT(is_reduced(proof.mu), false, "Input scalar not in range (bulletproof_VERIFY)");
            CHECK_ASSERT(is_reduced(proof.a), false, "Input scalar not in range (bulletproof_VERIFY)");
            CHECK_ASSERT(is_reduced(proof.b), false, "Input scalar not in range (bulletproof_VERIFY)");
            CHECK_ASSERT(is_reduced(proof.t), false, "Input scalar not in range (bulletproof_VERIFY)");

            CHECK_ASSERT(proof.V.size() >= 1, false, "V does not have at least one element (bulletproof_VERIFY)");
            CHECK_ASSERT(proof.L.size() == proof.R.size(), false, "Mismatched L and R sizes (bulletproof_VERIFY)");
            CHECK_ASSERT(proof.L.size() > 0, false, "Empty proof (bulletproof_VERIFY)");    

            max_length = std::max(max_length, proof.L.size());
            nV += proof.V.size();

            proof_data.resize(proof_data.size() + 1);
            proof_data_t &pd = proof_data.back();
            key hash_cache = hash_to_scalar(proof.V);
            pd.y = hash_cache_mash(hash_cache, proof.A, proof.S);
            CHECK_ASSERT(!(pd.y == zero()), false, "y == 0 (bulletproof_VERIFY)");
            pd.z = hash_cache = hash_to_scalar(pd.y);
            CHECK_ASSERT(!(pd.z == zero()), false, "z == 0 (bulletproof_VERIFY)");
            pd.x = hash_cache_mash(hash_cache, pd.z, proof.T1, proof.T2);
            CHECK_ASSERT(!(pd.x == zero()), false, "x == 0 (bulletproof_VERIFY)");
            pd.x_ip = hash_cache_mash(hash_cache, pd.x, proof.taux, proof.mu, proof.t);
            CHECK_ASSERT(!(pd.x_ip == zero()), false, "x_ip == 0 (bulletproof_VERIFY)");

            size_t M;
            for (pd.logM = 0; (M = 1<<pd.logM) <= maxM && M < proof.V.size(); ++pd.logM);
            CHECK_ASSERT(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size (bulletproof_VERIFY)");
            max_logM = std::max(pd.logM, max_logM);

            const size_t rounds = pd.logM+logN;
            CHECK_ASSERT(rounds > 0, false, "Zero rounds (bulletproof_VERIFY)");

            pd.w.resize(rounds);

            for (size_t i = 0; i < rounds; i++) {
                pd.w[i] = hash_cache_mash(hash_cache, proof.L[i], proof.R[i]);
                CHECK_ASSERT(!(pd.w[i] == zero()), false, "w[i] == 0 (bulletproof_VERIFY)");
            }

            pd.inv_offset = inv_offset;

            for (size_t i = 0; i < rounds; i++) {
                to_invert.push_back(pd.w[i]);
            }

            to_invert.push_back(pd.y);
            inv_offset += rounds + 1;
        }

        CHECK_ASSERT(max_length < 32, false, "At least one proof is too large (bulletproof_VERIFY)");
        size_t maxMN = 1u << max_length;

        key tmp;

        std::vector<multiexp_data> data;
        data.reserve(nV + (2 * (max_logM + logN) + 4) * proofs.size() + 2 * maxMN);
        data.resize(2 * maxMN);

        const std::vector<key> inverses = invert(to_invert);
        
        key z1 = zero();
        key z3 = zero();
        keyV m_z4(maxMN, zero()), m_z5(maxMN, zero());
        key m_y0 = zero(), y1 = zero();
        int proof_data_index = 0;
        keyV w_cache;
        std::vector<ge_p3> proof8_V, proof8_L, proof8_R;

        for (const bulletproof *p: proofs) {
            const bulletproof &proof = *p;
            const proof_data_t &pd = proof_data[proof_data_index++];

            CHECK_ASSERT(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size (bulletproof_VERIFY)");
            const size_t M = 1 << pd.logM;
            const size_t MN = M*N;
            const key weight_y = skgen();
            const key weight_z = skgen();

            proof8_V.resize(proof.V.size()); for (size_t i = 0; i < proof.V.size(); ++i) scalarmult_8(proof8_V[i], proof.V[i]);
            proof8_L.resize(proof.L.size()); for (size_t i = 0; i < proof.L.size(); ++i) scalarmult_8(proof8_L[i], proof.L[i]);
            proof8_R.resize(proof.R.size()); for (size_t i = 0; i < proof.R.size(); ++i) scalarmult_8(proof8_R[i], proof.R[i]);

            ge_p3 proof8_T1;
            ge_p3 proof8_T2;
            ge_p3 proof8_S;
            ge_p3 proof8_A;

            scalarmult_8(proof8_T1, proof.T1);
            scalarmult_8(proof8_T2, proof.T2);
            scalarmult_8(proof8_S, proof.S);
            scalarmult_8(proof8_A, proof.A);

            sc_mulsub(m_y0.bytes, proof.taux.bytes, weight_y.bytes, m_y0.bytes);

            const keyV zpow = vector_powers(pd.z, M+3);

            key k;
            const key ip1y = vector_power_sum(pd.y, MN);
            sc_mulsub(k.bytes, zpow[2].bytes, ip1y.bytes, zero().bytes);

            for (size_t j = 1; j <= M; j++) {
                CHECK_ASSERT(j+2 < zpow.size(), false, "invalid zpow index (bulletproof_VERIFY)");
                sc_mulsub(k.bytes, zpow[j+2].bytes, ip12.bytes, k.bytes);
            }

            sc_muladd(tmp.bytes, pd.z.bytes, ip1y.bytes, k.bytes);
            sc_sub(tmp.bytes, proof.t.bytes, tmp.bytes);
            sc_muladd(y1.bytes, tmp.bytes, weight_y.bytes, y1.bytes);

            for (size_t j = 0; j < proof8_V.size(); j++) {
                sc_mul(tmp.bytes, zpow[j+2].bytes, weight_y.bytes);
                data.emplace_back(tmp, proof8_V[j]);
            }

            sc_mul(tmp.bytes, pd.x.bytes, weight_y.bytes);
            data.emplace_back(tmp, proof8_T1);

            key xsq;
            sc_mul(xsq.bytes, pd.x.bytes, pd.x.bytes);
            sc_mul(tmp.bytes, xsq.bytes, weight_y.bytes);

            data.emplace_back(tmp, proof8_T2);
            data.emplace_back(weight_z, proof8_A);
            sc_mul(tmp.bytes, pd.x.bytes, weight_z.bytes);
            data.emplace_back(tmp, proof8_S);

            const size_t rounds = pd.logM+logN;
            CHECK_ASSERT(rounds > 0, false, "Zero rounds (bulletproof_VERIFY)");

            key yinvpow = identity();
            key ypow = identity();

            const key *winv = &inverses[pd.inv_offset];
            const key yinv = inverses[pd.inv_offset + rounds];

            w_cache.resize(1<<rounds);
            w_cache[0] = winv[0];
            w_cache[1] = pd.w[0];

            for (size_t j = 1; j < rounds; j++) {
                const size_t slots = 1<<(j+1);
                
                for (size_t s = slots; s-- > 0; s--) {
                    sc_mul(w_cache[s].bytes, w_cache[s/2].bytes, pd.w[j].bytes);
                    sc_mul(w_cache[s-1].bytes, w_cache[s/2].bytes, winv[j].bytes);
                }
            }

            for (size_t i = 0; i < MN; i++) {
                key g_scalar = proof.a;
                key h_scalar;
                if (i == 0) {
                    h_scalar = proof.b;
                }
                else {
                    sc_mul(h_scalar.bytes, proof.b.bytes, yinvpow.bytes);
                }

                sc_mul(g_scalar.bytes, g_scalar.bytes, w_cache[i].bytes);
                sc_mul(h_scalar.bytes, h_scalar.bytes, w_cache[(~i) & (MN-1)].bytes);

                sc_add(g_scalar.bytes, g_scalar.bytes, pd.z.bytes);

                CHECK_ASSERT(2+i/N < zpow.size(), false, "invalid zpow index (bulletproof_VERIFY)");
                CHECK_ASSERT(i%N < twoN.size(), false, "invalid twoN index (bulletproof_VERIFY)");

                sc_mul(tmp.bytes, zpow[2+i/N].bytes, twoN[i%N].bytes);
                
                if (i == 0) {
                    sc_add(tmp.bytes, tmp.bytes, pd.z.bytes);
                    sc_sub(h_scalar.bytes, h_scalar.bytes, tmp.bytes);
                }
                else {
                    sc_muladd(tmp.bytes, pd.z.bytes, ypow.bytes, tmp.bytes);
                    sc_mulsub(h_scalar.bytes, tmp.bytes, yinvpow.bytes, h_scalar.bytes);
                }

                sc_mulsub(m_z4[i].bytes, g_scalar.bytes, weight_z.bytes, m_z4[i].bytes);
                sc_mulsub(m_z5[i].bytes, h_scalar.bytes, weight_z.bytes, m_z5[i].bytes);

                if (i == 0) {
                    yinvpow = yinv;
                    ypow = pd.y;
                }
                else if (i != MN-1) {
                    sc_mul(yinvpow.bytes, yinvpow.bytes, yinv.bytes);
                    sc_mul(ypow.bytes, ypow.bytes, pd.y.bytes);
                }
            }

            sc_muladd(z1.bytes, proof.mu.bytes, weight_z.bytes, z1.bytes);
            
            for (size_t i = 0; i < rounds; i++) {
                sc_mul(tmp.bytes, pd.w[i].bytes, pd.w[i].bytes);
                sc_mul(tmp.bytes, tmp.bytes, weight_z.bytes);
                data.emplace_back(tmp, proof8_L[i]);

                sc_mul(tmp.bytes, winv[i].bytes, winv[i].bytes);
                sc_mul(tmp.bytes, tmp.bytes, weight_z.bytes);
                data.emplace_back(tmp, proof8_R[i]);
            }

            sc_mulsub(tmp.bytes, proof.a.bytes, proof.b.bytes, proof.t.bytes);
            sc_mul(tmp.bytes, tmp.bytes, pd.x_ip.bytes);
            sc_muladd(z3.bytes, tmp.bytes, weight_z.bytes, z3.bytes);
        }

        sc_sub(tmp.bytes, m_y0.bytes, z1.bytes);
        data.emplace_back(tmp, G);
        sc_sub(tmp.bytes, z3.bytes, y1.bytes);
        data.emplace_back(tmp, H);

        for (size_t i = 0; i < maxMN; i++) {
            data[i * 2] = {m_z4[i], Gi_p3[i]};
            data[i * 2 + 1] = {m_z5[i], Hi_p3[i]};
        }

        if (!(multiexp(data, 2 * maxMN) == identity())) {
            return false;
        }

        return true;
    }

    bool bulletproof_VERIFY(const std::vector<bulletproof> &proofs)
    {
        std::vector<const bulletproof*> proof_pointers;
        proof_pointers.reserve(proofs.size());

        for (const bulletproof &proof: proofs) {
            proof_pointers.push_back(&proof);
        }

        return bulletproof_VERIFY(proof_pointers);
    }

    bool bulletproof_VERIFY(const bulletproof &proof)
    {
        std::vector<const bulletproof*> proofs;
        proofs.push_back(&proof);
        return bulletproof_VERIFY(proofs);
    }
}

void bulletproof_PROVE(discore::ArgBulletproof bp, const uint64_t v[16], const discore::key16 gamma, uint64_t size)
{
    discore::keyV gamma_(size);
    std::vector<uint64_t> val(size);

    for (unsigned int i = 0; i < size; i++) {
        val[i] = v[i];
        gamma_[i] = gamma[i];
    }

    discore::bulletproof bp_ = discore::bulletproof_PROVE(val, gamma_);

    for (unsigned int i = 0; i < bp_.V.size(); i++) {
        bp.V[i] = bp_.V[i];
    }

    for (unsigned int i = 0; i < bp_.L.size(); i++) {
        bp.L[i] = bp_.L[i];
        bp.R[i] = bp_.R[i];
    }

    bp.A = bp_.A;
    bp.S = bp_.S;
    bp.T1 = bp_.T1;
    bp.T2 = bp_.T2;
    bp.taux = bp_.taux;
    bp.mu = bp_.mu;
    bp.a = bp_.a;
    bp.b = bp_.b;
    bp.t = bp_.t;

    bp.size = bp_.V.size();
}

bool bulletproof_VERIFY(discore::ArgBulletproof bp)
{
    discore::bulletproof bp_ = discore::bulletproof();

    bp_.A = bp.A;
    bp_.S = bp.S;
    bp_.T1 = bp.T1;
    bp_.T2 = bp.T2;
    bp_.taux = bp.taux;
    bp_.mu = bp.mu;

    int size = (bp.size == 16 ? 10 : (bp.size > 7 ? 9 : (bp.size > 3 ? 8 : (bp.size == 2 ? 7 : 6))));


    bp_.L = discore::keyV(size);
    bp_.R = discore::keyV(size);

    for (int i = 0; i < size; i++) {
        bp_.L[i] = bp.L[i];
        bp_.R[i] = bp.R[i];
    }

    bp_.V = discore::keyV((unsigned int)bp.size);

    for (int i = 0; i < bp.size; i++) {
        bp_.V[i] = bp.V[i];
    }

    bp_.a = bp.a;
    bp_.b = bp.b;
    bp_.t = bp.t;

    return discore::bulletproof_VERIFY(bp_);
}