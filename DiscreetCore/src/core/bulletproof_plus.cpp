#include <stdlib.h>
#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>

#include "util/span.h"
#include "util/varint.h"

extern "C"
{
#include "crypto_curve.h"
}

#include "ops.h"
#include "multiexp.h"
#include "bulletproof.h"

#define STRAUS_SIZE_LIMIT 232
#define PIPPENGER_SIZE_LIMIT 0

namespace discore
{
    // Vector functions
    static key vector_exponent(const keyV& a, const keyV& b);
    static keyV vector_of_scalar_powers(const key& x, size_t n);

    // Proof bounds
    static constexpr size_t maxN = 64; // maximum number of bits in range
    static constexpr size_t maxM = BULLETPROOF_MAX_OUTPUTS; // maximum number of outputs to aggregate into a single proof

    // Cached public generators
    static key Hi[maxN * maxM], Gi[maxN * maxM];
    static ge_p3 Hi_p3[maxN * maxM], Gi_p3[maxN * maxM];
    static std::shared_ptr<straus_cached_data> straus_HiGi_cache;
    static std::shared_ptr<pippenger_cached_data> pippenger_HiGi_cache;

    // Useful scalar constants
    static const key ZERO = { {0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } }; // 0
    static const key ONE = { {0x01, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } }; // 1
    static const key TWO = { {0x02, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } }; // 2
    static const key MINUS_ONE = { { 0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 } }; // -1
    static const key MINUS_INV_EIGHT = { { 0x74, 0xa4, 0x19, 0x7a, 0xf0, 0x7d, 0x0b, 0xf7, 0x05, 0xc2, 0xda, 0x25, 0x2b, 0x5c, 0x0b, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a } }; // -(8**(-1))
    static key TWO_SIXTY_FOUR_MINUS_ONE; // 2**64 - 1

    // Initial transcript hash
    static key initial_transcript;

    static boost::mutex init_mutex;

    // Use the generator caches to compute a multiscalar multiplication
    static inline key multiexp(const std::vector<MultiexpData>& data, size_t HiGi_size)
    {
        if (HiGi_size > 0)
        {
            static_assert(232 <= STRAUS_SIZE_LIMIT, "Straus in precalc mode can only be calculated till STRAUS_SIZE_LIMIT");
            return HiGi_size <= 232 && data.size() == HiGi_size ? straus(data, straus_HiGi_cache, 0) : pippenger(data, pippenger_HiGi_cache, HiGi_size, get_pippenger_c(data.size()));
        }
        else
        {
            return data.size() <= 95 ? straus(data, NULL, 0) : pippenger(data, NULL, 0, get_pippenger_c(data.size()));
        }
    }

    // Confirm that a scalar is properly reduced
    static inline bool is_reduced(const key& scalar)
    {
        return sc_check(scalar.bytes) == 0;
    }

    // Use hashed values to produce indexed public generators
    static key get_exponent(const key& base, size_t idx)
    {
        static const std::string domain_separator("bulletproof_plus");
        std::string hashed = std::string((const char*)base.bytes, sizeof(base)) + domain_separator + tools::get_varint_data(idx);
        key generator;
        ge_p3 generator_p3;
        key hashed_data;
        hash_to_scalar(hashed_data, hashed.data(), hashed.size());
        hash_to_p3(generator_p3, hashed_data);
        ge_p3_tobytes(generator.bytes, &generator_p3);
        CHECK_THROW_ERR(!(generator == identity()), "Exponent is point at infinity");
        return generator;
    }

    // Construct public generators
    static void init_exponents()
    {
        boost::lock_guard<boost::mutex> lock(init_mutex);

        // Only needs to be done once
        static bool init_done = false;
        if (init_done)
            return;

        std::vector<MultiexpData> data;
        data.reserve(maxN * maxM * 2);
        for (size_t i = 0; i < maxN * maxM; ++i)
        {
            Hi[i] = get_exponent(H, i * 2);
            CHECK_THROW_ERR(ge_frombytes_vartime(&Hi_p3[i], Hi[i].bytes) == 0, "ge_frombytes_vartime failed");
            Gi[i] = get_exponent(H, i * 2 + 1);
            CHECK_THROW_ERR(ge_frombytes_vartime(&Gi_p3[i], Gi[i].bytes) == 0, "ge_frombytes_vartime failed");

            data.push_back({ zero(), Gi_p3[i] });
            data.push_back({ zero(), Hi_p3[i] });
        }

        straus_HiGi_cache = straus_init_cache(data, STRAUS_SIZE_LIMIT);
        pippenger_HiGi_cache = pippenger_init_cache(data, 0, PIPPENGER_SIZE_LIMIT);

        // Compute 2**64 - 1 for later use in simplifying verification
        TWO_SIXTY_FOUR_MINUS_ONE = TWO;
        for (size_t i = 0; i < 6; i++)
        {
            sc_mul(TWO_SIXTY_FOUR_MINUS_ONE.bytes, TWO_SIXTY_FOUR_MINUS_ONE.bytes, TWO_SIXTY_FOUR_MINUS_ONE.bytes);
        }
        sc_sub(TWO_SIXTY_FOUR_MINUS_ONE.bytes, TWO_SIXTY_FOUR_MINUS_ONE.bytes, ONE.bytes);

        // Generate the initial Fiat-Shamir transcript hash, which is constant across all proofs
        static const std::string domain_separator("bulletproof_plus_transcript");
        ge_p3 initial_transcript_p3;
        key hashed_data;
        hash_to_scalar(hashed_data, domain_separator.data(), domain_separator.size());
        hash_to_p3(initial_transcript_p3, hashed_data);
        ge_p3_tobytes(initial_transcript.bytes, &initial_transcript_p3);

        init_done = true;
    }

    // Given two scalar arrays, construct a vector pre-commitment:
    //
    // a = (a_0, ..., a_{n-1})
    // b = (b_0, ..., b_{n-1})
    //
    // Outputs a_0*Gi_0 + ... + a_{n-1}*Gi_{n-1} +
    //         b_0*Hi_0 + ... + b_{n-1}*Hi_{n-1}
    static key vector_exponent(const keyV& a, const keyV& b)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b");
        CHECK_THROW_ERR(a.size() <= maxN * maxM, "Incompatible sizes of a and maxN");

        std::vector<MultiexpData> multiexp_data;
        multiexp_data.reserve(a.size() * 2);
        for (size_t i = 0; i < a.size(); ++i)
        {
            multiexp_data.emplace_back(a[i], Gi_p3[i]);
            multiexp_data.emplace_back(b[i], Hi_p3[i]);
        }
        return multiexp(multiexp_data, 2 * a.size());
    }

    // Helper function used to compute the L and R terms used in the inner-product round function
    static key compute_LR(size_t size, const key& y, const std::vector<ge_p3>& G, size_t G0, const std::vector<ge_p3>& H, size_t H0, const keyV& a, size_t a0, const keyV& b, size_t b0, const key& c, const key& d)
    {
        CHECK_THROW_ERR(size + G0 <= G.size(), "Incompatible size for G");
        CHECK_THROW_ERR(size + H0 <= H.size(), "Incompatible size for H");
        CHECK_THROW_ERR(size + a0 <= a.size(), "Incompatible size for a");
        CHECK_THROW_ERR(size + b0 <= b.size(), "Incompatible size for b");
        CHECK_THROW_ERR(size <= maxN * maxM, "size is too large");

        std::vector<MultiexpData> multiexp_data;
        multiexp_data.resize(size * 2 + 2);
        key temp;
        for (size_t i = 0; i < size; ++i)
        {
            sc_mul(temp.bytes, a[a0 + i].bytes, y.bytes);
            sc_mul(multiexp_data[i * 2].scalar.bytes, temp.bytes, INV_EIGHT.bytes);
            multiexp_data[i * 2].point = G[G0 + i];

            sc_mul(multiexp_data[i * 2 + 1].scalar.bytes, b[b0 + i].bytes, INV_EIGHT.bytes);
            multiexp_data[i * 2 + 1].point = H[H0 + i];
        }

        sc_mul(multiexp_data[2 * size].scalar.bytes, c.bytes, INV_EIGHT.bytes);
        ge_p3 H_p3;
        ge_frombytes_vartime(&H_p3, discore::H.bytes);
        multiexp_data[2 * size].point = H_p3;

        sc_mul(multiexp_data[2 * size + 1].scalar.bytes, d.bytes, INV_EIGHT.bytes);
        ge_p3 G_p3;
        ge_frombytes_vartime(&G_p3, discore::G.bytes);
        multiexp_data[2 * size + 1].point = G_p3;

        return multiexp(multiexp_data, 0);
    }

    // Given a scalar, construct a vector of its powers:
    //
    // Output (1,x,x**2,...,x**{n-1})
    static keyV vector_of_scalar_powers(const key& x, size_t n)
    {
        CHECK_THROW_ERR(n != 0, "Need n > 0");

        keyV res(n);
        res[0] = identity();
        if (n == 1)
            return res;
        res[1] = x;
        for (size_t i = 2; i < n; ++i)
        {
            sc_mul(res[i].bytes, res[i - 1].bytes, x.bytes);
        }
        return res;
    }

    // Given a scalar, construct the sum of its powers from 2 to n (where n is a power of 2):
    //
    // Output x**2 + x**4 + x**6 + ... + x**n
    static key sum_of_even_powers(const key& x, size_t n)
    {
        CHECK_THROW_ERR((n & (n - 1)) == 0, "Need n to be a power of 2");
        CHECK_THROW_ERR(n != 0, "Need n > 0");

        key x1 = copy(x);
        sc_mul(x1.bytes, x1.bytes, x1.bytes);

        key res = copy(x1);
        while (n > 2)
        {
            sc_muladd(res.bytes, x1.bytes, res.bytes, res.bytes);
            sc_mul(x1.bytes, x1.bytes, x1.bytes);
            n /= 2;
        }

        return res;
    }

    // Given a scalar, return the sum of its powers from 1 to n
    //
    // Output x**1 + x**2 + x**3 + ... + x**n
    static key sum_of_scalar_powers(const key& x, size_t n)
    {
        CHECK_THROW_ERR(n != 0, "Need n > 0");

        key res = ONE;
        if (n == 1)
            return res;

        n += 1;
        key x1 = copy(x);

        const bool is_power_of_2 = (n & (n - 1)) == 0;
        if (is_power_of_2)
        {
            sc_add(res.bytes, res.bytes, x1.bytes);
            while (n > 2)
            {
                sc_mul(x1.bytes, x1.bytes, x1.bytes);
                sc_muladd(res.bytes, x1.bytes, res.bytes, res.bytes);
                n /= 2;
            }
        }
        else
        {
            key prev = x1;
            for (size_t i = 1; i < n; ++i)
            {
                if (i > 1)
                    sc_mul(prev.bytes, prev.bytes, x1.bytes);
                sc_add(res.bytes, res.bytes, prev.bytes);
            }
        }
        sc_sub(res.bytes, res.bytes, ONE.bytes);

        return res;
    }

    // Given two scalar arrays, construct the weighted inner product against another scalar
    //
    // Output a_0*b_0*y**1 + a_1*b_1*y**2 + ... + a_{n-1}*b_{n-1}*y**n
    static key weighted_inner_product(const tools::span<const key>& a, const tools::span<const key>& b, const key& y)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b");
        key res = zero();
        key y_power = ONE;
        key temp;
        for (size_t i = 0; i < a.size(); ++i)
        {
            sc_mul(temp.bytes, a[i].bytes, b[i].bytes);
            sc_mul(y_power.bytes, y_power.bytes, y.bytes);
            sc_muladd(res.bytes, temp.bytes, y_power.bytes, res.bytes);
        }
        return res;
    }

    static key weighted_inner_product(const keyV& a, const tools::span<const key>& b, const key& y)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b");
        key res = zero();
        key y_power = ONE;
        key temp;
        for (size_t i = 0; i < a.size(); ++i)
        {
            sc_mul(temp.bytes, a[i].bytes, b[i].bytes);
            sc_mul(y_power.bytes, y_power.bytes, y.bytes);
            sc_muladd(res.bytes, temp.bytes, y_power.bytes, res.bytes);
        }
        return res;
    }

    // Fold inner-product point vectors
    static void hadamard_fold(std::vector<ge_p3>& v, const key& a, const key& b)
    {
        CHECK_THROW_ERR((v.size() & 1) == 0, "Vector size should be even");
        const size_t sz = v.size() / 2;
        for (size_t n = 0; n < sz; ++n)
        {
            ge_dsmp c[2];
            ge_dsm_precomp(c[0], &v[n]);
            ge_dsm_precomp(c[1], &v[sz + n]);
            ge_double_scalarmult_precomp_vartime2_p3(&v[n], a.bytes, c[0], b.bytes, c[1]);
        }
        v.resize(sz);
    }

    // Add vectors componentwise
    static keyV vector_add(const keyV& a, const keyV& b)
    {
        CHECK_THROW_ERR(a.size() == b.size(), "Incompatible sizes of a and b");
        keyV res(a.size());
        for (size_t i = 0; i < a.size(); ++i)
        {
            sc_add(res[i].bytes, a[i].bytes, b[i].bytes);
        }
        return res;
    }

    // Add a scalar to all elements of a vector
    static keyV vector_add(const keyV& a, const key& b)
    {
        keyV res(a.size());
        for (size_t i = 0; i < a.size(); ++i)
        {
            sc_add(res[i].bytes, a[i].bytes, b.bytes);
        }
        return res;
    }

    // Subtract a scalar from all elements of a vector
    static keyV vector_subtract(const keyV& a, const key& b)
    {
        keyV res(a.size());
        for (size_t i = 0; i < a.size(); ++i)
        {
            sc_sub(res[i].bytes, a[i].bytes, b.bytes);
        }
        return res;
    }

    // Multiply a scalar by all elements of a vector
    static keyV vector_scalar(const tools::span<const key>& a, const key& x)
    {
        keyV res(a.size());
        for (size_t i = 0; i < a.size(); ++i)
        {
            sc_mul(res[i].bytes, a[i].bytes, x.bytes);
        }
        return res;
    }

    // Inversion helper function
    static key sm(key y, int n, const key& x)
    {
        while (n--)
            sc_mul(y.bytes, y.bytes, y.bytes);
        sc_mul(y.bytes, y.bytes, x.bytes);
        return y;
    }

    // Compute the inverse of a nonzero
    static key invert(const key& x)
    {
        CHECK_THROW_ERR(!(x == ZERO), "Cannot invert zero!");
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

        return inv;
    }

    // Invert a batch of scalars, all of which _must_ be nonzero
    static keyV invert(keyV x)
    {
        keyV scratch;
        scratch.reserve(x.size());

        key acc = identity();
        for (size_t n = 0; n < x.size(); ++n)
        {
            CHECK_THROW_ERR(!(x[n] == ZERO), "Cannot invert zero!");
            scratch.push_back(acc);
            if (n == 0)
                acc = x[0];
            else
                sc_mul(acc.bytes, acc.bytes, x[n].bytes);
        }

        acc = invert(acc);

        key tmp;
        for (int i = x.size(); i-- > 0; )
        {
            sc_mul(tmp.bytes, acc.bytes, x[i].bytes);
            sc_mul(x[i].bytes, acc.bytes, scratch[i].bytes);
            acc = tmp;
        }

        return x;
    }

    // Compute the slice of a vector
    static tools::span<const key> slice(const keyV& a, size_t start, size_t stop)
    {
        CHECK_THROW_ERR(start < a.size(), "Invalid start index");
        CHECK_THROW_ERR(stop <= a.size(), "Invalid stop index");
        CHECK_THROW_ERR(start < stop, "Invalid start/stop indices");
        return tools::span<const key>(&a[start], stop - start);
    }

    // Update the transcript
    static key transcript_update(key& transcript, const key& update_0)
    {
        key data[2];
        data[0] = transcript;
        data[1] = update_0;
        hash_to_scalar(transcript, data, sizeof(data));
        return transcript;
    }

    static key transcript_update(key& transcript, const key& update_0, const key& update_1)
    {
        key data[3];
        data[0] = transcript;
        data[1] = update_0;
        data[2] = update_1;
        hash_to_scalar(transcript, data, sizeof(data));
        return transcript;
    }

    // Given a value v [0..2**N) and a mask gamma, construct a range proof
    BulletproofPlus bulletproof_plus_PROVE(const key& sv, const key& gamma)
    {
        return bulletproof_plus_PROVE(keyV(1, sv), keyV(1, gamma));
    }

    BulletproofPlus bulletproof_plus_PROVE(uint64_t v, const key& gamma)
    {
        return bulletproof_plus_PROVE(std::vector<uint64_t>(1, v), keyV(1, gamma));
    }

    // Given a set of values v [0..2**N) and masks gamma, construct a range proof
    BulletproofPlus bulletproof_plus_PROVE(const keyV& sv, const keyV& gamma)
    {
        // Sanity check on inputs
        CHECK_THROW_ERR(sv.size() == gamma.size(), "Incompatible sizes of sv and gamma");
        CHECK_THROW_ERR(!sv.empty(), "sv is empty");
        for (const key& sve : sv)
            CHECK_THROW_ERR(is_reduced(sve), "Invalid sv input");
        for (const key& g : gamma)
            CHECK_THROW_ERR(is_reduced(g), "Invalid gamma input");

        init_exponents();

        // Useful proof bounds
        //
        // N: number of bits in each range (here, 64)
        // logN: base-2 logarithm
        // M: first power of 2 greater than or equal to the number of range proofs to aggregate
        // logM: base-2 logarithm
        constexpr size_t logN = 6; // log2(64)
        constexpr size_t N = 1 << logN;
        size_t M, logM;
        for (logM = 0; (M = 1 << logM) <= maxM && M < sv.size(); ++logM);
        CHECK_THROW_ERR(M <= maxM, "sv/gamma are too large");
        const size_t logMN = logM + logN;
        const size_t MN = M * N;

        keyV V(sv.size());
        keyV aL(MN), aR(MN);
        keyV aL8(MN), aR8(MN);
        key temp;
        key temp2;

        // Prepare output commitments and offset by a factor of 8**(-1)
        //
        // This offset is applied to other group elements as well;
        //  it allows us to apply a multiply-by-8 operation in the verifier efficiently
        //  to ensure that the resulting group elements are in the prime-order point subgroup
        //  and avoid much more constly multiply-by-group-order operations.
        for (size_t i = 0; i < sv.size(); ++i)
        {
            key gamma8, sv8;
            sc_mul(gamma8.bytes, gamma[i].bytes, INV_EIGHT.bytes);
            sc_mul(sv8.bytes, sv[i].bytes, INV_EIGHT.bytes);
            add_keys2(V[i], gamma8, sv8, H);
        }

        // Decompose values
        //
        // Note that this effectively pads the set to a power of 2, which is required for the inner-product argument later.
        for (size_t j = 0; j < M; ++j)
        {
            for (size_t i = N; i-- > 0; )
            {
                if (j < sv.size() && (sv[j][i / 8] & (((uint64_t)1) << (i % 8))))
                {
                    aL[j * N + i] = identity();
                    aL8[j * N + i] = INV_EIGHT;
                    aR[j * N + i] = aR8[j * N + i] = zero();
                }
                else
                {
                    aL[j * N + i] = aL8[j * N + i] = zero();
                    aR[j * N + i] = MINUS_ONE;
                    aR8[j * N + i] = MINUS_INV_EIGHT;
                }
            }
        }

    try_again:
        // This is a Fiat-Shamir transcript
        key transcript = copy(initial_transcript);
        transcript = transcript_update(transcript, hash_to_scalar(V));

        // A
        key alpha = skgen();
        key pre_A = vector_exponent(aL8, aR8);
        key A;
        sc_mul(temp.bytes, alpha.bytes, INV_EIGHT.bytes);
        add_keys(A, pre_A, scalarmult_base(temp));

        // Challenges
        key y = transcript_update(transcript, A);
        if (y == zero())
        {
            goto try_again;
        }
        key z = transcript = hash_to_scalar(y);
        if (z == zero())
        {
            goto try_again;
        }
        key z_squared;
        sc_mul(z_squared.bytes, z.bytes, z.bytes);

        // Windowed vector
        // d[j*N+i] = z**(2*(j+1)) * 2**i
        //
        // We compute this iteratively in order to reduce scalar operations.
        keyV d(MN, zero());
        d[0] = z_squared;
        for (size_t i = 1; i < N; i++)
        {
            sc_mul(d[i].bytes, d[i - 1].bytes, TWO.bytes);
        }

        for (size_t j = 1; j < M; j++)
        {
            for (size_t i = 0; i < N; i++)
            {
                sc_mul(d[j * N + i].bytes, d[(j - 1) * N + i].bytes, z_squared.bytes);
            }
        }

        keyV y_powers = vector_of_scalar_powers(y, MN + 2);

        // Prepare inner product terms
        keyV aL1 = vector_subtract(aL, z);

        keyV aR1 = vector_add(aR, z);
        keyV d_y(MN);
        for (size_t i = 0; i < MN; i++)
        {
            sc_mul(d_y[i].bytes, d[i].bytes, y_powers[MN - i].bytes);
        }
        aR1 = vector_add(aR1, d_y);

        key alpha1 = alpha;
        temp = ONE;
        for (size_t j = 0; j < sv.size(); j++)
        {
            sc_mul(temp.bytes, temp.bytes, z_squared.bytes);
            sc_mul(temp2.bytes, y_powers[MN + 1].bytes, temp.bytes);
            sc_mul(temp2.bytes, temp2.bytes, gamma[j].bytes);
            sc_add(alpha1.bytes, alpha1.bytes, temp2.bytes);
        }

        // These are used in the inner product rounds
        size_t nprime = MN;
        std::vector<ge_p3> Gprime(MN);
        std::vector<ge_p3> Hprime(MN);
        keyV aprime(MN);
        keyV bprime(MN);

        const key yinv = invert(y);
        keyV yinvpow(MN);
        yinvpow[0] = ONE;
        for (size_t i = 0; i < MN; ++i)
        {
            Gprime[i] = Gi_p3[i];
            Hprime[i] = Hi_p3[i];
            if (i > 0)
            {
                sc_mul(yinvpow[i].bytes, yinvpow[i - 1].bytes, yinv.bytes);
            }
            aprime[i] = aL1[i];
            bprime[i] = aR1[i];
        }
        keyV L(logMN);
        keyV R(logMN);
        int round = 0;

        // Inner-product rounds
        while (nprime > 1)
        {
            nprime /= 2;

            key cL = weighted_inner_product(slice(aprime, 0, nprime), slice(bprime, nprime, bprime.size()), y);
            key cR = weighted_inner_product(vector_scalar(slice(aprime, nprime, aprime.size()), y_powers[nprime]), slice(bprime, 0, nprime), y);

            key dL = skgen();
            key dR = skgen();

            L[round] = compute_LR(nprime, yinvpow[nprime], Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, cL, dL);
            R[round] = compute_LR(nprime, y_powers[nprime], Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, cR, dR);

            const key challenge = transcript_update(transcript, L[round], R[round]);
            if (challenge == zero())
            {
                goto try_again;
            }

            const key challenge_inv = invert(challenge);

            sc_mul(temp.bytes, yinvpow[nprime].bytes, challenge.bytes);
            hadamard_fold(Gprime, challenge_inv, temp);
            hadamard_fold(Hprime, challenge, challenge_inv);

            sc_mul(temp.bytes, challenge_inv.bytes, y_powers[nprime].bytes);
            aprime = vector_add(vector_scalar(slice(aprime, 0, nprime), challenge), vector_scalar(slice(aprime, nprime, aprime.size()), temp));
            bprime = vector_add(vector_scalar(slice(bprime, 0, nprime), challenge_inv), vector_scalar(slice(bprime, nprime, bprime.size()), challenge));

            key challenge_squared;
            sc_mul(challenge_squared.bytes, challenge.bytes, challenge.bytes);
            key challenge_squared_inv = invert(challenge_squared);
            sc_muladd(alpha1.bytes, dL.bytes, challenge_squared.bytes, alpha1.bytes);
            sc_muladd(alpha1.bytes, dR.bytes, challenge_squared_inv.bytes, alpha1.bytes);

            ++round;
        }

        // Final round computations
        key r = skgen();
        key s = skgen();
        key d_ = skgen();
        key eta = skgen();

        std::vector<MultiexpData> A1_data;
        A1_data.reserve(4);
        A1_data.resize(4);

        sc_mul(A1_data[0].scalar.bytes, r.bytes, INV_EIGHT.bytes);
        A1_data[0].point = Gprime[0];

        sc_mul(A1_data[1].scalar.bytes, s.bytes, INV_EIGHT.bytes);
        A1_data[1].point = Hprime[0];

        sc_mul(A1_data[2].scalar.bytes, d_.bytes, INV_EIGHT.bytes);
        ge_p3 G_p3;
        ge_frombytes_vartime(&G_p3, G.bytes);
        A1_data[2].point = G_p3;

        sc_mul(temp.bytes, r.bytes, y.bytes);
        sc_mul(temp.bytes, temp.bytes, bprime[0].bytes);
        sc_mul(temp2.bytes, s.bytes, y.bytes);
        sc_mul(temp2.bytes, temp2.bytes, aprime[0].bytes);
        sc_add(temp.bytes, temp.bytes, temp2.bytes);
        sc_mul(A1_data[3].scalar.bytes, temp.bytes, INV_EIGHT.bytes);
        ge_p3 H_p3;
        ge_frombytes_vartime(&H_p3, H.bytes);
        A1_data[3].point = H_p3;

        key A1 = multiexp(A1_data, 0);

        sc_mul(temp.bytes, r.bytes, y.bytes);
        sc_mul(temp.bytes, temp.bytes, s.bytes);
        sc_mul(temp.bytes, temp.bytes, INV_EIGHT.bytes);
        sc_mul(temp2.bytes, eta.bytes, INV_EIGHT.bytes);
        key B;
        add_keys2(B, temp2, temp, H);

        key e = transcript_update(transcript, A1, B);
        if (e == zero())
        {
            goto try_again;
        }
        key e_squared;
        sc_mul(e_squared.bytes, e.bytes, e.bytes);

        key r1;
        sc_muladd(r1.bytes, aprime[0].bytes, e.bytes, r.bytes);

        key s1;
        sc_muladd(s1.bytes, bprime[0].bytes, e.bytes, s.bytes);

        key d1;
        sc_muladd(d1.bytes, d_.bytes, e.bytes, eta.bytes);
        sc_muladd(d1.bytes, alpha1.bytes, e_squared.bytes, d1.bytes);

        return BulletproofPlus(std::move(V), A, A1, B, r1, s1, d1, std::move(L), std::move(R));
    }

    BulletproofPlus bulletproof_plus_PROVE(const std::vector<uint64_t>& v, const keyV& gamma)
    {
        CHECK_THROW_ERR(v.size() == gamma.size(), "Incompatible sizes of v and gamma");

        // vG + gammaH
        keyV sv(v.size());
        for (size_t i = 0; i < v.size(); ++i)
        {
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
        return bulletproof_plus_PROVE(sv, gamma);
    }

    struct bp_plus_proof_data_t
    {
        key y, z, e;
        std::vector<key> challenges;
        size_t logM, inv_offset;
    };

    // Given a batch of range proofs, determine if they are all valid
    bool bulletproof_plus_VERIFY(const std::vector<const BulletproofPlus*>& proofs)
    {
        init_exponents();

        const size_t logN = 6;
        const size_t N = 1 << logN;

        // Set up
        size_t max_length = 0; // size of each of the longest proof's inner-product vectors
        size_t nV = 0; // number of output commitments across all proofs
        size_t inv_offset = 0;
        size_t max_logM = 0;

        std::vector<bp_plus_proof_data_t> proof_data;
        proof_data.reserve(proofs.size());

        // We'll perform only a single batch inversion across all proofs in the batch,
        //  since batch inversion requires only one scalar inversion operation.
        std::vector<key> to_invert;
        to_invert.reserve(11 * sizeof(proofs)); // maximal size, given the aggregation limit

        for (const BulletproofPlus* p : proofs)
        {
            const BulletproofPlus& proof = *p;

            // Sanity checks
            CHECK_ASSERT(is_reduced(proof.r1), false, "Input scalar not in range");
            CHECK_ASSERT(is_reduced(proof.s1), false, "Input scalar not in range");
            CHECK_ASSERT(is_reduced(proof.d1), false, "Input scalar not in range");

            CHECK_ASSERT(proof.V.size() >= 1, false, "V does not have at least one element");
            CHECK_ASSERT(proof.L.size() == proof.R.size(), false, "Mismatched L and R sizes");
            CHECK_ASSERT(proof.L.size() > 0, false, "Empty proof");

            max_length = std::max(max_length, proof.L.size());
            nV += proof.V.size();

            bp_plus_proof_data_t pd;

            // Reconstruct the challenges
            key transcript = copy(initial_transcript);
            transcript = transcript_update(transcript, hash_to_scalar(proof.V));
            pd.y = transcript_update(transcript, proof.A);
            CHECK_ASSERT(!(pd.y == zero()), false, "y == 0");
            pd.z = transcript = hash_to_scalar(pd.y);
            CHECK_ASSERT(!(pd.z == zero()), false, "z == 0");

            // Determine the number of inner-product rounds based on proof size
            size_t M;
            for (pd.logM = 0; (M = 1 << pd.logM) <= maxM && M < proof.V.size(); ++pd.logM);
            CHECK_ASSERT(proof.L.size() == 6 + pd.logM, false, "Proof is not the expected size");
            max_logM = std::max(pd.logM, max_logM);

            const size_t rounds = pd.logM + logN;
            CHECK_ASSERT(rounds > 0, false, "Zero rounds");

            // The inner-product challenges are computed per round
            pd.challenges.resize(rounds);
            for (size_t j = 0; j < rounds; ++j)
            {
                pd.challenges[j] = transcript_update(transcript, proof.L[j], proof.R[j]);
                CHECK_ASSERT(!(pd.challenges[j] == zero()), false, "challenges[j] == 0");
            }

            // Final challenge
            pd.e = transcript_update(transcript, proof.A1, proof.B);
            CHECK_ASSERT(!(pd.e == zero()), false, "e == 0");

            // Batch scalar inversions
            pd.inv_offset = inv_offset;
            for (size_t j = 0; j < rounds; ++j)
                to_invert.push_back(pd.challenges[j]);
            to_invert.push_back(pd.y);
            inv_offset += rounds + 1;
            proof_data.push_back(pd);
        }
        CHECK_ASSERT(max_length < 32, false, "At least one proof is too large");
        size_t maxMN = 1u << max_length;

        key temp;
        key temp2;

        // Final batch proof data
        std::vector<MultiexpData> multiexp_data;
        multiexp_data.reserve(nV + (2 * (max_logM + logN) + 3) * proofs.size() + 2 * maxMN);
        multiexp_data.resize(2 * maxMN);

        const std::vector<key> inverses = invert(to_invert);

        // Weights and aggregates
        //
        // The idea is to take the single multiscalar multiplication used in the verification
        //  of each proof in the batch and weight it using a random weighting factor, resulting
        //  in just one multiscalar multiplication check to zero for the entire batch.
        // We can further simplify the verifier complexity by including common group elements
        //  only once in this single multiscalar multiplication.
        // Common group elements' weighted scalar sums are tracked across proofs for this reason.
        //
        // To build a multiscalar multiplication for each proof, we use the method described in
        //  Section 6.1 of the preprint. Note that the result given there does not account for
        //  the construction of the inner-product inputs that are produced in the range proof
        //  verifier algorithm; we have done so here.
        key G_scalar = zero();
        key H_scalar = zero();
        keyV Gi_scalars(maxMN, zero());
        keyV Hi_scalars(maxMN, zero());

        int proof_data_index = 0;
        keyV challenges_cache;
        std::vector<ge_p3> proof8_V, proof8_L, proof8_R;

        // Process each proof and add to the weighted batch
        for (const BulletproofPlus* p : proofs)
        {
            const BulletproofPlus& proof = *p;
            const bp_plus_proof_data_t& pd = proof_data[proof_data_index++];

            CHECK_ASSERT(proof.L.size() == 6 + pd.logM, false, "Proof is not the expected size");
            const size_t M = 1 << pd.logM;
            const size_t MN = M * N;

            // Random weighting factor must be nonzero, which is exceptionally unlikely!
            key weight = ZERO;
            while (weight == ZERO)
            {
                weight = skgen();
            }

            // Rescale previously offset proof elements
            //
            // This ensures that all such group elements are in the prime-order subgroup.
            proof8_V.resize(proof.V.size()); for (size_t i = 0; i < proof.V.size(); ++i) scalarmult_8(proof8_V[i], proof.V[i]);
            proof8_L.resize(proof.L.size()); for (size_t i = 0; i < proof.L.size(); ++i) scalarmult_8(proof8_L[i], proof.L[i]);
            proof8_R.resize(proof.R.size()); for (size_t i = 0; i < proof.R.size(); ++i) scalarmult_8(proof8_R[i], proof.R[i]);
            ge_p3 proof8_A1;
            ge_p3 proof8_B;
            ge_p3 proof8_A;
            scalarmult_8(proof8_A1, proof.A1);
            scalarmult_8(proof8_B, proof.B);
            scalarmult_8(proof8_A, proof.A);

            // Compute necessary powers of the y-challenge
            key y_MN = copy(pd.y);
            key y_MN_1;
            size_t temp_MN = MN;
            while (temp_MN > 1)
            {
                sc_mul(y_MN.bytes, y_MN.bytes, y_MN.bytes);
                temp_MN /= 2;
            }
            sc_mul(y_MN_1.bytes, y_MN.bytes, pd.y.bytes);

            // V_j: -e**2 * z**(2*j+1) * y**(MN+1) * weight
            key e_squared;
            sc_mul(e_squared.bytes, pd.e.bytes, pd.e.bytes);

            key z_squared;
            sc_mul(z_squared.bytes, pd.z.bytes, pd.z.bytes);

            sc_sub(temp.bytes, ZERO.bytes, e_squared.bytes);
            sc_mul(temp.bytes, temp.bytes, y_MN_1.bytes);
            sc_mul(temp.bytes, temp.bytes, weight.bytes);
            for (size_t j = 0; j < proof8_V.size(); j++)
            {
                sc_mul(temp.bytes, temp.bytes, z_squared.bytes);
                multiexp_data.emplace_back(temp, proof8_V[j]);
            }

            // B: -weight
            sc_mul(temp.bytes, MINUS_ONE.bytes, weight.bytes);
            multiexp_data.emplace_back(temp, proof8_B);

            // A1: -weight*e
            sc_mul(temp.bytes, temp.bytes, pd.e.bytes);
            multiexp_data.emplace_back(temp, proof8_A1);

            // A: -weight*e*e
            key minus_weight_e_squared;
            sc_mul(minus_weight_e_squared.bytes, temp.bytes, pd.e.bytes);
            multiexp_data.emplace_back(minus_weight_e_squared, proof8_A);

            // G: weight*d1
            sc_muladd(G_scalar.bytes, weight.bytes, proof.d1.bytes, G_scalar.bytes);

            // Windowed vector
            // d[j*N+i] = z**(2*(j+1)) * 2**i
            keyV d(MN, zero());
            d[0] = z_squared;
            for (size_t i = 1; i < N; i++)
            {
                sc_add(d[i].bytes, d[i - 1].bytes, d[i - 1].bytes);
            }

            for (size_t j = 1; j < M; j++)
            {
                for (size_t i = 0; i < N; i++)
                {
                    sc_mul(d[j * N + i].bytes, d[(j - 1) * N + i].bytes, z_squared.bytes);
                }
            }

            // More efficient computation of sum(d)
            key sum_d;
            sc_mul(sum_d.bytes, TWO_SIXTY_FOUR_MINUS_ONE.bytes, sum_of_even_powers(pd.z, 2 * M).bytes);

            // H: weight*( r1*y*s1 + e**2*( y**(MN+1)*z*sum(d) + (z**2-z)*sum(y) ) )
            key sum_y = sum_of_scalar_powers(pd.y, MN);
            sc_sub(temp.bytes, z_squared.bytes, pd.z.bytes);
            sc_mul(temp.bytes, temp.bytes, sum_y.bytes);

            sc_mul(temp2.bytes, y_MN_1.bytes, pd.z.bytes);
            sc_mul(temp2.bytes, temp2.bytes, sum_d.bytes);
            sc_add(temp.bytes, temp.bytes, temp2.bytes);
            sc_mul(temp.bytes, temp.bytes, e_squared.bytes);
            sc_mul(temp2.bytes, proof.r1.bytes, pd.y.bytes);
            sc_mul(temp2.bytes, temp2.bytes, proof.s1.bytes);
            sc_add(temp.bytes, temp.bytes, temp2.bytes);
            sc_muladd(H_scalar.bytes, temp.bytes, weight.bytes, H_scalar.bytes);

            // Compute the number of rounds for the inner-product argument
            const size_t rounds = pd.logM + logN;
            CHECK_ASSERT(rounds > 0, false, "Zero rounds");

            const key* challenges_inv = &inverses[pd.inv_offset];
            const key yinv = inverses[pd.inv_offset + rounds];

            // Compute challenge products
            challenges_cache.resize(1 << rounds);
            challenges_cache[0] = challenges_inv[0];
            challenges_cache[1] = pd.challenges[0];
            for (size_t j = 1; j < rounds; ++j)
            {
                const size_t slots = 1 << (j + 1);
                for (size_t s = slots; s-- > 0; --s)
                {
                    sc_mul(challenges_cache[s].bytes, challenges_cache[s / 2].bytes, pd.challenges[j].bytes);
                    sc_mul(challenges_cache[s - 1].bytes, challenges_cache[s / 2].bytes, challenges_inv[j].bytes);
                }
            }

            // Gi and Hi
            key e_r1_w_y;
            sc_mul(e_r1_w_y.bytes, pd.e.bytes, proof.r1.bytes);
            sc_mul(e_r1_w_y.bytes, e_r1_w_y.bytes, weight.bytes);
            key e_s1_w;
            sc_mul(e_s1_w.bytes, pd.e.bytes, proof.s1.bytes);
            sc_mul(e_s1_w.bytes, e_s1_w.bytes, weight.bytes);
            key e_squared_z_w;
            sc_mul(e_squared_z_w.bytes, e_squared.bytes, pd.z.bytes);
            sc_mul(e_squared_z_w.bytes, e_squared_z_w.bytes, weight.bytes);
            key minus_e_squared_z_w;
            sc_sub(minus_e_squared_z_w.bytes, ZERO.bytes, e_squared_z_w.bytes);
            key minus_e_squared_w_y;
            sc_sub(minus_e_squared_w_y.bytes, ZERO.bytes, e_squared.bytes);
            sc_mul(minus_e_squared_w_y.bytes, minus_e_squared_w_y.bytes, weight.bytes);
            sc_mul(minus_e_squared_w_y.bytes, minus_e_squared_w_y.bytes, y_MN.bytes);
            for (size_t i = 0; i < MN; ++i)
            {
                key g_scalar = copy(e_r1_w_y);
                key h_scalar;

                // Use the binary decomposition of the index
                sc_muladd(g_scalar.bytes, g_scalar.bytes, challenges_cache[i].bytes, e_squared_z_w.bytes);
                sc_muladd(h_scalar.bytes, e_s1_w.bytes, challenges_cache[(~i) & (MN - 1)].bytes, minus_e_squared_z_w.bytes);

                // Complete the scalar derivation
                sc_add(Gi_scalars[i].bytes, Gi_scalars[i].bytes, g_scalar.bytes);
                sc_muladd(h_scalar.bytes, minus_e_squared_w_y.bytes, d[i].bytes, h_scalar.bytes);
                sc_add(Hi_scalars[i].bytes, Hi_scalars[i].bytes, h_scalar.bytes);

                // Update iterated values
                sc_mul(e_r1_w_y.bytes, e_r1_w_y.bytes, yinv.bytes);
                sc_mul(minus_e_squared_w_y.bytes, minus_e_squared_w_y.bytes, yinv.bytes);
            }

            // L_j: -weight*e*e*challenges[j]**2
            // R_j: -weight*e*e*challenges[j]**(-2)
            for (size_t j = 0; j < rounds; ++j)
            {
                sc_mul(temp.bytes, pd.challenges[j].bytes, pd.challenges[j].bytes);
                sc_mul(temp.bytes, temp.bytes, minus_weight_e_squared.bytes);
                multiexp_data.emplace_back(temp, proof8_L[j]);

                sc_mul(temp.bytes, challenges_inv[j].bytes, challenges_inv[j].bytes);
                sc_mul(temp.bytes, temp.bytes, minus_weight_e_squared.bytes);
                multiexp_data.emplace_back(temp, proof8_R[j]);
            }
        }

        // Verify all proofs in the weighted batch
        multiexp_data.emplace_back(G_scalar, G);
        multiexp_data.emplace_back(H_scalar, H);
        for (size_t i = 0; i < maxMN; ++i)
        {
            multiexp_data[i * 2] = { Gi_scalars[i], Gi_p3[i] };
            multiexp_data[i * 2 + 1] = { Hi_scalars[i], Hi_p3[i] };
        }
        if (!(multiexp(multiexp_data, 2 * maxMN) == identity()))
        {
            return false;
        }

        return true;
    }

    bool bulletproof_plus_VERIFY(const std::vector<BulletproofPlus>& proofs)
    {
        std::vector<const BulletproofPlus*> proof_pointers;
        proof_pointers.reserve(proofs.size());
        for (const BulletproofPlus& proof : proofs)
            proof_pointers.push_back(&proof);
        return bulletproof_plus_VERIFY(proof_pointers);
    }

    bool bulletproof_plus_VERIFY(const BulletproofPlus& proof)
    {
        std::vector<const BulletproofPlus*> proofs;
        proofs.push_back(&proof);
        return bulletproof_plus_VERIFY(proofs);
    }
}

discore::ArgBulletproofPlus bulletproof_plus_prove(const uint64_t v[16], const discore::key16 gamma, uint64_t size)
{
    discore::ArgBulletproofPlus bp = { 0 };

    discore::keyV gamma_(size);
    std::vector<uint64_t> val(size);

    for (unsigned int i = 0; i < size; i++) {
        val[i] = v[i];
        gamma_[i] = gamma[i];
    }

    discore::BulletproofPlus bp_ = discore::bulletproof_plus_PROVE(val, gamma_);

    for (unsigned int i = 0; i < bp_.V.size(); i++) {
        bp.V[i] = bp_.V[i];
    }

    for (unsigned int i = 0; i < bp_.L.size(); i++) {
        bp.L[i] = bp_.L[i];
        bp.R[i] = bp_.R[i];
    }

    bp.A = bp_.A;
    bp.A1 = bp_.A1;
    bp.B = bp_.B;
    bp.r1 = bp_.r1;
    bp.s1 = bp_.s1;
    bp.d1 = bp_.d1;

    bp.size = bp_.V.size();

    return bp;
}

bool bulletproof_plus_verify(discore::ArgBulletproofPlus bp)
{
    discore::BulletproofPlus bp_ = discore::BulletproofPlus();

    bp_.A = bp.A;
    bp_.A1 = bp.A1;
    bp_.B = bp.B;
    bp_.r1 = bp.r1;
    bp_.s1 = bp.s1;
    bp_.d1 = bp.d1;

    int size = (bp.size > 8 ? 10 : (bp.size > 4 ? 9 : (bp.size > 2 ? 8 : (bp.size > 1 ? 7 : 6))));

    bp_.L = discore::keyV(size);
    bp_.R = discore::keyV(size);

    for (int i = 0; i < size; i++) {
        bp_.L[i] = bp.L[i];
        bp_.R[i] = bp.R[i];
    }

    bp_.V = discore::keyV((unsigned int)bp.size);

    for (int i = 0; i < bp.size; i++) {
        discore::key tmp = discore::scalarmult_key(bp.V[i], discore::INV_EIGHT);
        bp_.V[i] = tmp;
    }

    bool test = discore::bulletproof_plus_VERIFY(bp_);

    return test;
}