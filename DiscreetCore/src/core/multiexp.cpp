#include <algorithm>

#include "ops.h"
#include "multiexp.h"

extern "C" {
#include "util/aligned.h"
#include "crypto_curve.h"
}

#define RAW_MEMORY_BLOCK
//#define ALTERNATE_LAYOUT
//#define TRACK_STRAUS_ZERO_IDENTITY

namespace discore {
    static inline bool operator<(const key &k0, const key &k1)
    {
        for (int n = 31; n >= 0; n--)
        {
            if (k0.bytes[n] < k1.bytes[n])
                return true;
            if (k0.bytes[n] > k1.bytes[n])
                return false;
        }
        return false;
    }

    static inline key div2(const key &k)
    {
        key res;
        int carry = 0;
        for (int n = 31; n >= 0; n--)
        {
            int new_carry = (k.bytes[n] & 1) << 7;
            res.bytes[n] = k.bytes[n] / 2 + carry;
            carry = new_carry;
        }
        return res;
    }

    static inline key pow2(size_t n)
    {
        CHECK_THROW_ERR(n < 256, "invalid pow2 argument");
        key res = zero();
        res[n >> 3] |= 1<<(n&7);
        return res;
    }

    static inline int test(const key &k, size_t n)
    {
        if (n >= 256) return 0;
        return k[n >> 3] & (1 << (n & 7));
    }

    static inline void add(ge_p3 &p3, const ge_cached &other)
    {
        ge_p1p1 p1;
        ge_add(&p1, &p3, &other);
        ge_p1p1_to_p3(&p3, &p1);
    }

    static inline void add(ge_p3 &p3, const ge_p3 &other)
    {
        ge_cached cached;
        ge_p3_to_cached(&cached, &other);
        add(p3, cached);
    }

    key heap_conv(std::vector<multiexp_data> data)
    {
        size_t points = data.size();
        CHECK_THROW_ERR(points > 1, "not enough points for heap_conv");
        std::vector<size_t> heap(points);

        for (size_t n = 0; n < points; n++) {
            heap[n] = n;
        }

        auto Comp = [&](size_t e0, size_t e1) {
            return data[e0].scalar < data[e1].scalar;
        };

        std::make_heap(heap.begin(), heap.end(), Comp);

        while(heap.size() > 1) {
            std::pop_heap(heap.begin(), heap.end(), Comp);
            size_t index1 = heap.back();
            heap.pop_back();
            std::pop_heap(heap.begin(), heap.end(), Comp);
            size_t index2 = heap.back();
            heap.pop_back();

            ge_cached cached;
            ge_p3_to_cached(&cached, &data[index1].point);
            ge_p1p1 p1;
            ge_add(&p1, &data[index2].point, &cached);
            ge_p1p1_to_p3(&data[index2].point, &p1);

            sc_sub(data[index1].scalar.bytes, data[index1].scalar.bytes, data[index2].scalar.bytes);

            if (!(data[index1].scalar == zero()))
            {
                heap.push_back(index1);
                std::push_heap(heap.begin(), heap.end(), Comp);
            }

            heap.push_back(index2);
            std::push_heap(heap.begin(), heap.end(), Comp);
        }

        std::pop_heap(heap.begin(), heap.end(), Comp);
        size_t index = heap.back();
        heap.pop_back();

        ge_p2 p2;
        ge_scalarmult(&p2, data[index].scalar.bytes, &data[index].point);
        
        key res;
        ge_tobytes(res.bytes, &p2);
        return res;
    }

    key heap_conv_robust(std::vector<multiexp_data> data)
    {
        size_t points = data.size();
        CHECK_THROW_ERR(points > 1, "not enough points for heap_conv_robust");
        std::vector<size_t> heap;
        heap.reserve(points);

        for (size_t n = 0; n < points; n++) {
            if(!(data[n].scalar == zero()) && !ge_p3_is_point_at_infinity(&data[n].point))
                heap.push_back(n);
        }

        points = heap.size();
        if (points == 0)
            return identity();

        auto Comp = [&](size_t e0, size_t e1) {
            return data[e0].scalar < data[e1].scalar;
        };

        std::make_heap(heap.begin(), heap.end(), Comp);

        if (points < 2) {
            std::pop_heap(heap.begin(), heap.end(), Comp);
            size_t index = heap.back();

            ge_p2 p2;
            ge_scalarmult(&p2, data[index].scalar.bytes, &data[index].point);
            
            key res;
            ge_tobytes(res.bytes, &p2);
            return res;
        }

        while(heap.size() > 1) {
            std::pop_heap(heap.begin(), heap.end(), Comp);
            size_t index1 = heap.back();
            heap.pop_back();
            std::pop_heap(heap.begin(), heap.end(), Comp);
            size_t index2 = heap.back();
            heap.pop_back();

            ge_cached cached;
            ge_p1p1 p1;
            ge_p2 p2;

            while (1) {
                key s1_2 = div2(data[index1].scalar);
                if (!(data[index2].scalar.bytes[0] & 1))
                    break;

                if (data[index1].scalar.bytes[0] & 1) {
                    data.resize(data.size() + 1);
                    data.back().scalar = identity();
                    data.back().point = data[index1].point;
                    heap.push_back(data.size() - 1);
                    std::push_heap(heap.begin(), heap.end(), Comp);
                }

                data[index1].scalar = div2(data[index1].scalar);
                ge_p3_to_p2(&p2, &data[index1].point);
                ge_p2_dbl(&p1, &p2);
                ge_p1p1_to_p3(&data[index1].point, &p1);
            }

            ge_p3_to_cached(&cached, &data[index1].point);
            ge_add(&p1, &data[index2].point, &cached);
            ge_p1p1_to_p3(&data[index2].point, &p1);

            sc_sub(data[index1].scalar.bytes, data[index1].scalar.bytes, data[index2].scalar.bytes);

            if (!(data[index1].scalar == zero()))
            {
                heap.push_back(index1);
                std::push_heap(heap.begin(), heap.end(), Comp);
            }

            heap.push_back(index2);
            std::push_heap(heap.begin(), heap.end(), Comp);
        }

        std::pop_heap(heap.begin(), heap.end(), Comp);
        size_t index = heap.back();
        heap.pop_back();

        ge_p2 p2;
        ge_scalarmult(&p2, data[index].scalar.bytes, &data[index].point);
        
        key res;
        ge_tobytes(res.bytes, &p2);
        return res;
    }

#define STRAUS_C 4

    struct straus_cache {
#ifdef RAW_MEMORY_BLOCK
        size_t size;
        ge_cached *multiples;
        straus_cache(): size(0), multiples(NULL) {}
        ~straus_cache() { aligned_free(multiples); }
#else 
        std::vector<std::vector<ge_cached>> multiples;
#endif
    };

#ifdef RAW_MEMORY_BLOCK
#ifdef ALTERNATE_LAYOUT
#define CACHE_OFFSET(cache, point, digit) cache->multiples[(point)*((1<<STRAUS_C)-1)+((digit)-1)]
#else
#define CACHE_OFFSET(cache, point, digit) cache->multiples[(point)+cache->size*((digit)-1)]
#endif
#else
#ifdef ALTERNATE_LAYOUT
#define CACHE_OFFSET(cache, point, digit) local_cache->multiples[j][digit-1]
#else
#define CACHE_OFFSET(cache, point, digit) local_cache->multiples[digit][j]
#endif
#endif

    std::shared_ptr<straus_cache> straus_init(const std::vector<multiexp_data> &data, size_t N)
    {
        if (N == 0)
            N = data.size();
        
        CHECK_THROW_ERR(N <= data.size(), "bad cache base data");

        ge_p1p1 p1;
        ge_p3 p3;
        std::shared_ptr<straus_cache> cache(new straus_cache());

#ifdef RAW_MEMORY_BLOCK
        const size_t offset = cache->size;
        cache->multiples = (ge_cached*)aligned_realloc(cache->multiples, sizeof(ge_cached)* ((1<<STRAUS_C)-1) * std::max(offset, N), 4096);
        CHECK_THROW_ERR(cache->multiples, "OOM: OUT OF MEMORY!");
        cache->size = N;

        for (size_t j = offset; j < N; j++) {
            ge_p3_to_cached(&CACHE_OFFSET(cache, j, 1), &data[j].point);

            for (size_t i = 2; i < 1<<STRAUS_C; i++) {
                ge_add(&p1, &data[j].point, &CACHE_OFFSET(cache, j, i-1));
                ge_p1p1_to_p3(&p3, &p1);
                ge_p3_to_cached(&CACHE_OFFSET(cache, j, i), &p3);
            }
        }
#else
#ifdef ALTERNATE_LAYOUT
        const size_t offset = cache->multiples.size();
        cache->multiples.resize(std::max(offset, N));
        for (size_t i = offset; i < N; i++) {
            cache->multiples[i].resize((1<<STRAUS_C)-1);
            ge_p3_to_cached(&cache->multiples[i][0], &data[i].point);

            for (size_t j = 2; j < 1<<STRAUS_C; j++) {
                ge_add(&p1, &data[i].point, &cache->multiples[i][j-2]);
                ge_p1p1_to_p3(&p3, &p1);
                ge_p3_to_cached(&cache->multiples[i][j-1], &p3);
            }
        }
#else
        cache->multiples.resize(1<<STRAUS_C);
        size_t offset = cache->multiples[1].size();
        cache->multiples[1].resize(std::max(offset, N));

        for (size_t i = offset; i < N; i++) {
            ge_p3_to_cached(&cache->multiples[1][i], &data[i].point);
        }

        for (size_t i = 2; i < 1<<STRAUS_C; i++) {
            cache->multiples[i].resize(std::max(offset, N));
        }

        for (size_t j = offset; j < N; j++) {
            for (size_t i = 2; i < 1<<STRAUS_C; i++) {
                ge_add(&p1, &data[j].point, &cache->multiples[i-1][j]);
                ge_p1p1_to_p3(&p3, &p1);
                ge_p3_to_cached(&cache->multiples[i][j], &p3);
            }
        }
#endif
#endif

        return cache;
    }

    size_t straus_get_cache_size(const std::shared_ptr<straus_cache> &cache)
    {
        size_t sz = 0;
#ifdef RAW_MEMORY_BLOCK
        sz += cache->size * sizeof(ge_cached) * ((1<<STRAUS_C)-1);
#else
        for (const auto &e0: cache->multiples) {
            sz += e0.size() * sizeof(ge_cached);
        }
#endif
        return sz;
    }

    key straus(const std::vector<multiexp_data> &data, const std::shared_ptr<straus_cache> &cache, size_t STEP)
    {
        CHECK_THROW_ERR(cache == NULL || cache->size >= data.size(), "cache is too small! (straus)");
        STEP = STEP ? STEP : 192;

        static constexpr unsigned int mask = (1<<STRAUS_C)-1;
        std::shared_ptr<straus_cache> local_cache = cache == NULL ? straus_init(data) : cache;
        ge_cached cached;
        ge_p1p1 p1;

#ifdef TRACK_STRAUS_ZERO_IDENTITY
        std::vector<uint8_t> skip(data.size());
        for (size_t i = 0; i < data.size(); i++) {
            skip[i] = data[i].scalar == zero() || ge_p3_is_point_at_infinity(&data[i].point);
        }
#endif

#if STRAUS_C==4
        std::unique_ptr<uint8_t[]> digits{new uint8_t[64 * data.size()]};
#else
        std::unique_ptr<uint8_t[]> digits{new uint8_t[256 * data.size()]};
#endif
        for (size_t j = 0; j < data.size(); j++) {
            const unsigned char *bytes = data[j].scalar.bytes;
#if STRAUS_C==4
            unsigned int i;
            for (i = 0; i < 64; i += 2, bytes++) {
                digits[j*64+i] = bytes[0] & 0xf;
                digits[j*64+i+1] = bytes[0] >> 4;
            }
#elif 1
            unsigned char bytes33[33];
            memcpy(bytes33,  data[j].scalar.bytes, 32);
            bytes33[32] = 0;
            bytes = bytes33;
            for (size_t i = 0; i < 256; i++) {
                digits[j*256+i] = ((bytes[i>>3] | (bytes[(i>>3)+1]<<8)) >> (i&7)) & mask;
            }
#else
            key shifted = data[j].scalar;
            for (size_t i = 0; i < 256; i++) {
                digits[j*256+i] = shifted.bytes[0] & 0xf;
                shifted = div2(shifted, (256-i)>>3);
            }
#endif
        }

        key maxscalar = zero();
        for (size_t i = 0; i < data.size(); i++) {
            if (maxscalar < data[i].scalar) {
                maxscalar = data[i].scalar;
            }
        }
        size_t start_i = 0;
        while (start_i < 256 && !(maxscalar < pow2(start_i))) {
            start_i += STRAUS_C;
        }

        ge_p3 res_p3 = ge_p3_identity;

        for (size_t start_offset = 0; start_offset < data.size(); start_offset += STEP) {
            const size_t num_points = std::min(data.size() - start_offset, STEP);

            ge_p3 band_p3 = ge_p3_identity;
            size_t i = start_i;

            if (!(i < STRAUS_C)) {
                goto skipfirst;
            }

            while (!(i < STRAUS_C)) {
                ge_p2 p2;
                ge_p3_to_p2(&p2, &band_p3);

                for (size_t j = 0; j < STRAUS_C; j++) {
                    ge_p2_dbl(&p1, &p2);

                    if (j == STRAUS_C - 1) {
                        ge_p1p1_to_p3(&band_p3, &p1);
                    }
                    else {
                        ge_p1p1_to_p2(&p2, &p1);
                    }
                }
skipfirst:
                i -= STRAUS_C;
                for (size_t j = start_offset; j < start_offset + num_points; j++) {
#ifdef TRACK_STRAUS_ZERO_IDENTITY
                    if (skip[j]) {
                        continue;
                    }
#endif
#if STRAUS_C==4 
                    const uint8_t digit = digits[j*64+i/4];
#else
                    const uint8_t digit = digits[j*256+i];
#endif
                    if (digit) {
                        ge_add(&p1, &band_p3, &CACHE_OFFSET(local_cache, j, digit));
                        ge_p1p1_to_p3(&band_p3, &p1);
                    }
                }
            }

            ge_p3_to_cached(&cached, &band_p3);
            ge_add(&p1, &res_p3, &cached);
            ge_p1p1_to_p3(&res_p3, &p1);
        }

        key res;
        ge_p3_tobytes(res.bytes, &res_p3);
        return res;
    }

    size_t get_pippenger_c(size_t N) 
    {
        if (N <= 13) return 2;
        if (N <= 29) return 3;
        if (N <= 83) return 4;
        if (N <= 185) return 5;
        if (N <= 465) return 6;
        if (N <= 1180) return 7;
        if (N <= 2295) return 8;
        return 9;
    }

    struct pippenger_cache {
        size_t size;
        ge_cached *cached;
        pippenger_cache(): size(0), cached(NULL) {}
        ~pippenger_cache() { aligned_free(cached); }
    };

    std::shared_ptr<pippenger_cache> pippenger_init(const std::vector<multiexp_data> &data, size_t start_offset, size_t N) 
    {
        CHECK_THROW_ERR(start_offset <= data.size(), "bad cache base data (pippenger_init)");
        if (N == 0) {
            N = data.size() - start_offset;
        }

        CHECK_THROW_ERR(N <= data.size() - start_offset, "bad cache base data (pippenger_init)");

        std::shared_ptr<pippenger_cache> cache(new pippenger_cache());

        cache->size = N;
        cache->cached = (ge_cached*)aligned_realloc(cache->cached, N * sizeof(ge_cached), 4096);
        CHECK_THROW_ERR(cache->cached, "OOM: OUT OF MEMORY!");

        for (size_t i = 0; i < N; i++) {
            ge_p3_to_cached(&cache->cached[i], &data[i+start_offset].point);
        }

        return cache;
    }

    size_t pippenger_get_cache_size(const std::shared_ptr<pippenger_cache> &cache)
    {
        return cache->size * sizeof(*cache->cached);
    }

    key pippenger(const std::vector<multiexp_data> &data, const std::shared_ptr<pippenger_cache> &cache, size_t cache_size, size_t c)
    {
        if (cache != NULL && cache_size == 0) {
            cache_size = cache->size;
        }

        CHECK_THROW_ERR(cache == NULL || cache_size <= cache->size, "cache is too small (pippenger)");

        if (c == 0) {
            c = get_pippenger_c(data.size());
        }

        CHECK_THROW_ERR(c <= 9, "c is too large (pippenger)");

        ge_p3 result = ge_p3_identity;
        bool result_init = false;
        std::unique_ptr<ge_p3[]> buckets{new ge_p3[1<<c]};
        bool buckets_init[1<<9];
        std::shared_ptr<pippenger_cache> local_cache = cache == NULL ? pippenger_init(data) : cache;
        std::shared_ptr<pippenger_cache> local_cache_2 = data.size() > cache_size ? pippenger_init(data, cache_size) : NULL;

        key maxscalar = zero();

        for (size_t i = 0; i < data.size(); i++) {
            if (maxscalar < data[i].scalar) {
                maxscalar = data[i].scalar;
            }
        }

        size_t groups = 0;

        while (groups < 256 && !(maxscalar < pow2(groups))) {
            groups++;
        }

        groups = (groups + c - 1) / c;

        for (size_t k = groups; k-- > 0; ) {
            if (result_init) {
                ge_p2 p2;
                ge_p3_to_p2(&p2, &result);

                for (size_t i = 0; i < c; i++) {
                    ge_p1p1 p1;
                    ge_p2_dbl(&p1, &p2);

                    if (i == c - 1) {
                        ge_p1p1_to_p3(&result, &p1);
                    }
                    else {
                        ge_p1p1_to_p2(&p2, &p1);
                    }
                }
            }

            memset(buckets_init, 0, 1u<<c);

            for (size_t i = 0; i < data.size(); i++) {
                unsigned int bucket = 0;

                for (size_t j = 0; j < c; j++) {
                    if (test(data[i].scalar, k*c+j)) {
                        bucket |= 1<<j;
                    }
                }

                if (bucket == 0) {
                    continue;
                }

                CHECK_THROW_ERR(bucket < (1u<<c), "bucket overflow (pippenger)");

                if (buckets_init[bucket]) {
                    if (i < cache_size) {
                        add(buckets[bucket], local_cache->cached[i]);
                    }
                    else {
                        add(buckets[bucket], local_cache_2->cached[i - cache_size]);
                    }
                }
                else {
                    buckets[bucket] = data[i].point;
                    buckets_init[bucket] = true;
                }
            }

            ge_p3 pail;
            bool pail_init = false;

            for (size_t i = (1<<c)-1; i > 0; i--) {
                if (buckets_init[i]) {
                    if (pail_init) {
                        add(pail, buckets[i]);
                    }
                    else {
                        pail = buckets[i];
                        pail_init = true;
                    }
                }

                if (pail_init) {
                    if (result_init) {
                        add(result, pail);
                    }
                    else {
                        result = pail;
                        result_init = true;
                    }
                }
            }
        }

        key res;
        ge_p3_tobytes(res.bytes, &result);
        return res;
    }
}
