#pragma once
#ifndef MULTIEXP_H
#define MULTIEXP_H

#include <memory>
#include <vector>
#include "types.h"

#include "crypto.h"

namespace discore
{

    struct MultiexpData {
        key scalar;
        ge_p3 point;

        MultiexpData() {}
        MultiexpData(const key& s, const ge_p3& p) : scalar(s), point(p) {}
        MultiexpData(const key& s, const key& p) : scalar(s)
        {
            CHECK_THROW_ERR(ge_frombytes_vartime(&point, p.bytes) == 0, "ge_frombytes_vartime failed");
        }
    };

    struct straus_cached_data;
    struct pippenger_cached_data;

    key bos_coster_heap_conv(std::vector<MultiexpData> data);
    key bos_coster_heap_conv_robust(std::vector<MultiexpData> data);
    std::shared_ptr<straus_cached_data> straus_init_cache(const std::vector<MultiexpData>& data, size_t N = 0);
    size_t straus_get_cache_size(const std::shared_ptr<straus_cached_data>& cache);
    key straus(const std::vector<MultiexpData>& data, const std::shared_ptr<straus_cached_data>& cache = NULL, size_t STEP = 0);
    std::shared_ptr<pippenger_cached_data> pippenger_init_cache(const std::vector<MultiexpData>& data, size_t start_offset = 0, size_t N = 0);
    size_t pippenger_get_cache_size(const std::shared_ptr<pippenger_cached_data>& cache);
    size_t get_pippenger_c(size_t N);
    key pippenger(const std::vector<MultiexpData>& data, const std::shared_ptr<pippenger_cached_data>& cache = NULL, size_t cache_size = 0, size_t c = 0);

}

#endif // MULTIEXP_H
