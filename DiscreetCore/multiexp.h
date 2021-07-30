#pragma once
#ifndef MULTIEXP_H
#define MULTIEXP_H

#include <memory>
#include <vector>
#include "types.h"

extern "C" {
#include "crypto.h"
}

namespace discore {
    struct multiexp_data {
        key scalar;
        ge_p3 point;

        multiexp_data() {}
        multiexp_data(const key &s, const ge_p3 &p): scalar(s), point(p) {}
        multiexp_data(const key &s, const key &p): scalar(s)
        {
            CHECK_THROW_ERR(ge_frombytes_vartime(&point, p.bytes) == 0, "ge_frombytes_vartime failed (multiexp_data)");
        }
    };

    struct straus_cache;
    struct pippenger_cache;

    key heap_conv(std::vector<multiexp_data> data);
    key heap_conv_robust(std::vector<multiexp_data> data);
    std::shared_ptr<straus_cache> straus_init(const std::vector<multiexp_data> &data, size_t N = 0);
    size_t straus_get_cache_size(const std::shared_ptr<straus_cache> &cache);
    key straus(const std::vector<multiexp_data> &data, const std::shared_ptr<straus_cache> &cache = NULL, size_t STEP = 0);
    std::shared_ptr<pippenger_cache> pippenger_init(const std::vector<multiexp_data> &data, size_t start_offset = 0, size_t N = 0);
    size_t pippenger_get_cache_size(const std::shared_ptr<pippenger_cache> &cache);
    size_t get_pippenger_c(size_t N);
    key pippenger(const std::vector<multiexp_data> &data, const std::shared_ptr<pippenger_cache> &cache = NULL, size_t cache_size = 0, size_t c = 0);
}

#endif // MULTIEXP_H
