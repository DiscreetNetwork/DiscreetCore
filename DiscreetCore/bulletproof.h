#pragma once
#ifndef BULLETPROOF_H
#define BULLETPROOF_H

#include <vector>
#include "types.h"

#include "export.h"

/* based on cryptonote config :) */
#define BULLETPROOF_MAX_OUTPUTS 16

namespace discore
{
    Bulletproof bulletproof_PROVE (const key &v, const key &gamma);
    Bulletproof bulletproof_PROVE (uint64_t v, const key &gamma);
    Bulletproof bulletproof_PROVE (const keyV &v, const keyV &gamma);
    Bulletproof bulletproof_PROVE (const std::vector<uint64_t> &v, const keyV &gamma);

    bool bulletproof_VERIFY (const Bulletproof & proof);
    bool bulletproof_VERIFY (const std::vector<const Bulletproof*> &proofs);
    bool bulletproof_VERIFY (const std::vector<Bulletproof> &proofs);
}

#ifdef __cplusplus
extern "C" {
#endif

EXPORT discore::ArgBulletproof bulletproof_prove(const uint64_t v[16], const discore::key16 gamma, uint64_t size);
EXPORT bool bulletproof_verify(discore::ArgBulletproof bp);

#ifdef __cplusplus
}
#endif

#endif // BULLETPROOF_H
