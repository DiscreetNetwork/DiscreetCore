#pragma once
#ifndef BULLETPROOF_H
#define BULLETPROOF_H

#include <vector>
#include "types.h"

/* based on cryptonote config :) */
#define BULLETPROOF_MAX_OUTPUTS 16

namespace discore
{
    bulletproof bulletproof_PROVE (const key &v, const key &gamma);
    bulletproof bulletproof_PROVE (uint64_t v, const key &gamma);
    bulletproof bulletproof_PROVE (const keyV &v, const keyV &gamma);
    bulletproof bulletproof_PROVE (const std::vector<uint64_t> &v, const keyV &gamma);

    bool bulletproof_VERIFY (const bulletproof & proof);
    bool bulletproof_VERIFY (const std::vector<const bulletproof*> &proofs);
    bool bulletproof_VERIFY (const std::vector<bulletproof> &proofs);
}

#endif // BULLETPROOF_H
