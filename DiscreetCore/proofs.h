#pragma once

#ifndef PROOFS_H
#define PROOFS_H

#include <cstddef>
#include <tuple>
#include <vector>

#include "crypto.h"

extern "C" {
#include "crypto_curve.h"
}

#include "ops.h"
#include "types.h"

namespace discore {
    triptych triptych_prove(const keyV &, const keyV &, const key &, const size_t, const key &, const key &, const size_t, const size_t, const key &);
    bool triptych_verify(const keyV &, const keyV &, const keyV &, std::vector<triptych *> &, const size_t, const size_t, const keyV &);
}

#endif // PROOFS_H