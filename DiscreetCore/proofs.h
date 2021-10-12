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

#include "export.h"

namespace discore {
    TriptychProof triptych_prove(const keyV &, const keyV &, const key &, const size_t, const key &, const key &, const size_t, const size_t, const key &);
    bool triptych_verify(const keyV &, const keyV &, const keyV &, std::vector<TriptychProof*> &, const keyV &);
    bool triptych_verify(const keyV& M, const keyV& P, const key C_offset, TriptychProof& proof, const key& message);
    key scalar_invert(const key& x);
}

#ifdef __cplusplus
extern "C" {
#endif

EXPORT discore::ArgTriptych triptych_PROVE(const discore::key64 M, const discore::key64 P, const discore::key C_offset, const size_t l, const discore::key r, const discore::key s, const discore::key message);
EXPORT bool triptych_VERIFY(discore::ArgTriptych proof, const discore::key64 M, const discore::key64 P, const discore::key C_offset, const discore::key message);

#ifdef __cplusplus
}
#endif

#endif // PROOFS_H