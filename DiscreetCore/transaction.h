#pragma once
#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <vector>

#include "bulletproof.h"
#include "proofs.h"
#include "ops.h"
#include "types.h"

#ifdef _WIN32
#define EXPORT  __declspec(dllexport)
#else
#define EXPORT 
#endif

namespace discore {
    struct tx_input {
        key C; /* commitment */
        key T; /* UTXO pubkey */
    };

    struct tx_output {
        key C; /* commitment */
        key T; /* UTXO pubkey */
        key J; /* linking tag */
    };


    struct tx_head {
        key R; /* TX pubkey */

        std::vector<tx_input> inputs;
        std::vector<tx_input> outputs;

        ctkey fee; /* another value */
    };


    struct tx {
        key R;

        std::vector<tx_input> inputs;
        std::vector<tx_output> outputs;

        discore::dis_amount fee;

        bulletproof range_proof;
        std::vector<dis_sig> sigs;
    };   
}

#ifdef __cplusplus
extern "C" {
#endif

EXPORT void DKSAP(discore::key &R, discore::key &T, const discore::key &pv, const discore::key &ps);
EXPORT void DKSAPRecover(discore::key &t, const discore::key &R, const discore::key &sv, const discore::key &ss);
EXPORT discore::key GenerateSeckey1();
EXPORT void GenerateSeckey(discore::key &sk);
EXPORT discore::key GeneratePubkey();
EXPORT void GenerateKeypair(discore::key &sk, discore::key &pk);
EXPORT void ScalarmultBase(discore::key &ag, const discore::key &a);
EXPORT discore::key ScalarmultBase1(const discore::key &a);
EXPORT void GenCommitment(discore::key &c, const discore::key &a, discore::dis_amount amount);
EXPORT discore::key Commit(discore::dis_amount amount, const discore::key &mask);
EXPORT discore::key CommitToZero(discore::dis_amount amount);
EXPORT discore::dis_amount RandomDisAmount(discore::dis_amount limit);
EXPORT void ScalarmultKey(discore::key &ap, const discore::key &p, const discore::key &a);
EXPORT discore::key ScalarmultKey1(const discore::key &p, const discore::key &a);
EXPORT discore::key ScalarmultH(const discore::key &a);
EXPORT void Scalarmult8(ge_p3 &res, const discore::key &p);
EXPORT discore::key Scalarmult81(const discore::key &p);
EXPORT bool InMainSubgroup(const discore::key &a);
EXPORT void AddKeys(discore::key &ab, const discore::key &a, const discore::key &b);
EXPORT discore::key AddKeys_1(const discore::key &a, const discore::key &b);
EXPORT void AddKeys1(discore::key &agb, const discore::key &a, const discore::key &b);
EXPORT void AddKeys2(discore::key &agbp, const discore::key &a, const discore::key &b, const discore::key &p);
EXPORT void Precomp(ge_dsmp rv, const discore::key &b);
EXPORT void AddKeys3(discore::key &apbq, const discore::key &a, const discore::key &p, const discore::key &b, const ge_dsmp q);
EXPORT void AddKeys3_1(discore::key &apbq, const discore::key &a, const ge_dsmp p, const discore::key &b, const ge_dsmp q);
EXPORT void AddKeys4(discore::key &agbpcq, const discore::key &a, const discore::key &b, const ge_dsmp p, const discore::key &c, const ge_dsmp q);
EXPORT void AddKeys5(discore::key &apbqcr, const discore::key &a, const ge_dsmp p, const discore::key &b, const ge_dsmp q, const discore::key &c, const ge_dsmp r);
EXPORT void SubKeys(discore::key &ab, const discore::key &a, const discore::key &b);
EXPORT bool EqualKeys(const discore::key &a, const discore::key &b);
EXPORT void HashData(discore::key &hash, const void *data, const size_t l);
EXPORT void HashToScalar(discore::key &hash, const void *data, const size_t l);
EXPORT void HashKey(discore::key &hash, const discore::key &data);
EXPORT void HashKeyToScalar(discore::key &hash, const discore::key &data);
EXPORT discore::key HashKey1(const discore::key &data);
EXPORT discore::key HashKeyToScalar1(const discore::key &data);
EXPORT discore::key HashData128(const void *data);
EXPORT discore::key HashToScalar128(const void *data);
EXPORT void HashToP3(ge_p3 &hash8_p3, const discore::key &k);
EXPORT discore::key GenCommitmentMask(const discore::key &sk);
EXPORT void ECDHEncode(discore::ecdhtuple &unmasked, const discore::key &secret, bool v2);
EXPORT void ECDHDecode(discore::ecdhtuple &masked, const discore::key &secret, bool v2);


#ifdef __cplusplus
}
#endif

#endif // TRANSACTION_H