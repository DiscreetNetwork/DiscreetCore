#include <stdint.h>

#include "export.h"

#pragma once

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef int32_t fe[10];

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;


EXPORT void ge_add(ge_p1p1 *, const ge_p3 *, const ge_cached *);
typedef ge_cached ge_dsmp[8];
EXPORT void ge_dsm_precomp(ge_dsmp r, const ge_p3 *s);
EXPORT void ge_double_scalarmult_base_vartime(ge_p2 *, const unsigned char *, const ge_p3 *, const unsigned char *);
EXPORT void ge_triple_scalarmult_base_vartime(ge_p2 *, const unsigned char *, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp);
EXPORT void ge_double_scalarmult_base_vartime_p3(ge_p3 *, const unsigned char *, const ge_p3 *, const unsigned char *);

EXPORT int ge_frombytes_vartime(ge_p3 *, const unsigned char *);
EXPORT void ge_p1p1_to_p2(ge_p2 *, const ge_p1p1 *);
EXPORT void ge_p1p1_to_p3(ge_p3 *, const ge_p1p1 *);
EXPORT void ge_p2_dbl(ge_p1p1 *, const ge_p2 *);
EXPORT void ge_p3_to_cached(ge_cached *, const ge_p3 *);
EXPORT void ge_p3_to_p2(ge_p2 *, const ge_p3 *);
EXPORT void ge_p3_tobytes(unsigned char *, const ge_p3 *);
EXPORT void ge_scalarmult_base(ge_p3 *, const unsigned char *);
EXPORT void ge_tobytes(unsigned char *, const ge_p2 *);
EXPORT void ge_scalarmult(ge_p2 *, const unsigned char *, const ge_p3 *);
EXPORT void ge_scalarmult_p3(ge_p3 *, const unsigned char *, const ge_p3 *);
EXPORT void ge_double_scalarmult_precomp_vartime(ge_p2 *, const unsigned char *, const ge_p3 *, const unsigned char *, const ge_dsmp);
EXPORT void ge_triple_scalarmult_precomp_vartime(ge_p2 *, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp);
EXPORT void ge_double_scalarmult_precomp_vartime2(ge_p2 *, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp);
EXPORT void ge_double_scalarmult_precomp_vartime2_p3(ge_p3 *, const unsigned char *, const ge_dsmp, const unsigned char *, const ge_dsmp);void ge_mul8(ge_p1p1 *, const ge_p2 *);
EXPORT void ge_fromfe_frombytes_vartime(ge_p2 *, const unsigned char *);

extern const fe fe_d;
extern const fe fe_sqrtm1;
extern const fe fe_d2;
extern const ge_precomp ge_base[32][8];
extern const ge_precomp ge_Bi[8];
extern const fe fe_ma2;
extern const fe fe_ma;
extern const fe fe_fffb1;
extern const fe fe_fffb2;
extern const fe fe_fffb3;
extern const fe fe_fffb4;
extern const ge_p3 ge_p3_identity;
extern const ge_p3 ge_p3_H;

EXPORT void sc_reduce(unsigned char *);
EXPORT void sc_0(unsigned char *);
EXPORT void sc_reduce32(unsigned char *);
EXPORT void sc_add(unsigned char *, const unsigned char *, const unsigned char *);
EXPORT void sc_sub(unsigned char *, const unsigned char *, const unsigned char *);
EXPORT void sc_mulsub(unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *);
EXPORT void sc_mul(unsigned char *, const unsigned char *, const unsigned char *);
EXPORT void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);
EXPORT int sc_check(const unsigned char *);
EXPORT int sc_isnonzero(const unsigned char *); /* Doesn't normalize */

// internal
uint64_t load_3(const unsigned char *in);
uint64_t load_4(const unsigned char *in);
EXPORT void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void fe_add(fe h, const fe f, const fe g);
void fe_tobytes(unsigned char *, const fe);
void fe_invert(fe out, const fe z);

EXPORT int ge_p3_is_point_at_infinity(const ge_p3 *p);

#ifdef __cplusplus
}
#endif // __cplusplus
