/**
 * Filename:    random.h
 * Author:      Brandon Koerner (bkoerner@getdiscreet.org)
 * Disclaimer:  Code is presented "as is" without guarantees.
 * Details:     RNG definitions.
 * 
 * Protected under GNU general public license v3.
 */

#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

void generate_randombytes(size_t n, void *res);

#ifdef __cplusplus
}
#endif

#endif // RANDOM_H