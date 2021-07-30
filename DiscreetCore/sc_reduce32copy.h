#pragma once
#ifndef SC_REDUCE32COPY_H
#define SC_REDUCE32COPY_H

extern "C" {
#include "crypto_curve.h"
}

void sc_reduce32copy(unsigned char * scopy, const unsigned char *s);

#endif // SC_REDUCE32COPY_H