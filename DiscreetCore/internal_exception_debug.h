#pragma once

#include "export.h"

void ThrowException(const char* s_Messg);

#ifdef __cplusplus
extern "C" {
#endif 

EXPORT void GetLastException(unsigned char* data);

#ifdef __cplusplus
}
#endif