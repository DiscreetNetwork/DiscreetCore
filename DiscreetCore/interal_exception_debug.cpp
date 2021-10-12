#include <string.h>
#include "export.h"

static char ms_GlobExcp[4096] = { 0 };
static int ms_GlobExcpLen = 0;

void ThrowException(const char* s_Messg)
{
    ms_GlobExcpLen = strlen(s_Messg);
    memcpy(ms_GlobExcp, s_Messg, ms_GlobExcpLen);
    throw s_Messg;
}


extern "C" {
    EXPORT void GetLastException(unsigned char* data)
    {
        char* _data = (char*)data;

        memcpy(_data, ms_GlobExcp, ms_GlobExcpLen);
    }
}

