#include "types.h"

extern "C" {
//#include "../crypto/crypto.h"
#include "util.h"
}

namespace discore {
    void d2h(key &amounth, dis_amount val)
    {
        sc_0(amounth.bytes);
        memcpy_swap64le(amounth.bytes, &val, 1);
    }

    key d2h(dis_amount val)
    {
        key amounth;
        d2h(amounth, val);
        return amounth;
    }

    void d2b(bits amountb, dis_amount val)
    {
        int i = 0;
        while (i < 64) {
            amountb[i++] = val & 1;
            val >>= 1;
        }
    }

    dis_amount h2d(const key &val)
    {
        dis_amount vali = 0;
        int j = 0;
        for (j = 7; j >= 0; j--) {
            vali = (dis_amount)(vali * 256 + (unsigned char)val.bytes[j]);
        }
        return vali;
    }

    void h2b(bits amountb2, const key &val)
    {
        int val2 = 0, i = 0, j = 0;
        for (j = 0; j < 8; j++) {
            val2 = (unsigned char)val.bytes[j];
            i = 0;
            while (i < 8) {
                amountb2[j*8+i++] = val2 & 1;
                val2 >>= 1;
            }
        }
    }

    void b2h(key &amountdh, bits amountb2)
    {
        int byte, i, j;
        for (j = 0; j < 8; j++) {
            byte = 0;
            for (i = 7; i > -1; i--) {
                byte = byte * 2 + amountb2[8 * j + i];
            }
            amountdh[j] = (unsigned char)byte;
        }
        for (j = 8; j < 32; j++) {
            amountdh[j] = (unsigned char)(0x00);
        }
    }

    dis_amount b2d(bits amountb)
    {
        dis_amount vali = 0;
        int j = 0;
        for (j = 63; j >= 0; j--) {
            vali = (dis_amount)(vali * 2 + amountb[j]);
        }
        return vali;
    }
}