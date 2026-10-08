// Exact BLS12-381 base-field arithmetic for public-data CUDA batches.
// Values use twelve little-endian 32-bit limbs in Montgomery form, R=2^384.
// These variable-time routines MUST NOT process secret keys or witnesses.
#ifndef DGFLOW_CUDA_FIELD_CUH
#define DGFLOW_CUDA_FIELD_CUH

// Keep the header self-contained: NVRTC does not need a host C++ SDK.
namespace dgflow_cuda {
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

struct Fp { uint32_t limb[12]; };

// CUDA constant memory also remains usable by the host-reference test harness.
#if defined(__CUDACC__)
#define DGFLOW_DEVICE __device__ __forceinline__
#define DGFLOW_COMPLEX_DEVICE __device__ __noinline__
#define DGFLOW_CONSTANT __device__ __constant__
#else
#define DGFLOW_DEVICE inline
#define DGFLOW_COMPLEX_DEVICE inline
#define DGFLOW_CONSTANT static const
#endif

DGFLOW_CONSTANT uint32_t FP_MODULUS[12] = {
    0xffffaaabu, 0xb9feffffu, 0xb153ffffu, 0x1eabfffeu,
    0xf6b0f624u, 0x6730d2a0u, 0xf38512bfu, 0x64774b84u,
    0x434bacd7u, 0x4b1ba7b6u, 0x397fe69au, 0x1a0111eau
};
DGFLOW_CONSTANT uint32_t FP_R[12] = {
    0x0002fffdu, 0x76090000u, 0xc40c0002u, 0xebf4000bu,
    0x53c758bau, 0x5f489857u, 0x70525745u, 0x77ce5853u,
    0xa256ec6du, 0x5c071a97u, 0xfa80e493u, 0x15f65ec3u
};
DGFLOW_CONSTANT uint32_t FP_R2[12] = {
    0x1c341746u, 0xf4df1f34u, 0x09d104f1u, 0x0a76e6a6u,
    0x4c95b6d5u, 0x8de5476cu, 0x939d83c0u, 0x67eb88a9u,
    0xb519952du, 0x9a793e85u, 0x92cae3aau, 0x11988fe5u
};
DGFLOW_CONSTANT uint32_t FP_INVERSE_EXPONENT[12] = {
    0xffffaaa9u, 0xb9feffffu, 0xb153ffffu, 0x1eabfffeu,
    0xf6b0f624u, 0x6730d2a0u, 0xf38512bfu, 0x64774b84u,
    0x434bacd7u, 0x4b1ba7b6u, 0x397fe69au, 0x1a0111eau
};
DGFLOW_CONSTANT uint32_t SCALAR_MODULUS[8] = {
    0x00000001u, 0xffffffffu, 0xfffe5bfeu, 0x53bda402u,
    0x09a1d805u, 0x3339d808u, 0x299d7d48u, 0x73eda753u
};

DGFLOW_DEVICE Fp fp_zero() {
    Fp out; for (int i=0; i<12; ++i) out.limb[i]=0; return out;
}
DGFLOW_DEVICE Fp fp_one() {
    Fp out; for (int i=0; i<12; ++i) out.limb[i]=FP_R[i]; return out;
}
DGFLOW_DEVICE bool fp_is_zero(const Fp& a) {
    uint32_t x=0; for (int i=0; i<12; ++i) x|=a.limb[i]; return x==0;
}
DGFLOW_DEVICE bool fp_eq(const Fp& a, const Fp& b) {
    uint32_t x=0; for (int i=0; i<12; ++i) x|=a.limb[i]^b.limb[i]; return x==0;
}
DGFLOW_DEVICE bool fp_ge_modulus(const Fp& a) {
    for (int i=11; i>=0; --i) {
        if (a.limb[i]!=FP_MODULUS[i]) return a.limb[i]>FP_MODULUS[i];
    }
    return true;
}
DGFLOW_DEVICE Fp fp_sub_modulus(const Fp& a) {
    Fp out; uint64_t borrow=0;
    for (int i=0; i<12; ++i) {
        uint64_t sub=(uint64_t)FP_MODULUS[i]+borrow;
        out.limb[i]=(uint32_t)((uint64_t)a.limb[i]-sub);
        borrow=(uint64_t)a.limb[i]<sub;
    }
    return out;
}
DGFLOW_DEVICE Fp fp_add(const Fp& a, const Fp& b) {
    Fp out; uint64_t carry=0;
    for (int i=0; i<12; ++i) {
        uint64_t s=(uint64_t)a.limb[i]+b.limb[i]+carry;
        out.limb[i]=(uint32_t)s; carry=s>>32;
    }
    // 2*p < 2^382: canonical operands cannot overflow twelve limbs.
    if (fp_ge_modulus(out)) out=fp_sub_modulus(out);
    return out;
}
DGFLOW_DEVICE Fp fp_sub(const Fp& a, const Fp& b) {
    Fp out; uint64_t borrow=0;
    for (int i=0; i<12; ++i) {
        uint64_t sub=(uint64_t)b.limb[i]+borrow;
        out.limb[i]=(uint32_t)((uint64_t)a.limb[i]-sub);
        borrow=(uint64_t)a.limb[i]<sub;
    }
    if (borrow) {
        uint64_t carry=0;
        for (int i=0; i<12; ++i) {
            uint64_t s=(uint64_t)out.limb[i]+FP_MODULUS[i]+carry;
            out.limb[i]=(uint32_t)s; carry=s>>32;
        }
    }
    return out;
}
DGFLOW_DEVICE Fp fp_neg(const Fp& a) { return fp_sub(fp_zero(),a); }

// Coarsely integrated operand scanning. Each accumulate fits in uint64_t:
// (2^32-1)^2 + (2^32-1) + (2^32-1) = 2^64-1.
DGFLOW_COMPLEX_DEVICE Fp fp_mul(const Fp& a, const Fp& b) {
    uint32_t t0=0,t1=0,t2=0,t3=0,t4=0,t5=0,t6=0,t7=0,t8=0,t9=0,t10=0,t11=0,t12=0,t13=0;
    #pragma unroll 1
    for (int i=0; i<12; ++i) {
        uint64_t carry=0,s; const uint32_t bi=b.limb[i];
        s=(uint64_t)a.limb[0]*bi+t0+carry; t0=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[1]*bi+t1+carry; t1=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[2]*bi+t2+carry; t2=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[3]*bi+t3+carry; t3=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[4]*bi+t4+carry; t4=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[5]*bi+t5+carry; t5=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[6]*bi+t6+carry; t6=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[7]*bi+t7+carry; t7=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[8]*bi+t8+carry; t8=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[9]*bi+t9+carry; t9=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[10]*bi+t10+carry; t10=(uint32_t)s; carry=s>>32;
        s=(uint64_t)a.limb[11]*bi+t11+carry; t11=(uint32_t)s; carry=s>>32;
        s=(uint64_t)t12+carry; t12=(uint32_t)s; t13+=(uint32_t)(s>>32);
        const uint32_t m=t0*0xfffcfffdu; carry=0;
        s=(uint64_t)m*FP_MODULUS[0]+t0+carry; t0=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[1]+t1+carry; t1=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[2]+t2+carry; t2=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[3]+t3+carry; t3=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[4]+t4+carry; t4=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[5]+t5+carry; t5=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[6]+t6+carry; t6=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[7]+t7+carry; t7=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[8]+t8+carry; t8=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[9]+t9+carry; t9=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[10]+t10+carry; t10=(uint32_t)s; carry=s>>32;
        s=(uint64_t)m*FP_MODULUS[11]+t11+carry; t11=(uint32_t)s; carry=s>>32;
        s=(uint64_t)t12+carry; t12=(uint32_t)s; t13+=(uint32_t)(s>>32);
        t0=t1;
        t1=t2;
        t2=t3;
        t3=t4;
        t4=t5;
        t5=t6;
        t6=t7;
        t7=t8;
        t8=t9;
        t9=t10;
        t10=t11;
        t11=t12;
        t12=t13;
        t13=0;
    }
    Fp out={{t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11}};
    if (fp_ge_modulus(out)) out=fp_sub_modulus(out);
    return out;
}
DGFLOW_DEVICE Fp fp_square(const Fp& a) { return fp_mul(a,a); }
DGFLOW_COMPLEX_DEVICE Fp fp_pow(Fp base, const uint32_t* exponent, int limbs) {
    Fp out=fp_one();
    bool started=false;
    #pragma unroll 1
    for (int i=limbs*32-1; i>=0; --i) {
        bool bit=((exponent[i/32]>>(i%32))&1u)!=0;
        if (!started) { if (!bit) continue; started=true; }
        out=fp_square(out);
        if (bit) out=fp_mul(out,base);
    }
    return out;
}
// Zero maps to zero. Callers needing a multiplicative inverse reject zero.
DGFLOW_DEVICE Fp fp_inv(const Fp& a) { return fp_pow(a,FP_INVERSE_EXPONENT,12); }

DGFLOW_DEVICE uint32_t fp_read_le32(const unsigned char* raw) {
    return (uint32_t)raw[0] | ((uint32_t)raw[1]<<8) |
           ((uint32_t)raw[2]<<16) | ((uint32_t)raw[3]<<24);
}
DGFLOW_DEVICE bool fp_is_canonical_bytes(const unsigned char* raw) {
    Fp x; for (int i=0; i<12; ++i) x.limb[i]=fp_read_le32(raw+4*i);
    return !fp_ge_modulus(x);
}
DGFLOW_DEVICE bool fp_decode(const unsigned char* raw, Fp* out) {
    Fp x; for (int i=0; i<12; ++i) x.limb[i]=fp_read_le32(raw+4*i);
    if (fp_ge_modulus(x)) { *out=fp_zero(); return false; }
    Fp r2; for (int i=0; i<12; ++i) r2.limb[i]=FP_R2[i];
    *out=fp_mul(x,r2); return true;
}
DGFLOW_DEVICE void fp_encode(const Fp& a, unsigned char* raw) {
    Fp canonical_one=fp_zero(); canonical_one.limb[0]=1;
    Fp x=fp_mul(a,canonical_one);
    for (int i=0; i<12; ++i) {
        uint32_t v=x.limb[i];
        for (int j=0; j<4; ++j) raw[4*i+j]=(unsigned char)(v>>(8*j));
    }
}
DGFLOW_DEVICE Fp fp_from_bytes(const unsigned char* raw) {
    Fp out; fp_decode(raw,&out); return out;
}
DGFLOW_DEVICE void fp_to_bytes(const Fp& a, unsigned char* raw) { fp_encode(a,raw); }
DGFLOW_DEVICE Fp fp_from_u32(uint32_t value) {
    Fp x=fp_zero(); x.limb[0]=value;
    Fp r2; for (int i=0; i<12; ++i) r2.limb[i]=FP_R2[i];
    return fp_mul(x,r2);
}

DGFLOW_DEVICE bool scalar_decode_be(const unsigned char* raw, uint32_t* out) {
    for (int i=0; i<8; ++i) {
        const unsigned char* b=raw+28-4*i;
        out[i]=((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|
               ((uint32_t)b[2]<<8)|(uint32_t)b[3];
    }
    for (int i=7; i>=0; --i) {
        if (out[i]!=SCALAR_MODULUS[i]) return out[i]<SCALAR_MODULUS[i];
    }
    return false;
}
} // namespace dgflow_cuda
#endif

