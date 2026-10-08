#pragma once
#include "field.cuh"

// BLS12-381 Fq12, matching arkworks' canonical 576-byte serialization:
// c0.c0.c0, c0.c0.c1, c0.c1.c0, ... c1.c2.c1; each Fq is 48-byte LE.
// Only PUBLIC verifier exponents are accepted by the kernels below.
namespace dgflow_cuda {

struct Fp2 { Fp c0, c1; };                 // u^2 = -1
struct Fp6 { Fp2 c0, c1, c2; };            // v^3 = 1 + u
struct Fp12 { Fp6 c0, c1; };               // w^2 = v

DGFLOW_DEVICE Fp2 fp2_zero() { return {fp_zero(), fp_zero()}; }
DGFLOW_DEVICE Fp2 fp2_one() { return {fp_one(), fp_zero()}; }
DGFLOW_DEVICE Fp2 fp2_add(const Fp2& a, const Fp2& b) {
    return {fp_add(a.c0,b.c0), fp_add(a.c1,b.c1)};
}
DGFLOW_DEVICE Fp2 fp2_sub(const Fp2& a, const Fp2& b) {
    return {fp_sub(a.c0,b.c0), fp_sub(a.c1,b.c1)};
}
DGFLOW_DEVICE Fp2 fp2_neg(const Fp2& a) { return {fp_neg(a.c0),fp_neg(a.c1)}; }
DGFLOW_DEVICE Fp2 fp2_double(const Fp2& a) { return fp2_add(a,a); }
DGFLOW_DEVICE bool fp2_eq(const Fp2& a, const Fp2& b) {
    return fp_eq(a.c0,b.c0) && fp_eq(a.c1,b.c1);
}
DGFLOW_COMPLEX_DEVICE Fp2 fp2_mul(const Fp2& a, const Fp2& b) {
    Fp ac=fp_mul(a.c0,b.c0), bd=fp_mul(a.c1,b.c1);
    return {fp_sub(ac,bd), fp_sub(fp_sub(fp_mul(fp_add(a.c0,a.c1),
        fp_add(b.c0,b.c1)),ac),bd)};
}
DGFLOW_COMPLEX_DEVICE Fp2 fp2_square(const Fp2& a) {
    return {fp_mul(fp_add(a.c0,a.c1),fp_sub(a.c0,a.c1)),
        fp_mul(fp_add(a.c0,a.c0),a.c1)};
}
DGFLOW_DEVICE Fp2 fp2_mul_nr(const Fp2& a) {
    return {fp_sub(a.c0,a.c1),fp_add(a.c0,a.c1)};
}
DGFLOW_DEVICE Fp2 fp2_mul_fp(const Fp2& a, const Fp& b) {
    return {fp_mul(a.c0,b),fp_mul(a.c1,b)};
}

DGFLOW_DEVICE Fp6 fp6_zero() { return {fp2_zero(),fp2_zero(),fp2_zero()}; }
DGFLOW_DEVICE Fp6 fp6_one() { return {fp2_one(),fp2_zero(),fp2_zero()}; }
DGFLOW_DEVICE Fp6 fp6_add(const Fp6& a, const Fp6& b) {
    return {fp2_add(a.c0,b.c0),fp2_add(a.c1,b.c1),fp2_add(a.c2,b.c2)};
}
DGFLOW_DEVICE Fp6 fp6_sub(const Fp6& a, const Fp6& b) {
    return {fp2_sub(a.c0,b.c0),fp2_sub(a.c1,b.c1),fp2_sub(a.c2,b.c2)};
}
DGFLOW_DEVICE Fp6 fp6_neg(const Fp6& a) {
    return {fp2_neg(a.c0),fp2_neg(a.c1),fp2_neg(a.c2)};
}
DGFLOW_DEVICE Fp6 fp6_mul_nr(const Fp6& a) { return {fp2_mul_nr(a.c2),a.c0,a.c1}; }
DGFLOW_DEVICE Fp6 fp6_mul_fp(const Fp6& a, const Fp& b) {
    return {fp2_mul_fp(a.c0,b),fp2_mul_fp(a.c1,b),fp2_mul_fp(a.c2,b)};
}
DGFLOW_DEVICE bool fp6_eq(const Fp6& a, const Fp6& b) {
    return fp2_eq(a.c0,b.c0)&&fp2_eq(a.c1,b.c1)&&fp2_eq(a.c2,b.c2);
}
DGFLOW_COMPLEX_DEVICE Fp6 fp6_mul(const Fp6& a, const Fp6& b) {
    Fp2 t0=fp2_mul(a.c0,b.c0), t1=fp2_mul(a.c1,b.c1), t2=fp2_mul(a.c2,b.c2);
    Fp2 r0=fp2_add(t0,fp2_mul_nr(fp2_sub(fp2_sub(fp2_mul(
        fp2_add(a.c1,a.c2),fp2_add(b.c1,b.c2)),t1),t2)));
    Fp2 r1=fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a.c0,a.c1),
        fp2_add(b.c0,b.c1)),t0),t1),fp2_mul_nr(t2));
    Fp2 r2=fp2_add(fp2_sub(fp2_sub(fp2_mul(fp2_add(a.c0,a.c2),
        fp2_add(b.c0,b.c2)),t0),t2),t1);
    return {r0,r1,r2};
}
DGFLOW_COMPLEX_DEVICE Fp6 fp6_square(const Fp6& a) {
    Fp2 s0=fp2_square(a.c0), s1=fp2_double(fp2_mul(a.c0,a.c1));
    Fp2 s2=fp2_square(fp2_add(fp2_sub(a.c0,a.c1),a.c2));
    Fp2 s3=fp2_double(fp2_mul(a.c1,a.c2)), s4=fp2_square(a.c2);
    return {fp2_add(s0,fp2_mul_nr(s3)),fp2_add(s1,fp2_mul_nr(s4)),
        fp2_sub(fp2_sub(fp2_add(fp2_add(s1,s2),s3),s0),s4)};
}

DGFLOW_DEVICE Fp12 fp12_zero() { return {fp6_zero(),fp6_zero()}; }
DGFLOW_DEVICE Fp12 fp12_one() { return {fp6_one(),fp6_zero()}; }
DGFLOW_DEVICE bool fp12_eq(const Fp12& a, const Fp12& b) {
    return fp6_eq(a.c0,b.c0)&&fp6_eq(a.c1,b.c1);
}
DGFLOW_DEVICE bool fp12_is_zero(const Fp12& a) { return fp12_eq(a,fp12_zero()); }
DGFLOW_DEVICE Fp12 fp12_add(const Fp12& a, const Fp12& b) {
    return {fp6_add(a.c0,b.c0),fp6_add(a.c1,b.c1)};
}
DGFLOW_DEVICE Fp12 fp12_sub(const Fp12& a, const Fp12& b) {
    return {fp6_sub(a.c0,b.c0),fp6_sub(a.c1,b.c1)};
}
DGFLOW_COMPLEX_DEVICE Fp12 fp12_mul(const Fp12& a, const Fp12& b) {
    Fp6 ac=fp6_mul(a.c0,b.c0),bd=fp6_mul(a.c1,b.c1);
    return {fp6_add(ac,fp6_mul_nr(bd)),fp6_sub(fp6_sub(
        fp6_mul(fp6_add(a.c0,a.c1),fp6_add(b.c0,b.c1)),ac),bd)};
}
DGFLOW_COMPLEX_DEVICE Fp12 fp12_square(const Fp12& a) {
    Fp6 ab=fp6_mul(a.c0,a.c1);
    return {fp6_sub(fp6_sub(fp6_mul(fp6_add(a.c0,a.c1),
        fp6_add(a.c0,fp6_mul_nr(a.c1))),ab),fp6_mul_nr(ab)),fp6_add(ab,ab)};
}
DGFLOW_DEVICE Fp12 fp12_conjugate(const Fp12& a) { return {a.c0,fp6_neg(a.c1)}; }

DGFLOW_COMPLEX_DEVICE bool fp12_decode(const unsigned char* raw, Fp12* out) {
    // Do not map noncanonical coefficients into Fq by reduction.
    Fp* cs[12]={&out->c0.c0.c0,&out->c0.c0.c1,&out->c0.c1.c0,&out->c0.c1.c1,
        &out->c0.c2.c0,&out->c0.c2.c1,&out->c1.c0.c0,&out->c1.c0.c1,
        &out->c1.c1.c0,&out->c1.c1.c1,&out->c1.c2.c0,&out->c1.c2.c1};
    bool valid=true;
    for(int i=0;i<12;++i) valid=fp_decode(raw+48*i,cs[i])&&valid;
    return valid;
}
DGFLOW_COMPLEX_DEVICE void fp12_encode(const Fp12& a, unsigned char* raw) {
    const Fp* cs[12]={&a.c0.c0.c0,&a.c0.c0.c1,&a.c0.c1.c0,&a.c0.c1.c1,
        &a.c0.c2.c0,&a.c0.c2.c1,&a.c1.c0.c0,&a.c1.c0.c1,
        &a.c1.c1.c0,&a.c1.c1.c1,&a.c1.c2.c0,&a.c1.c2.c1};
    for(int i=0;i<12;++i) fp_encode(*cs[i],raw+48*i);
}

// Montgomery constants for the real Fq2 Frobenius coefficients at powers
// 2 and 4, from ark-bls12-381 0.4.0 fields/{fq6,fq12}.rs. Coefficients
// are represented with R=2^384, matching field.cuh.
DGFLOW_DEVICE Fp frob_a() { return {{
    0x798a64e8u,0x30f1361bu,0x7ece5a2au,0xf3b8ddabu,0xc61577f7u,0x16a8ca3au,
    0x74fd029bu,0xc26a2ff8u,0x60701c6eu,0x3636b766u,0x241b6160u,0x051ba4abu}}; }
DGFLOW_DEVICE Fp frob_b() { return {{
    0x798dba3au,0xecfb361bu,0x91865a2cu,0xc100ddb8u,0x232bda8eu,0x0ec08ff1u,
    0xf1ca4721u,0xd5c13cc6u,0xbf7b5c04u,0x47222a47u,0xe51c5f59u,0x0110f184u}}; }
DGFLOW_DEVICE Fp frob_c() { return {{
    0x8671f071u,0xcd03c9e4u,0x1fcda5d2u,0x5dab2246u,0xd3851b95u,0x587042afu,
    0x01bacb9eu,0x8eb60ebeu,0x83d050d2u,0x03f97d6eu,0x54638741u,0x18f02065u}}; }
DGFLOW_COMPLEX_DEVICE Fp12 fp12_frobenius_even(const Fp12& x, int power) {
    // Fq2's Frobenius is the identity at both of these even powers.
    Fp f1=power==2?frob_a():frob_c(),f2=power==2?frob_c():frob_a();
    Fp fw=power==2?frob_b():frob_a();
    return {{x.c0.c0,fp2_mul_fp(x.c0.c1,f1),fp2_mul_fp(x.c0.c2,f2)},
        {fp2_mul_fp(x.c1.c0,fw),fp2_mul_fp(x.c1.c1,fp_mul(f1,fw)),
        fp2_mul_fp(x.c1.c2,fp_mul(f2,fw))}};
}
// EXPERIMENT ONLY: derived for the existing tower v^3=(1+i), w^2=v.
// C=(1+i)^((p-1)/6). These are C^k in Montgomery R=2^384 form.
// C matches arkworks FROBENIUS_COEFF_FP12_C1[1] exactly (decimal check).
DGFLOW_DEVICE Fp2 fp2_frobenius_one(const Fp2& a) {
    return {a.c0,fp_neg(a.c1)};
}
DGFLOW_DEVICE Fp2 frob1_c1() {
    return {{{
        0xb319d465u,0x07089552u,0xb50a8313u,0xc6695f92u,0xd117228fu,0x97e83cccu,
        0xb2dc29eeu,0xa35baecau,0x5daace4du,0x1ce393eau,0xb0fb66ebu,0x08f2220fu}},{{
        0x4ce5d646u,0xb2f66aadu,0xfc497cecu,0x5842a06bu,0x2599d394u,0xcf4895d4u,
        0x40a8e8d0u,0xc11b9cbau,0xe5a0de89u,0x2e3813cbu,0x88847fafu,0x110eefdau}}};
}
DGFLOW_DEVICE Fp2 frob1_c2() {
    return {{{
        0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,
        0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u}},{{
        0x8671f071u,0xcd03c9e4u,0x1fcda5d2u,0x5dab2246u,0xd3851b95u,0x587042afu,
        0x01bacb9eu,0x8eb60ebeu,0x83d050d2u,0x03f97d6eu,0x54638741u,0x18f02065u}}};
}
DGFLOW_DEVICE Fp2 frob1_c3() {
    return {{{
        0x5aa30fdau,0x7bcfa7a2u,0x2a927e7cu,0xdc17dec1u,0x6b4ebef1u,0x2f088dd8u,
        0xda74d4a7u,0xd1ca2087u,0x96cebc1du,0x2da25966u,0xbbfd87d2u,0x0e2b7eedu}},{{
        0x5aa30fdau,0x7bcfa7a2u,0x2a927e7cu,0xdc17dec1u,0x6b4ebef1u,0x2f088dd8u,
        0xda74d4a7u,0xd1ca2087u,0x96cebc1du,0x2da25966u,0xbbfd87d2u,0x0e2b7eedu}}};
}
DGFLOW_DEVICE Fp2 frob1_c4() {
    return {{{
        0x867545c3u,0x890dc9e4u,0x3285a5d5u,0x2af32253u,0x309b7e2cu,0x50880866u,
        0x7e881024u,0xa20d1b8cu,0xe2db9068u,0x14e4f04fu,0x1564853au,0x14e56d3fu}},{{
        0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,
        0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u}}};
}
DGFLOW_DEVICE Fp2 frob1_c5() {
    return {{{
        0x0dbce43fu,0x82d83cf5u,0xdf9d018fu,0xa2813e53u,0x3c65e181u,0xc6f0caa5u,
        0x8d50fe95u,0x7525cf52u,0xf4798a6bu,0x4a85ed50u,0x6cf8eebdu,0x171da0fdu}},{{
        0xf242c66cu,0x3726c30au,0xd1b6fe70u,0x7c2ac1aau,0xba4b14a2u,0xa04007fbu,
        0x66341429u,0xef517c32u,0x4ed2226bu,0x0095ba65u,0xcc86f7ddu,0x02e370ecu}}};
}
DGFLOW_COMPLEX_DEVICE Fp12 fp12_frobenius_one(const Fp12& x) {
    return {{fp2_frobenius_one(x.c0.c0),
        fp2_mul(fp2_frobenius_one(x.c0.c1),frob1_c2()),
        fp2_mul(fp2_frobenius_one(x.c0.c2),frob1_c4())},
        {fp2_mul(fp2_frobenius_one(x.c1.c0),frob1_c1()),
        fp2_mul(fp2_frobenius_one(x.c1.c1),frob1_c3()),
        fp2_mul(fp2_frobenius_one(x.c1.c2),frob1_c5())}};
}

DGFLOW_COMPLEX_DEVICE bool fp12_cyclotomic_member(const Fp12& x) {
    // For nonzero x this proves x^(p^4-p^2+1)=1, not merely unitarity.
    return !fp12_is_zero(x)&&fp12_eq(fp12_mul(fp12_frobenius_even(x,4),x),
        fp12_frobenius_even(x,2));
}
DGFLOW_DEVICE Fp2 three_minus_two(const Fp2& t,const Fp2& z) {
    return fp2_add(fp2_double(fp2_sub(t,z)),t);
}
DGFLOW_DEVICE Fp2 three_plus_two(const Fp2& t,const Fp2& z) {
    return fp2_add(fp2_double(fp2_add(t,z)),t);
}
DGFLOW_COMPLEX_DEVICE void cyclo_pair(const Fp2& a,const Fp2& b,Fp2* t0,Fp2* t1) {
    Fp2 tmp=fp2_mul(a,b);
    *t0=fp2_sub(fp2_sub(fp2_mul(fp2_add(a,b),fp2_add(fp2_mul_nr(b),a)),tmp),
        fp2_mul_nr(tmp));
    *t1=fp2_double(tmp);
}
DGFLOW_COMPLEX_DEVICE Fp12 fp12_cyclotomic_square(const Fp12& x) {
    // Granger-Scott, same coordinate placement as ark-ff 0.4.2. Use ONLY
    // after fp12_cyclotomic_member or on a trusted checked q-order input.
    Fp2 t0,t1,t2,t3,t4,t5;
    cyclo_pair(x.c0.c0,x.c1.c1,&t0,&t1);
    cyclo_pair(x.c1.c0,x.c0.c2,&t2,&t3);
    cyclo_pair(x.c0.c1,x.c1.c2,&t4,&t5);
    return {{three_minus_two(t0,x.c0.c0),three_minus_two(t2,x.c0.c1),
        three_minus_two(t4,x.c0.c2)},
        {three_plus_two(fp2_mul_nr(t5),x.c1.c0),three_plus_two(t1,x.c1.c1),
        three_plus_two(t3,x.c1.c2)}};
}
DGFLOW_COMPLEX_DEVICE Fp12 fp12_pow_words(const Fp12& base,const uint32_t* exponent,
        int words,bool cyclotomic=false) {
    Fp12 result=fp12_one(); bool started=false;
    #pragma unroll 1
    for(int i=words-1;i>=0;--i) {
        #pragma unroll 1
        for(int bit=31;bit>=0;--bit) {
        bool set=(exponent[i]>>bit)&1u;
        if(!started) { if(set) {result=base; started=true;} continue; }
        result=cyclotomic?fp12_cyclotomic_square(result):fp12_square(result);
        if(set) result=fp12_mul(result,base);
        }
    }
    return result;
}
DGFLOW_COMPLEX_DEVICE bool fp12_gt_member(const Fp12& x) {
    if(!fp12_cyclotomic_member(x)) return false;
    // EXACT check, not randomized aggregation. BLS seed x_BLS=-u.
    // ord(x) divides Phi12(p); Frob1(x)==x^(-u) also forces ord(x)|(p+u).
    // gcd(Phi12(p),p+u)==q for the pinned BLS12-381 constants.
    // The Phi12 gate is essential: without it the gcd is q*(u+1).
    const uint32_t u[2]={0x00010000u,0xd2010000u};
    Fp12 power=fp12_pow_words(x,u,2,true);
    return fp12_eq(fp12_frobenius_one(x),fp12_conjugate(power));
}
// Use only a q-order input, established by a full exact check or a prior
// trusted verifier check. Phi12 alone is insufficient: q-s and -s are equal
// as exponents only when x^q=1. Scalar decoding below guarantees 0 <= s < q.
DGFLOW_COMPLEX_DEVICE Fp12 fp12_pow_gt_words(const Fp12& x,const uint32_t* scalar) {
    uint32_t complement[8];uint64_t borrow=0;
    for(int i=0;i<8;++i) {
        uint64_t sub=(uint64_t)scalar[i]+borrow;
        complement[i]=(uint32_t)((uint64_t)SCALAR_MODULUS[i]-sub);
        borrow=(uint64_t)SCALAR_MODULUS[i]<sub;
    }
    bool shorter=false;
    for(int i=7;i>=0;--i) {
        if(scalar[i]!=complement[i]) {shorter=scalar[i]>complement[i];break;}
    }
    return shorter ? fp12_pow_words(fp12_conjugate(x),complement,8,true) :
        fp12_pow_words(x,scalar,8,true);
}
DGFLOW_DEVICE bool gt_scalar_decode_be(const unsigned char* raw,uint32_t* out) {
    const uint32_t order[8]={0x00000001u,0xffffffffu,0xfffe5bfeu,0x53bda402u,
        0x09a1d805u,0x3339d808u,0x299d7d48u,0x73eda753u};
    for(int i=0;i<8;++i) {const unsigned char* p=raw+28-4*i;
        out[i]=(uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
    for(int i=7;i>=0;--i) {if(out[i]<order[i]) return true;if(out[i]>order[i]) return false;}
    return false;
}

} // namespace dgflow_cuda

// Each thread verifies a distinct original proof coordinate. No randomized
// batching or weakening of canonical / nonzero / full q-order checks occurs.
extern "C" __global__ void dgfl_gt_validate(const unsigned char* raw,
        unsigned int* flags,unsigned int count) {
    unsigned int i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
    dgflow_cuda::Fp12 x;
    flags[i]=dgflow_cuda::fp12_decode(raw+576ull*i,&x)&&dgflow_cuda::fp12_gt_member(x);
}
extern "C" __global__ void dgfl_gt_verify(const unsigned char* b_raw,
        const unsigned char* e_raw,const unsigned char* zs_raw,const unsigned char* t_raw,
        const unsigned char* challenge_raw,unsigned int* flags,unsigned int count) {
    using namespace dgflow_cuda;
    unsigned int i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;flags[i]=0;
    Fp12 b,e,t;uint32_t zs[8],challenge[8];
    if(!fp12_decode(b_raw+576ull*i,&b)||!fp12_decode(e_raw+576ull*i,&e)
        ||!fp12_decode(t_raw,&t)||!gt_scalar_decode_be(zs_raw+32ull*i,zs)
        ||!gt_scalar_decode_be(challenge_raw,challenge))return;
    if(!fp12_gt_member(b)||!fp12_gt_member(e))return;
    // Host validates immutable T once with dgfl_gt_validate; this additional
    // exact Phi12 gate ensures cyclotomic squaring is safe in this kernel.
    if(!fp12_cyclotomic_member(t))return;
    // Proof responses/challenges are large public scalars. Use the direct
    // power here to avoid the extra signed-power call frame for a marginal
    // exponent reduction; signed powers remain useful for small negative
    // interpolation coefficients in the batch power/product kernels.
    flags[i]=fp12_eq(fp12_pow_words(t,zs,8,true),fp12_mul(b,
        fp12_pow_words(e,challenge,8,true)));
}
// A verifier-owned PUBLIC 4-bit positional table. Host full-q validation of T
// is mandatory. The table contains Montgomery Fp12, never private exponents.
extern "C" __global__ void dgfl_gt_prepare_public_table(const unsigned char* t_raw,
        unsigned char* table_raw, unsigned int* flags, unsigned int windows) {
    using namespace dgflow_cuda;
    static_assert(sizeof(Fp12)==576,"unexpected Fp12 table layout");
    unsigned int w=blockIdx.x*blockDim.x+threadIdx.x;if(w>=windows)return;
    flags[w]=0;if(windows!=64)return;
    Fp12 base;if(!fp12_decode(t_raw,&base)||!fp12_cyclotomic_member(base))return;
    for(unsigned int k=0;k<4*w;++k)base=fp12_cyclotomic_square(base);
    Fp12* table=reinterpret_cast<Fp12*>(table_raw);
    Fp12 value=fp12_one();
    for(unsigned int digit=0;digit<16;++digit) {
        table[w*16+digit]=value;
        if(digit!=15)value=fp12_mul(value,base);
    }
    flags[w]=1;
}
// Tables are generated above from this verifier's fully checked immutable T.
// Scalar-indexed lookup is limited to PUBLIC proof responses. B/E retain exact
// nonzero/q-subgroup checks, and each row has its own original challenge.
extern "C" __global__ void dgfl_gt_verify_many(const unsigned char* b_raw,
        const unsigned char* e_raw,const unsigned char* zs_raw,
        const unsigned char* t_raw,const unsigned char* table_raw,
        const unsigned char* challenges,unsigned int* flags,unsigned int count) {
    using namespace dgflow_cuda;
    unsigned int i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;flags[i]=0;
    Fp12 b,e,t;uint32_t zs[8],challenge[8];
    if(!fp12_decode(b_raw+576ull*i,&b)||!fp12_decode(e_raw+576ull*i,&e)
        ||!fp12_decode(t_raw,&t)||!gt_scalar_decode_be(zs_raw+32ull*i,zs)
        ||!gt_scalar_decode_be(challenges+32ull*i,challenge))return;
    if(!fp12_gt_member(b)||!fp12_gt_member(e)||!fp12_cyclotomic_member(t))return;
    const Fp12* table=reinterpret_cast<const Fp12*>(table_raw);
    Fp12 lhs=fp12_one();
    #pragma unroll 1
    for(unsigned int w=0;w<64;++w) {
        unsigned int digit=(zs[w/8]>>(4*(w%8)))&15u;
        if(digit)lhs=fp12_mul(lhs,table[w*16+digit]);
    }
    flags[i]=fp12_eq(lhs,fp12_mul(b,fp12_pow_words(e,challenge,8,true)));
}
extern "C" __global__ void dgfl_gt_pow_batch(const unsigned char* inputs,
        const unsigned char* scalars,unsigned char* outputs,unsigned int* flags,
        unsigned int count,unsigned int check_inputs) {
    using namespace dgflow_cuda;
    unsigned int i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;flags[i]=0;
    Fp12 x;uint32_t scalar[8];
    if(!fp12_decode(inputs+576ull*i,&x)||!gt_scalar_decode_be(scalars+32ull*i,scalar))return;
    // check_inputs=0 is reserved for bytes produced by a prior checked GPU
    // proof verification within the same trusted verifier instance.
    if(check_inputs ? !fp12_gt_member(x) : !fp12_cyclotomic_member(x))return;
    fp12_encode(fp12_pow_gt_words(x,scalar),outputs+576ull*i);flags[i]=1;
}
extern "C" __global__ void dgfl_gt_product_powers_batch(const unsigned char* inputs,
        const unsigned char* scalars,unsigned char* outputs,unsigned int* flags,
        unsigned int row_count,unsigned int terms,unsigned int check_inputs) {
    using namespace dgflow_cuda;
    unsigned int i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=row_count)return;flags[i]=0;
    // Final recovery is D times up to 32 cloud E powers. The loop streams
    // one Fp12 value/scalar, so the extra term needs no larger local array.
    if(terms<1 || terms>33)return;
    Fp12 result=fp12_one();
    for(unsigned int j=0;j<terms;++j) {
        unsigned long long k=(unsigned long long)i*terms+j;Fp12 x;uint32_t scalar[8];
        if(!fp12_decode(inputs+576ull*k,&x)||!gt_scalar_decode_be(scalars+32ull*k,scalar))return;
        if(check_inputs ? !fp12_gt_member(x) : !fp12_cyclotomic_member(x))return;
        result=fp12_mul(result,fp12_pow_gt_words(x,scalar));
    }
    fp12_encode(result,outputs+576ull*i);flags[i]=1;
}
// A narrow arithmetic oracle used by CUDA/native differential checks. It
// deliberately uses generic Fq12 arithmetic, including arbitrary field inputs.
extern "C" __global__ void dgfl_gt_arithmetic(const unsigned char* a_raw,
        const unsigned char* b_raw,unsigned char* outputs,unsigned int* flags,
        unsigned int count,unsigned int operation) {
    using namespace dgflow_cuda;
    unsigned int i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;flags[i]=0;
    Fp12 a,b;if(!fp12_decode(a_raw+576ull*i,&a))return;
    if(operation==0) {if(!fp12_decode(b_raw+576ull*i,&b))return;a=fp12_mul(a,b);}
    else if(operation==1) a=fp12_square(a);
    else if(operation==2) a=fp12_frobenius_even(a,2);
    else if(operation==3) a=fp12_frobenius_even(a,4);
    else if(operation==4) {if(!fp12_cyclotomic_member(a))return;a=fp12_cyclotomic_square(a);}
    // Full arbitrary-field Frobenius oracle, including values outside GT.
    else if(operation==5) a=fp12_frobenius_one(a);
    else return;
    fp12_encode(a,outputs+576ull*i);flags[i]=1;
}
