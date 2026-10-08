// BLS12-381 G1 public scalar batches. Input points must also be checked for
// prime-order subgroup membership by the host's canonical group decoder.
#ifndef DGFLOW_CUDA_G1_CUH
#define DGFLOW_CUDA_G1_CUH
#include "field.cuh"

namespace dgflow_cuda {
struct G1Affine { Fp x,y; bool infinity; };
struct G1Jacobian { Fp x,y,z; };

DGFLOW_DEVICE G1Jacobian g1_identity() {
    G1Jacobian out; out.x=fp_zero(); out.y=fp_one(); out.z=fp_zero(); return out;
}
DGFLOW_DEVICE bool g1_is_zero(const G1Jacobian& a) { return fp_is_zero(a.z); }
DGFLOW_DEVICE G1Jacobian g1_from_affine(const G1Affine& a) {
    if (a.infinity) return g1_identity();
    G1Jacobian out; out.x=a.x; out.y=a.y; out.z=fp_one(); return out;
}
// Keep the point formulas as device calls: force-inlining every Horner/MSM
// call site under NVRTC's fast compilation creates a much larger per-thread
// local-memory frame and can exhaust VRAM across independent actor contexts.
DGFLOW_COMPLEX_DEVICE G1Jacobian g1_double(const G1Jacobian& p) {
    if (g1_is_zero(p) || fp_is_zero(p.y)) return g1_identity();
    // dbl-2009-l, short Weierstrass a=0, Jacobian x=X/Z^2, y=Y/Z^3.
    Fp a=fp_square(p.x), b=fp_square(p.y), c=fp_square(b);
    Fp d=fp_sub(fp_sub(fp_square(fp_add(p.x,b)),a),c); d=fp_add(d,d);
    Fp e=fp_add(fp_add(a,a),a), f=fp_square(e);
    G1Jacobian out;
    out.x=fp_sub(f,fp_add(d,d));
    Fp c8=fp_add(c,c); c8=fp_add(c8,c8); c8=fp_add(c8,c8);
    out.y=fp_sub(fp_mul(e,fp_sub(d,out.x)),c8);
    out.z=fp_mul(fp_add(p.y,p.y),p.z);
    return out;
}
DGFLOW_COMPLEX_DEVICE G1Jacobian g1_add_mixed(const G1Jacobian& p, const G1Affine& q) {
    if (q.infinity) return p;
    if (g1_is_zero(p)) return g1_from_affine(q);
    // madd-2007-bl with explicit equal/opposite-point exceptional cases.
    Fp zz=fp_square(p.z), u=fp_mul(q.x,zz);
    Fp s=fp_mul(q.y,fp_mul(p.z,zz));
    Fp h=fp_sub(u,p.x), sy=fp_sub(s,p.y);
    if (fp_is_zero(h)) return fp_is_zero(sy)?g1_double(p):g1_identity();
    Fp hh=fp_square(h), i=fp_add(hh,hh); i=fp_add(i,i);
    Fp j=fp_mul(h,i), r=fp_add(sy,sy), v=fp_mul(p.x,i);
    G1Jacobian out;
    out.x=fp_sub(fp_sub(fp_square(r),j),fp_add(v,v));
    out.y=fp_sub(fp_mul(r,fp_sub(v,out.x)),fp_mul(fp_add(p.y,p.y),j));
    out.z=fp_sub(fp_sub(fp_square(fp_add(p.z,h)),zz),hh);
    return out;
}
DGFLOW_COMPLEX_DEVICE G1Jacobian g1_add(const G1Jacobian& p, const G1Jacobian& q) {
    if (g1_is_zero(p)) return q;
    if (g1_is_zero(q)) return p;
    Fp z1z1=fp_square(p.z), z2z2=fp_square(q.z);
    Fp u1=fp_mul(p.x,z2z2), u2=fp_mul(q.x,z1z1);
    Fp s1=fp_mul(p.y,fp_mul(q.z,z2z2));
    Fp s2=fp_mul(q.y,fp_mul(p.z,z1z1));
    Fp h=fp_sub(u2,u1), sy=fp_sub(s2,s1);
    if (fp_is_zero(h)) return fp_is_zero(sy)?g1_double(p):g1_identity();
    Fp twoh=fp_add(h,h), i=fp_square(twoh), j=fp_mul(h,i);
    Fp r=fp_add(sy,sy), v=fp_mul(u1,i);
    G1Jacobian out;
    out.x=fp_sub(fp_sub(fp_square(r),j),fp_add(v,v));
    out.y=fp_sub(fp_mul(r,fp_sub(v,out.x)),fp_mul(fp_add(s1,s1),j));
    out.z=fp_mul(fp_sub(fp_sub(fp_square(fp_add(p.z,q.z)),z1z1),z2z2),h);
    return out;
}
DGFLOW_DEVICE G1Affine g1_to_affine(const G1Jacobian& p) {
    G1Affine out; out.infinity=g1_is_zero(p);
    if (out.infinity) { out.x=fp_zero(); out.y=fp_zero(); return out; }
    Fp zi=fp_inv(p.z), zz=fp_square(zi);
    out.x=fp_mul(p.x,zz); out.y=fp_mul(p.y,fp_mul(zi,zz)); return out;
}
DGFLOW_DEVICE bool g1_decode_xy(const unsigned char* raw, G1Affine* out) {
    if (!fp_decode(raw,&out->x) || !fp_decode(raw+48,&out->y)) return false;
    out->infinity=fp_is_zero(out->x)&&fp_is_zero(out->y);
    if (out->infinity) return true;
    return fp_eq(fp_square(out->y),fp_add(fp_mul(fp_square(out->x),out->x),fp_from_u32(4)));
}
DGFLOW_DEVICE void g1_encode_xy(const G1Affine& p, unsigned char* raw) {
    if (p.infinity) { for (int i=0; i<96; ++i) raw[i]=0; return; }
    fp_encode(p.x,raw); fp_encode(p.y,raw+48);
}
DGFLOW_DEVICE G1Jacobian g1_scalar_mul(const G1Affine& p, const uint32_t* scalar) {
    G1Jacobian out=g1_identity();
    for (int bit=254; bit>=0; --bit) {
        out=g1_double(out);
        if ((scalar[bit/32]>>(bit%32))&1u) out=g1_add_mixed(out,p);
    }
    return out;
}
// Share the 255 doublings across the 1..4 public scalar products in each row.
DGFLOW_DEVICE G1Jacobian g1_small_msm(const G1Affine* points, const uint32_t scalars[4][8], int count) {
    G1Jacobian out=g1_identity();
    for (int bit=254; bit>=0; --bit) {
        out=g1_double(out);
        for (int k=0; k<count; ++k) {
            if ((scalars[k][bit/32]>>(bit%32))&1u) out=g1_add_mixed(out,points[k]);
        }
    }
    return out;
}
DGFLOW_DEVICE bool g1_decode_row(const unsigned char* points, const unsigned char* scalars,
                               G1Affine* decoded, uint32_t words[4][8], int count) {
    if (count<1 || count>4) return false;
    for (int i=0; i<count; ++i) {
        if (!g1_decode_xy(points+96*i,&decoded[i]) ||
            !scalar_decode_be(scalars+32*i,words[i])) return false;
    }
    return true;
}
// Horner evaluation stays in Jacobian coordinates. The caller's public cloud
// identifier is bounded by 32, so each multiplication needs at most six bits.
DGFLOW_DEVICE G1Jacobian g1_mul_public_u32(const G1Jacobian& p, uint32_t scalar) {
    if (scalar==0 || g1_is_zero(p)) return g1_identity();
    int bit=31; while (((scalar>>bit)&1u)==0) --bit;
    G1Jacobian out=p;
    for (--bit; bit>=0; --bit) {
        out=g1_double(out);
        if ((scalar>>bit)&1u) out=g1_add(out,p);
    }
    return out;
}
DGFLOW_DEVICE bool g1_decode_polynomial(const unsigned char* raw, int terms,
        uint32_t cloud_id, G1Jacobian* polynomial) {
    // Horner streams one checked affine coefficient at a time; unlike the
    // separate small MSM kernel, this path has no four-element local array.
    // The 32 coefficients cover every configured cloud threshold.
    if (terms<2 || terms>32 || cloud_id<1 || cloud_id>32) return false;
    G1Affine coefficient;
    if (!g1_decode_xy(raw+96*(terms-1),&coefficient)) return false;
    *polynomial=g1_from_affine(coefficient);
    for (int k=terms-2; k>=0; --k) {
        if (!g1_decode_xy(raw+96*k,&coefficient)) return false;
        *polynomial=g1_add_mixed(g1_mul_public_u32(*polynomial,cloud_id),coefficient);
    }
    return true;
}
// Keep each original equation independent. Negate the polynomial and A as
// points rather than replacing their public coefficients by q-c and q-1.
// This saves the full scalar product for A and the per-row affine inversion.
DGFLOW_DEVICE bool g1_verify_polynomial_row(const unsigned char* polynomial_xy,
        const unsigned char* a_xy, const unsigned char* responses_zs_zr,
        const unsigned char* bases_g_h, const unsigned char* challenge_raw,
        int terms, uint32_t cloud_id, bool* identity) {
    G1Jacobian polynomial;
    G1Affine g,h,a;
    uint32_t zs[8],zr[8],challenge[8];
    if (!g1_decode_polynomial(polynomial_xy,terms,cloud_id,&polynomial) ||
        !g1_decode_xy(bases_g_h,&g) || !g1_decode_xy(bases_g_h+96,&h) ||
        !g1_decode_xy(a_xy,&a) || !scalar_decode_be(responses_zs_zr,zs) ||
        !scalar_decode_be(responses_zs_zr+32,zr) ||
        !scalar_decode_be(challenge_raw,challenge)) return false;
    polynomial.y=fp_neg(polynomial.y);
    G1Jacobian sum=g1_identity();
    #pragma unroll 1
    for (int bit=254; bit>=0; --bit) {
        sum=g1_double(sum);
        if ((zs[bit/32]>>(bit%32))&1u) sum=g1_add_mixed(sum,g);
        if ((zr[bit/32]>>(bit%32))&1u) sum=g1_add_mixed(sum,h);
        if ((challenge[bit/32]>>(bit%32))&1u) sum=g1_add(sum,polynomial);
    }
    a.y=fp_neg(a.y);
    *identity=g1_is_zero(g1_add_mixed(sum,a));
    return true;
}
} // namespace dgflow_cuda

#if defined(__CUDACC__)
// Contiguous row-major buffers. valid[row]==0 rejects the row; output is zeroed.
// Host canonical/subgroup validation is mandatory before either kernel launch.
extern "C" __global__ void dgflow_g1_msm(const unsigned char* points,
    const unsigned char* scalars, unsigned char* output, unsigned int* valid,
    int rows, int points_per_row) {
    int row=(int)(blockIdx.x*blockDim.x+threadIdx.x); if (row>=rows) return;
    using namespace dgflow_cuda;
    G1Affine decoded[4]; uint32_t words[4][8];
    bool ok=g1_decode_row(points+(unsigned long long)row*points_per_row*96,
                         scalars+(unsigned long long)row*points_per_row*32,
                         decoded,words,points_per_row);
    valid[row]=(unsigned int)ok;
    if (!ok) { for (int i=0; i<96; ++i) output[(unsigned long long)row*96+i]=0; return; }
    g1_encode_xy(g1_to_affine(g1_small_msm(decoded,words,points_per_row)),output+(unsigned long long)row*96);
}
// Faster proof-equation variant avoids per-row inversion and affine output.
// verdict: 0 = invalid input, 1 = valid nonzero sum, 2 = valid identity sum.
extern "C" __global__ void dgflow_g1_equation_zero(const unsigned char* points,
    const unsigned char* scalars, unsigned int* verdict, int rows, int points_per_row) {
    int row=(int)(blockIdx.x*blockDim.x+threadIdx.x); if (row>=rows) return;
    using namespace dgflow_cuda;
    G1Affine decoded[4]; uint32_t words[4][8];
    if (!g1_decode_row(points+(unsigned long long)row*points_per_row*96,
                       scalars+(unsigned long long)row*points_per_row*32,
                       decoded,words,points_per_row)) { verdict[row]=0; return; }
    verdict[row]=g1_is_zero(g1_small_msm(decoded,words,points_per_row))?2:1;
}
// Input points have already passed the host's canonical subgroup decoder.
// Kernel decoding additionally rejects noncanonical coefficients/off-curve
// points. No host affine output, inversion or intermediate buffer is needed.
extern "C" __global__ void dgflow_g1_verify_polynomial(
    const unsigned char* polynomial_xy, const unsigned char* a_xy,
    const unsigned char* responses_zs_zr, const unsigned char* bases_g_h,
    const unsigned char* challenge_raw, unsigned int* verdict,
    int rows, int terms, int cloud_id) {
    int row=(int)(blockIdx.x*blockDim.x+threadIdx.x); if (row>=rows) return;
    bool identity=false;
    bool valid=dgflow_cuda::g1_verify_polynomial_row(
        polynomial_xy+(unsigned long long)row*terms*96,
        a_xy+(unsigned long long)row*96,
        responses_zs_zr+(unsigned long long)row*64,
        bases_g_h,challenge_raw,terms,(unsigned int)cloud_id,&identity);
    verdict[row]=valid?(identity?2u:1u):0u;
}
// Independent proof statements can share a launch, but every coordinate keeps
// its own authenticated cloud identifier and Fiat-Shamir challenge.
extern "C" __global__ void dgflow_g1_verify_polynomial_many(
    const unsigned char* polynomial_xy, const unsigned char* a_xy,
    const unsigned char* responses_zs_zr, const unsigned char* bases_g_h,
    const unsigned char* challenges, const unsigned char* cloud_ids,
    unsigned int* verdict, int rows, int terms) {
    int row=(int)(blockIdx.x*blockDim.x+threadIdx.x); if (row>=rows) return;
    const unsigned char* cloud=cloud_ids+4ull*row;
    unsigned int cloud_id=(unsigned int)cloud[0]|((unsigned int)cloud[1]<<8)|
        ((unsigned int)cloud[2]<<16)|((unsigned int)cloud[3]<<24);
    bool identity=false;
    bool valid=dgflow_cuda::g1_verify_polynomial_row(
        polynomial_xy+(unsigned long long)row*terms*96,
        a_xy+(unsigned long long)row*96,
        responses_zs_zr+(unsigned long long)row*64,
        bases_g_h,challenges+32ull*row,terms,cloud_id,&identity);
    verdict[row]=valid?(identity?2u:1u):0u;
}
#endif
#endif
