#ifndef CUDA_VECTOR_H
#define CUDA_VECTOR_H


///////////////////////////////////////////////////////////////////////////////////
#if (defined(_MSC_VER) && defined(_WIN64)) || defined(__LP64__)
#define __LDG_PTR   "l"
#else
#define __LDG_PTR   "r"
#endif

#include "cuda_helper.h"

//typedef __device_builtin__ struct ulong16 ulong16;


typedef struct __align__(32) uint8
{
	unsigned int s0, s1, s2, s3, s4, s5, s6, s7;
} uint8;

typedef struct __align__(64) ulonglong2to8
{
ulonglong2 l0,l1,l2,l3;
} ulonglong2to8;

typedef struct __align__(128) ulonglong8to16
{
	ulonglong2to8 lo, hi;
} ulonglong8to16;

typedef struct __align__(256) ulonglong16to32
{
	ulonglong8to16 lo, hi;
} ulonglong16to32;

typedef struct __align__(512) ulonglong32to64
{
	ulonglong16to32 lo, hi;
} ulonglong32to64;



typedef struct __align__(1024) ulonglonglong
{
	ulonglong8to16 s0,s1,s2,s3,s4,s5,s6,s7;
} ulonglonglong;




typedef struct __align__(64) uint16
{
	union {
		struct {unsigned int  s0, s1, s2, s3, s4, s5, s6, s7;};
		uint8 lo;
	};
	union {
		struct {unsigned int s8, s9, sa, sb, sc, sd, se, sf;};
		uint8 hi;
	};
} uint16;

typedef struct __align__(128) uint32
{

		uint16 lo,hi;
} uint32;



struct __align__(128) ulong8
{
	ulonglong4 s0, s1, s2, s3;
};
typedef __device_builtin__ struct ulong8 ulong8;


typedef struct  __align__(256) ulonglong16
{
	ulonglong2 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, sa, sb, sc, sd, se, sf;
} ulonglong16;

typedef struct  __align__(32) uint48
{
	uint4 s0, s1;

} uint48;

typedef struct  __align__(64) uint816
{
	uint48 s0, s1;

} uint816;

typedef struct  __align__(128) uint1632
{
	uint816 s0, s1;

} uint1632;

typedef struct  __align__(256) uintx64
{
	uint1632 s0, s1;

} uintx64;

typedef struct  __align__(512) uintx128
{
	uintx64 s0, s1;

} uintx128;

typedef struct  __align__(1024) uintx256
{
	uintx128 s0, s1;

} uintx256;



typedef struct __align__(256) uint4x16
{
	uint4 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
} uint4x16;

static __inline__ __device__ ulonglong2to8 make_ulonglong2to8(ulonglong2 s0, ulonglong2 s1, ulonglong2 s2, ulonglong2 s3)
{
ulonglong2to8 t; t.l0=s0; t.l1=s1; t.l2=s2; t.l3=s3;
return t;
}

static __inline__ __device__ ulonglong8to16 make_ulonglong8to16(const ulonglong2to8 &s0, const ulonglong2to8 &s1)
{
	ulonglong8to16 t; t.lo = s0; t.hi = s1;
	return t;
}

static __inline__ __device__ ulonglong16to32 make_ulonglong16to32(const ulonglong8to16 &s0, const ulonglong8to16 &s1)
{
	ulonglong16to32 t; t.lo = s0; t.hi = s1;
	return t;
}

static __inline__ __device__ ulonglong32to64 make_ulonglong32to64(const ulonglong16to32 &s0, const ulonglong16to32 &s1)
{
	ulonglong32to64 t; t.lo = s0; t.hi = s1;
	return t;
}


static __inline__ __host__ __device__ ulonglonglong make_ulonglonglong(
	const ulonglong8to16 &s0, const ulonglong8to16 &s1, const ulonglong8to16 &s2, const ulonglong8to16 &s3,
	const ulonglong8to16 &s4, const ulonglong8to16 &s5, const ulonglong8to16 &s6, const ulonglong8to16 &s7)
{
	ulonglonglong t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3; t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
	return t;
}


static __inline__ __device__ uint48 make_uint48(uint4 s0, uint4 s1)
{
	uint48 t; t.s0 = s0; t.s1 = s1;
	return t;
}

static __inline__ __device__ uint816 make_uint816(const uint48 &s0, const uint48 &s1)
{
	uint816 t; t.s0 = s0; t.s1 = s1;
	return t;
}

static __inline__ __device__ uint1632 make_uint1632(const uint816 &s0, const uint816 &s1)
{
	uint1632 t; t.s0 = s0; t.s1 = s1;
	return t;
}

static __inline__ __device__ uintx64 make_uintx64(const uint1632 &s0, const uint1632 &s1)
{
	uintx64 t; t.s0 = s0; t.s1 = s1;
	return t;
}

static __inline__ __device__ uintx128 make_uintx128(const uintx64 &s0, const uintx64 &s1)
{
	uintx128 t; t.s0 = s0; t.s1 = s1;
	return t;
}

static __inline__ __device__ uintx256 make_uintx256(const uintx128 &s0, const uintx128 &s1)
{
	uintx256 t; t.s0 = s0; t.s1 = s1;
	return t;
}


static __inline__ __device__ uintx256 make_uintx64(const uintx128 &s0, const uintx128 &s1)
{
	uintx256 t; t.s0 = s0; t.s1 = s1;
	return t;
}


static __inline__ __host__ __device__ uint4x16 make_uint4x16(
	uint4 s0, uint4 s1, uint4 s2, uint4 s3, uint4 s4, uint4 s5, uint4 s6, uint4 s7,
	uint4 s8, uint4 s9, uint4 sa, uint4 sb, uint4 sc, uint4 sd, uint4 se, uint4 sf)
{
	uint4x16 t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3; t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
	t.s8 = s8; t.s9 = s9; t.s10 = sa; t.s11 = sb; t.s12 = sc; t.s13 = sd; t.s14 = se; t.s15 = sf;
	return t;
}




static __inline__ __host__ __device__ uint16 make_uint16(
	unsigned int s0, unsigned int s1, unsigned int s2, unsigned int s3, unsigned int s4, unsigned int s5, unsigned int s6, unsigned int s7,
	unsigned int s8, unsigned int s9, unsigned int sa, unsigned int sb, unsigned int sc, unsigned int sd, unsigned int se, unsigned int sf)
{
	uint16 t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3; t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
	t.s8 = s8; t.s9 = s9; t.sa = sa; t.sb = sb; t.sc = sc; t.sd = sd; t.se = se; t.sf = sf;
	return t;
}

static __inline__ __host__ __device__ uint16 make_uint16(const uint8 &a, const uint8 &b)
{
	uint16 t; t.lo=a; t.hi=b; return t;
}

static __inline__ __host__ __device__ uint32 make_uint32(const uint16 &a, const uint16 &b)
{
	uint32 t; t.lo = a; t.hi = b; return t;
}


static __inline__ __host__ __device__ uint8 make_uint8(
	unsigned int s0, unsigned int s1, unsigned int s2, unsigned int s3, unsigned int s4, unsigned int s5, unsigned int s6, unsigned int s7)
{
	uint8 t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3; t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
	return t;
}


static __inline__ __host__ __device__ ulonglong16 make_ulonglong16(const ulonglong2 &s0, const ulonglong2 &s1,
	const ulonglong2 &s2, const ulonglong2 &s3, const ulonglong2 &s4, const ulonglong2 &s5, const ulonglong2 &s6, const ulonglong2 &s7,
	const ulonglong2 &s8, const ulonglong2 &s9,
	const ulonglong2 &sa, const ulonglong2 &sb, const ulonglong2 &sc, const ulonglong2 &sd, const ulonglong2 &se, const ulonglong2 &sf
) {
	ulonglong16 t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3; t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
	t.s8 = s8; t.s9 = s9; t.sa = sa; t.sb = sb; t.sc = sc; t.sd = sd; t.se = se; t.sf = sf;
	return t;
}



static __inline__ __host__ __device__ ulong8 make_ulong8(
	ulonglong4 s0, ulonglong4 s1, ulonglong4 s2, ulonglong4 s3)
{
	ulong8 t; t.s0 = s0; t.s1 = s1; t.s2 = s2; t.s3 = s3;// t.s4 = s4; t.s5 = s5; t.s6 = s6; t.s7 = s7;
	return t;
}


static __forceinline__ __device__ uchar4 operator^ (uchar4 a, uchar4 b) { return make_uchar4(a.x ^ b.x, a.y ^ b.y, a.z ^ b.z, a.w ^ b.w); }
static __forceinline__ __device__ uchar4 operator+ (uchar4 a, uchar4 b) { return make_uchar4(a.x + b.x, a.y + b.y, a.z + b.z, a.w + b.w); }





static __forceinline__ __device__ uint4 operator^ (uint4 a, uint4 b) { return make_uint4(a.x ^ b.x, a.y ^ b.y, a.z ^ b.z, a.w ^ b.w); }
static __forceinline__ __device__ uint4 operator+ (uint4 a, uint4 b) { return make_uint4(a.x + b.x, a.y + b.y, a.z + b.z, a.w + b.w); }


static __forceinline__ __device__ ulonglong4 operator^ (ulonglong4 a, ulonglong4 b) { return make_ulonglong4(a.x ^ b.x, a.y ^ b.y, a.z ^ b.z, a.w ^ b.w); }
static __forceinline__ __device__ ulonglong4 operator+ (ulonglong4 a, ulonglong4 b) { return make_ulonglong4(a.x + b.x, a.y + b.y, a.z + b.z, a.w + b.w); }
static __forceinline__ __device__ ulonglong2 operator^ (ulonglong2 a, ulonglong2 b) { return make_ulonglong2(a.x ^ b.x, a.y ^ b.y); }
static __forceinline__ __device__ ulonglong2 operator+ (ulonglong2 a, ulonglong2 b) { return make_ulonglong2(a.x + b.x, a.y + b.y); }

static __forceinline__ __device__ ulong8 operator^ (const ulong8 &a, const ulong8 &b) {
	return make_ulong8(a.s0 ^ b.s0, a.s1 ^ b.s1, a.s2 ^ b.s2, a.s3 ^ b.s3);
} //, a.s4 ^ b.s4, a.s5 ^ b.s5, a.s6 ^ b.s6, a.s7 ^ b.s7); }

static __forceinline__ __device__ ulong8 operator+ (const ulong8 &a, const ulong8 &b) {
	return make_ulong8(a.s0 + b.s0, a.s1 + b.s1, a.s2 + b.s2, a.s3 + b.s3);
} //, a.s4 + b.s4, a.s5 + b.s5, a.s6 + b.s6, a.s7 + b.s7); }


static __forceinline__ __device__  __host__ uint8 operator^ (const uint8 &a, const uint8 &b) { return make_uint8(a.s0 ^ b.s0, a.s1 ^ b.s1, a.s2 ^ b.s2, a.s3 ^ b.s3, a.s4 ^ b.s4, a.s5 ^ b.s5, a.s6 ^ b.s6, a.s7 ^ b.s7); }

static __forceinline__ __device__  __host__ uint8 operator+ (const uint8 &a, const uint8 &b) { return make_uint8(a.s0 + b.s0, a.s1 + b.s1, a.s2 + b.s2, a.s3 + b.s3, a.s4 + b.s4, a.s5 + b.s5, a.s6 + b.s6, a.s7 + b.s7); }

////////////// mess++ //////

static __forceinline__ __device__  uint48 operator^ (const uint48 &a, const uint48 &b) {
	return make_uint48(a.s0 ^ b.s0, a.s1 ^ b.s1);
}

static __forceinline__ __device__  uint816 operator^ (const uint816 &a, const uint816 &b) {
	return make_uint816(a.s0 ^ b.s0, a.s1 ^ b.s1);
}

static __forceinline__ __device__ uint1632 operator^ (const uint1632 &a, const uint1632 &b) {
	return make_uint1632(a.s0 ^ b.s0, a.s1 ^ b.s1);
}


static __forceinline__ __device__  uintx64 operator^ (const uintx64 &a, const uintx64 &b) {
	return make_uintx64(a.s0 ^ b.s0, a.s1 ^ b.s1);
}

static __forceinline__ __device__  uintx128 operator^ (const uintx128 &a, const uintx128 &b) {
	return make_uintx128(a.s0 ^ b.s0, a.s1 ^ b.s1);
}

static __forceinline__ __device__  uintx256 operator^ (const uintx256 &a, const uintx256 &b) {
	return make_uintx256(a.s0 ^ b.s0, a.s1 ^ b.s1);
}

/////////////////////////

static __forceinline__ __device__ __host__ uint16 operator^ (const uint16 &a, const uint16 &b) {
	return make_uint16(a.s0 ^ b.s0, a.s1 ^ b.s1, a.s2 ^ b.s2, a.s3 ^ b.s3, a.s4 ^ b.s4, a.s5 ^ b.s5, a.s6 ^ b.s6, a.s7 ^ b.s7,
		a.s8 ^ b.s8, a.s9 ^ b.s9, a.sa ^ b.sa, a.sb ^ b.sb, a.sc ^ b.sc, a.sd ^ b.sd, a.se ^ b.se, a.sf ^ b.sf);
}

static __forceinline__ __device__  __host__ uint16 operator+ (const uint16 &a, const uint16 &b) {
	return make_uint16(a.s0 + b.s0, a.s1 + b.s1, a.s2 + b.s2, a.s3 + b.s3, a.s4 + b.s4, a.s5 + b.s5, a.s6 + b.s6, a.s7 + b.s7,
		a.s8 + b.s8, a.s9 + b.s9, a.sa + b.sa, a.sb + b.sb, a.sc + b.sc, a.sd + b.sd, a.se + b.se, a.sf + b.sf);
}

static __forceinline__ __device__  uint32 operator^ (const uint32 &a, const uint32 &b) {
	return make_uint32(a.lo ^ b.lo, a.hi ^ b.hi);
}

static __forceinline__ __device__  uint32 operator+ (const uint32 &a, const uint32 &b) {
	return make_uint32(a.lo + b.lo, a.hi + b.hi);
}

static __forceinline__ __device__ ulonglong16 operator^ (const ulonglong16 &a, const ulonglong16 &b) {
	return make_ulonglong16(a.s0 ^ b.s0, a.s1 ^ b.s1, a.s2 ^ b.s2, a.s3 ^ b.s3, a.s4 ^ b.s4, a.s5 ^ b.s5, a.s6 ^ b.s6, a.s7 ^ b.s7,
		a.s8 ^ b.s8, a.s9 ^ b.s9, a.sa ^ b.sa, a.sb ^ b.sb, a.sc ^ b.sc, a.sd ^ b.sd, a.se ^ b.se, a.sf ^ b.sf
);
}

static __forceinline__ __device__ ulonglong16 operator+ (const ulonglong16 &a, const ulonglong16 &b) {
	return make_ulonglong16(a.s0 + b.s0, a.s1 + b.s1, a.s2 + b.s2, a.s3 + b.s3, a.s4 + b.s4, a.s5 + b.s5, a.s6 + b.s6, a.s7 + b.s7,
		a.s8 + b.s8, a.s9 + b.s9, a.sa + b.sa, a.sb + b.sb, a.sc + b.sc, a.sd + b.sd, a.se + b.se, a.sf + b.sf
);
}

static __forceinline__ __device__ void operator^= (ulong8 &a, const ulong8 &b) { a = a ^ b; }
static __forceinline__ __device__ void operator^= (uintx64 &a, const uintx64 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator^= (uintx128 &a, const uintx128 &b) { a = a ^ b; }
static __forceinline__ __device__ void operator^= (uintx256 &a, const uintx256 &b) { a = a ^ b; }


static __forceinline__ __device__ void operator^= (uint816 &a, const uint816 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator^= (uint48 &a, const uint48 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator^= (uint32 &a, const uint32 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator+= (uint32 &a, const uint32 &b) { a = a + b; }


static __forceinline__ __device__ void operator^= (uint4 &a, uint4 b) { a = a ^ b; }
static __forceinline__ __device__ void operator^= (uchar4 &a, uchar4 b) { a = a ^ b; }
static __forceinline__ __device__  __host__ void operator^= (uint8 &a, const uint8 &b) { a = a ^ b; }
static __forceinline__ __device__  __host__ void operator^= (uint16 &a, const uint16 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator^= (ulonglong16 &a, const ulonglong16 &b) { a = a ^ b; }
static __forceinline__ __device__ void operator^= (ulonglong4 &a, const ulonglong4 &b) { a = a ^ b; }
static __forceinline__ __device__ void operator^= (ulonglong2 &a, const ulonglong2 &b) { a = a ^ b; }
static __forceinline__ __device__ void operator+= (ulonglong2 &a, const ulonglong2 &b) { a = a + b; }

static __forceinline__ __device__
ulonglong2to8 operator^ (const ulonglong2to8 &a, const ulonglong2to8 &b)
{
	return make_ulonglong2to8(a.l0 ^ b.l0, a.l1 ^ b.l1, a.l2 ^ b.l2, a.l3 ^ b.l3);
}
static __forceinline__ __device__
ulonglong2to8 operator+ (const ulonglong2to8 &a, const ulonglong2to8 &b)
{
	return make_ulonglong2to8(a.l0 + b.l0, a.l1 + b.l1, a.l2 + b.l2, a.l3 + b.l3);
}


static __forceinline__ __device__
ulonglong8to16 operator^ (const ulonglong8to16 &a, const ulonglong8to16 &b)
{
	return make_ulonglong8to16(a.lo ^ b.lo, a.hi ^ b.hi);
}

static __forceinline__ __device__
ulonglong8to16 operator+ (const ulonglong8to16 &a, const ulonglong8to16 &b)
{
	return make_ulonglong8to16(a.lo + b.lo, a.hi + b.hi);
}

static __forceinline__ __device__
ulonglong16to32 operator^ (const ulonglong16to32 &a, const ulonglong16to32 &b)
{
	return make_ulonglong16to32(a.lo ^ b.lo, a.hi ^ b.hi);
}

static __forceinline__ __device__
ulonglong16to32 operator+ (const ulonglong16to32 &a, const ulonglong16to32 &b)
{
	return make_ulonglong16to32(a.lo + b.lo, a.hi + b.hi);
}

static __forceinline__ __device__
ulonglong32to64 operator^ (const ulonglong32to64 &a, const ulonglong32to64 &b)
{
	return make_ulonglong32to64(a.lo ^ b.lo, a.hi ^ b.hi);
}

static __forceinline__ __device__
ulonglong32to64 operator+ (const ulonglong32to64 &a, const ulonglong32to64 &b)
{
	return make_ulonglong32to64(a.lo + b.lo, a.hi + b.hi);
}


static __forceinline__ __device__ ulonglonglong operator^ (const ulonglonglong &a, const ulonglonglong &b) {
	return make_ulonglonglong(a.s0 ^ b.s0, a.s1 ^ b.s1, a.s2 ^ b.s2, a.s3 ^ b.s3, a.s4 ^ b.s4, a.s5 ^ b.s5, a.s6 ^ b.s6, a.s7 ^ b.s7);
}

static __forceinline__ __device__ ulonglonglong operator+ (const ulonglonglong &a, const ulonglonglong &b) {
	return make_ulonglonglong(a.s0 + b.s0, a.s1 + b.s1, a.s2 + b.s2, a.s3 + b.s3, a.s4 + b.s4, a.s5 + b.s5, a.s6 + b.s6, a.s7 + b.s7);
}


static __forceinline__ __device__ void operator^= (ulonglong2to8 &a, const ulonglong2to8 &b) { a = a ^ b; }


static __forceinline__ __device__ void operator+= (uint4 &a, uint4 b) { a = a + b; }
static __forceinline__ __device__ void operator+= (uchar4 &a, uchar4 b) { a = a + b; }
static __forceinline__ __device__  __host__ void operator+= (uint8 &a, const uint8 &b) { a = a + b; }
static __forceinline__ __device__  __host__ void operator+= (uint16 &a, const uint16 &b) { a = a + b; }
static __forceinline__ __device__ void operator+= (ulong8 &a, const ulong8 &b) { a = a + b; }
static __forceinline__ __device__ void operator+= (ulonglong16 &a, const ulonglong16 &b) { a = a + b; }
static __forceinline__ __device__ void operator+= (ulonglong8to16 &a, const ulonglong8to16 &b) { a = a + b; }
static __forceinline__ __device__ void operator^= (ulonglong8to16 &a, const ulonglong8to16 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator+= (ulonglong16to32 &a, const ulonglong16to32 &b) { a = a + b; }
static __forceinline__ __device__ void operator^= (ulonglong16to32 &a, const ulonglong16to32 &b) { a = a ^ b; }

static __forceinline__ __device__ void operator+= (ulonglong32to64 &a, const ulonglong32to64 &b) { a = a + b; }
static __forceinline__ __device__ void operator^= (ulonglong32to64 &a, const ulonglong32to64 &b) { a = a ^ b; }


static __forceinline__ __device__ void operator+= (ulonglonglong &a, const ulonglonglong &b) { a = a + b; }
static __forceinline__ __device__ void operator^= (ulonglonglong &a, const ulonglonglong &b) { a = a ^ b; }

#if __CUDA_ARCH__ < 320

#define rotate ROTL32
#define rotateR ROTR32

#else

static __forceinline__ __device__ uint4 rotate4(uint4 vec4, uint32_t shift)
{
	uint4 ret;
	asm("shf.l.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.x) : "r"(vec4.x), "r"(vec4.x), "r"(shift));
	asm("shf.l.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.y) : "r"(vec4.y), "r"(vec4.y), "r"(shift));
	asm("shf.l.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.z) : "r"(vec4.z), "r"(vec4.z), "r"(shift));
	asm("shf.l.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.w) : "r"(vec4.w), "r"(vec4.w), "r"(shift));
	return ret;
}

static __forceinline__ __device__ uint4 rotate4R(uint4 vec4, uint32_t shift)
{
	uint4 ret;
	asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.x) : "r"(vec4.x), "r"(vec4.x), "r"(shift));
	asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.y) : "r"(vec4.y), "r"(vec4.y), "r"(shift));
	asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.z) : "r"(vec4.z), "r"(vec4.z), "r"(shift));
	asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(ret.w) : "r"(vec4.w), "r"(vec4.w), "r"(shift));
	return ret;
}

static __forceinline__ __device__ uint32_t rotate(uint32_t vec4, uint32_t shift)
{
	uint32_t ret;
	asm("shf.l.wrap.b32 %0, %1, %2, %3;" : "=r"(ret) : "r"(vec4), "r"(vec4), "r"(shift));
	return ret;
}


static __forceinline__ __device__ uint32_t rotateR(uint32_t vec4, uint32_t shift)
{
	uint32_t ret;
	asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(ret) : "r"(vec4), "r"(vec4), "r"(shift));
	return ret;
}



static __device__ __inline__ uint8 __ldg8(const uint8_t *ptr)
{
	uint8 test;
	asm volatile ("ld.global.nc.v4.u32 {%0,%1,%2,%3},[%4];" : "=r"(test.s0), "=r"(test.s1), "=r"(test.s2), "=r"(test.s3) : __LDG_PTR(ptr));
	asm volatile ("ld.global.nc.v4.u32 {%0,%1,%2,%3},[%4+16];" : "=r"(test.s4), "=r"(test.s5), "=r"(test.s6), "=r"(test.s7) : __LDG_PTR(ptr));
	return (test);
}


static __device__ __inline__ uint32_t __ldgtoint(const uint8_t *ptr)
{
	uint32_t test;
	asm volatile ("ld.global.nc.u32 {%0},[%1];" : "=r"(test) : __LDG_PTR(ptr));
	return (test);
}

static __device__ __inline__ uint32_t __ldgtoint64(const uint8_t *ptr)
{
	uint64_t test;
	asm volatile ("ld.global.nc.u64 {%0},[%1];" : "=l"(test) : __LDG_PTR(ptr));
	return (test);
}


static __device__ __inline__ uint32_t __ldgtoint_unaligned(const uint8_t *ptr)
{
	uint32_t test;
	asm volatile ("{\n\t"
		".reg .u8 a,b,c,d; \n\t"
	"ld.global.nc.u8 a,[%1]; \n\t"
	"ld.global.nc.u8 b,[%1+1]; \n\t"
	"ld.global.nc.u8 c,[%1+2]; \n\t"
	"ld.global.nc.u8 d,[%1+3]; \n\t"
	"mov.b32 %0,{a,b,c,d}; }\n\t"
		: "=r"(test) : __LDG_PTR(ptr));
	return (test);
}

static __device__ __inline__ uint64_t __ldgtoint64_unaligned(const uint8_t *ptr)
{
	uint64_t test;
	asm volatile ("{\n\t"
		".reg .u8 a,b,c,d,e,f,g,h; \n\t"
		".reg .u32 i,j; \n\t"
		"ld.global.nc.u8 a,[%1]; \n\t"
		"ld.global.nc.u8 b,[%1+1]; \n\t"
		"ld.global.nc.u8 c,[%1+2]; \n\t"
		"ld.global.nc.u8 d,[%1+3]; \n\t"
		"ld.global.nc.u8 e,[%1+4]; \n\t"
		"ld.global.nc.u8 f,[%1+5]; \n\t"
		"ld.global.nc.u8 g,[%1+6]; \n\t"
		"ld.global.nc.u8 h,[%1+7]; \n\t"
		 "mov.b32 i,{a,b,c,d}; \n\t"
         "mov.b32 j,{e,f,g,h}; \n\t"
		 "mov.b64 %0,{i,j}; }\n\t"
		: "=l"(test) : __LDG_PTR(ptr));
	return (test);
}


static __device__ __inline__ uint64_t __ldgtoint64_trunc(const uint8_t *ptr)
{
	uint32_t zero = 0;
	uint64_t test;
	asm volatile ("{\n\t"
		".reg .u8 a,b,c,d; \n\t"
		".reg .u32 i; \n\t"
		"ld.global.nc.u8 a,[%1]; \n\t"
		"ld.global.nc.u8 b,[%1+1]; \n\t"
		"ld.global.nc.u8 c,[%1+2]; \n\t"
		"ld.global.nc.u8 d,[%1+3]; \n\t"
		"mov.b32 i,{a,b,c,d}; \n\t"
		"mov.b64 %0,{i,%1}; }\n\t"
		: "=l"(test) : __LDG_PTR(ptr), "r"(zero));
	return (test);
}



static __device__ __inline__ uint32_t __ldgtoint_unaligned2(const uint8_t *ptr)
{
	uint32_t test;
	asm("{\n\t"
		".reg .u8 e,b,c,d; \n\t"
		"ld.global.nc.u8 e,[%1]; \n\t"
		"ld.global.nc.u8 b,[%1+1]; \n\t"
		"ld.global.nc.u8 c,[%1+2]; \n\t"
		"ld.global.nc.u8 d,[%1+3]; \n\t"
		"mov.b32 %0,{e,b,c,d}; }\n\t"
		: "=r"(test) : __LDG_PTR(ptr));
	return (test);
}

#endif

static __forceinline__ __device__ void shift256R2(uint32_t * ret, const uint8 &vec4, uint32_t shift)
{
	uint32_t truc = 0, truc2 = cuda_swab32(vec4.s7), truc3 = 0;
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift));
	ret[8] = cuda_swab32(truc);
	truc3 = cuda_swab32(vec4.s6);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc2), "r"(truc3), "r"(shift));
	ret[7] = cuda_swab32(truc);
	truc2 = cuda_swab32(vec4.s5);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift));
	ret[6] = cuda_swab32(truc);
	truc3 = cuda_swab32(vec4.s4);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc2), "r"(truc3), "r"(shift));
	ret[5] = cuda_swab32(truc);
	truc2 = cuda_swab32(vec4.s3);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift));
	ret[4] = cuda_swab32(truc);
	truc3 = cuda_swab32(vec4.s2);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc2), "r"(truc3), "r"(shift));
	ret[3] = cuda_swab32(truc);
	truc2 = cuda_swab32(vec4.s1);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift));
	ret[2] = cuda_swab32(truc);
	truc3 = cuda_swab32(vec4.s0);
	asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc2), "r"(truc3), "r"(shift));
	ret[1] = cuda_swab32(truc);
	asm("shr.b32        %0, %1, %2;" : "=r"(truc) : "r"(truc3), "r"(shift));
	ret[0] = cuda_swab32(truc);

}

#define shift256R3(ret,vec4, shift) \
{ \
 \
uint32_t truc=0,truc2=cuda_swab32(vec4.s7),truc3=0; \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[8] = cuda_swab32(truc); \
truc2=cuda_swab32(vec4.s6);truc3=cuda_swab32(vec4.s7); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[7] = cuda_swab32(truc); \
truc2=cuda_swab32(vec4.s5);truc3=cuda_swab32(vec4.s6); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[6] = cuda_swab32(truc); \
truc2 = cuda_swab32(vec4.s4); truc3 = cuda_swab32(vec4.s5); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[5] = cuda_swab32(truc); \
truc2 = cuda_swab32(vec4.s3); truc3 = cuda_swab32(vec4.s4); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[4] = cuda_swab32(truc); \
truc2 = cuda_swab32(vec4.s2); truc3 = cuda_swab32(vec4.s3); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[3] = cuda_swab32(truc); \
truc2 = cuda_swab32(vec4.s1); truc3 = cuda_swab32(vec4.s2); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[2] = cuda_swab32(truc); \
truc2 = cuda_swab32(vec4.s0); truc3 = cuda_swab32(vec4.s1); \
	asm volatile ("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(truc) : "r"(truc3), "r"(truc2), "r"(shift)); \
		ret[1] = cuda_swab32(truc); \
truc3 = cuda_swab32(vec4.s0); \
	asm volatile ("shr.b32        %0, %1, %2;" : "=r"(truc) : "r"(truc3), "r"(shift)); \
		ret[0] = cuda_swab32(truc); \
 \
 \
}


static __device__ __inline__ uint32 __ldg32b(const uint32 *ptr)
{
	uint32 ret;
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4];"     : "=r"(ret.lo.s0), "=r"(ret.lo.s1), "=r"(ret.lo.s2), "=r"(ret.lo.s3) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+16];"  : "=r"(ret.lo.s4), "=r"(ret.lo.s5), "=r"(ret.lo.s6), "=r"(ret.lo.s7) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+32];"  : "=r"(ret.lo.s8), "=r"(ret.lo.s9), "=r"(ret.lo.sa), "=r"(ret.lo.sb) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+48];"  : "=r"(ret.lo.sc), "=r"(ret.lo.sd), "=r"(ret.lo.se), "=r"(ret.lo.sf) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+64];"  : "=r"(ret.hi.s0), "=r"(ret.hi.s1), "=r"(ret.hi.s2), "=r"(ret.hi.s3) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+80];"  : "=r"(ret.hi.s4), "=r"(ret.hi.s5), "=r"(ret.hi.s6), "=r"(ret.hi.s7) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+96];"  : "=r"(ret.hi.s8), "=r"(ret.hi.s9), "=r"(ret.hi.sa), "=r"(ret.hi.sb) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+112];" : "=r"(ret.hi.sc), "=r"(ret.hi.sd), "=r"(ret.hi.se), "=r"(ret.hi.sf) : __LDG_PTR(ptr));
	return ret;
}

static __device__ __inline__ uint16 __ldg16b(const uint16 *ptr)
{
	uint16 ret;
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4];"     : "=r"(ret.s0), "=r"(ret.s1), "=r"(ret.s2), "=r"(ret.s3) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+16];"  : "=r"(ret.s4), "=r"(ret.s5), "=r"(ret.s6), "=r"(ret.s7) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+32];"  : "=r"(ret.s8), "=r"(ret.s9), "=r"(ret.sa), "=r"(ret.sb) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+48];"  : "=r"(ret.sc), "=r"(ret.sd), "=r"(ret.se), "=r"(ret.sf) : __LDG_PTR(ptr));
	return ret;
}


static __device__ __inline__ uintx64 __ldg32(const uint4 *ptr)
{
	uintx64 ret;
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4];"  : "=r"(ret.s0.s0.s0.s0.x), "=r"(ret.s0.s0.s0.s0.y), "=r"(ret.s0.s0.s0.s0.z), "=r"(ret.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+16];"  : "=r"(ret.s0.s0.s0.s1.x), "=r"(ret.s0.s0.s0.s1.y), "=r"(ret.s0.s0.s0.s1.z), "=r"(ret.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+32];"  : "=r"(ret.s0.s0.s1.s0.x), "=r"(ret.s0.s0.s1.s0.y), "=r"(ret.s0.s0.s1.s0.z), "=r"(ret.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+48];"  : "=r"(ret.s0.s0.s1.s1.x), "=r"(ret.s0.s0.s1.s1.y), "=r"(ret.s0.s0.s1.s1.z), "=r"(ret.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+64];"  : "=r"(ret.s0.s1.s0.s0.x), "=r"(ret.s0.s1.s0.s0.y), "=r"(ret.s0.s1.s0.s0.z), "=r"(ret.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+80];"  : "=r"(ret.s0.s1.s0.s1.x), "=r"(ret.s0.s1.s0.s1.y), "=r"(ret.s0.s1.s0.s1.z), "=r"(ret.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+96];"  : "=r"(ret.s0.s1.s1.s0.x), "=r"(ret.s0.s1.s1.s0.y), "=r"(ret.s0.s1.s1.s0.z), "=r"(ret.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+112];"  : "=r"(ret.s0.s1.s1.s1.x), "=r"(ret.s0.s1.s1.s1.y), "=r"(ret.s0.s1.s1.s1.z), "=r"(ret.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+128];"  : "=r"(ret.s1.s0.s0.s0.x), "=r"(ret.s1.s0.s0.s0.y), "=r"(ret.s1.s0.s0.s0.z), "=r"(ret.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+144];"  : "=r"(ret.s1.s0.s0.s1.x), "=r"(ret.s1.s0.s0.s1.y), "=r"(ret.s1.s0.s0.s1.z), "=r"(ret.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+160];"  : "=r"(ret.s1.s0.s1.s0.x), "=r"(ret.s1.s0.s1.s0.y), "=r"(ret.s1.s0.s1.s0.z), "=r"(ret.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+176];"  : "=r"(ret.s1.s0.s1.s1.x), "=r"(ret.s1.s0.s1.s1.y), "=r"(ret.s1.s0.s1.s1.z), "=r"(ret.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+192];"  : "=r"(ret.s1.s1.s0.s0.x), "=r"(ret.s1.s1.s0.s0.y), "=r"(ret.s1.s1.s0.s0.z), "=r"(ret.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+208];"  : "=r"(ret.s1.s1.s0.s1.x), "=r"(ret.s1.s1.s0.s1.y), "=r"(ret.s1.s1.s0.s1.z), "=r"(ret.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+224];"  : "=r"(ret.s1.s1.s1.s0.x), "=r"(ret.s1.s1.s1.s0.y), "=r"(ret.s1.s1.s1.s0.z), "=r"(ret.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+240];"  : "=r"(ret.s1.s1.s1.s1.x), "=r"(ret.s1.s1.s1.s1.y), "=r"(ret.s1.s1.s1.s1.z), "=r"(ret.s1.s1.s1.s1.w) : __LDG_PTR(ptr));
	return ret;
}

static __device__ __inline__ uintx64 __ldg32c(const uintx64 *ptr)
{
	uintx64 ret;
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4];"  : "=r"(ret.s0.s0.s0.s0.x), "=r"(ret.s0.s0.s0.s0.y), "=r"(ret.s0.s0.s0.s0.z), "=r"(ret.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+16];"  : "=r"(ret.s0.s0.s0.s1.x), "=r"(ret.s0.s0.s0.s1.y), "=r"(ret.s0.s0.s0.s1.z), "=r"(ret.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+32];"  : "=r"(ret.s0.s0.s1.s0.x), "=r"(ret.s0.s0.s1.s0.y), "=r"(ret.s0.s0.s1.s0.z), "=r"(ret.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+48];"  : "=r"(ret.s0.s0.s1.s1.x), "=r"(ret.s0.s0.s1.s1.y), "=r"(ret.s0.s0.s1.s1.z), "=r"(ret.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+64];"  : "=r"(ret.s0.s1.s0.s0.x), "=r"(ret.s0.s1.s0.s0.y), "=r"(ret.s0.s1.s0.s0.z), "=r"(ret.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+80];"  : "=r"(ret.s0.s1.s0.s1.x), "=r"(ret.s0.s1.s0.s1.y), "=r"(ret.s0.s1.s0.s1.z), "=r"(ret.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+96];"  : "=r"(ret.s0.s1.s1.s0.x), "=r"(ret.s0.s1.s1.s0.y), "=r"(ret.s0.s1.s1.s0.z), "=r"(ret.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+112];"  : "=r"(ret.s0.s1.s1.s1.x), "=r"(ret.s0.s1.s1.s1.y), "=r"(ret.s0.s1.s1.s1.z), "=r"(ret.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+128];"  : "=r"(ret.s1.s0.s0.s0.x), "=r"(ret.s1.s0.s0.s0.y), "=r"(ret.s1.s0.s0.s0.z), "=r"(ret.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+144];"  : "=r"(ret.s1.s0.s0.s1.x), "=r"(ret.s1.s0.s0.s1.y), "=r"(ret.s1.s0.s0.s1.z), "=r"(ret.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+160];"  : "=r"(ret.s1.s0.s1.s0.x), "=r"(ret.s1.s0.s1.s0.y), "=r"(ret.s1.s0.s1.s0.z), "=r"(ret.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+176];"  : "=r"(ret.s1.s0.s1.s1.x), "=r"(ret.s1.s0.s1.s1.y), "=r"(ret.s1.s0.s1.s1.z), "=r"(ret.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+192];"  : "=r"(ret.s1.s1.s0.s0.x), "=r"(ret.s1.s1.s0.s0.y), "=r"(ret.s1.s1.s0.s0.z), "=r"(ret.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+208];"  : "=r"(ret.s1.s1.s0.s1.x), "=r"(ret.s1.s1.s0.s1.y), "=r"(ret.s1.s1.s0.s1.z), "=r"(ret.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+224];"  : "=r"(ret.s1.s1.s1.s0.x), "=r"(ret.s1.s1.s1.s0.y), "=r"(ret.s1.s1.s1.s0.z), "=r"(ret.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+240];"  : "=r"(ret.s1.s1.s1.s1.x), "=r"(ret.s1.s1.s1.s1.y), "=r"(ret.s1.s1.s1.s1.z), "=r"(ret.s1.s1.s1.s1.w) : __LDG_PTR(ptr));

	return ret;
}

static __device__ __inline__ uintx128 __ldg128(const uintx128 *ptr)
{
	uintx128 ret;
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4];"     : "=r"(ret.s0.s0.s0.s0.s0.x), "=r"(ret.s0.s0.s0.s0.s0.y), "=r"(ret.s0.s0.s0.s0.s0.z), "=r"(ret.s0.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+16];"  : "=r"(ret.s0.s0.s0.s0.s1.x), "=r"(ret.s0.s0.s0.s0.s1.y), "=r"(ret.s0.s0.s0.s0.s1.z), "=r"(ret.s0.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+32];"  : "=r"(ret.s0.s0.s0.s1.s0.x), "=r"(ret.s0.s0.s0.s1.s0.y), "=r"(ret.s0.s0.s0.s1.s0.z), "=r"(ret.s0.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+48];"  : "=r"(ret.s0.s0.s0.s1.s1.x), "=r"(ret.s0.s0.s0.s1.s1.y), "=r"(ret.s0.s0.s0.s1.s1.z), "=r"(ret.s0.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+64];"  : "=r"(ret.s0.s0.s1.s0.s0.x), "=r"(ret.s0.s0.s1.s0.s0.y), "=r"(ret.s0.s0.s1.s0.s0.z), "=r"(ret.s0.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+80];"  : "=r"(ret.s0.s0.s1.s0.s1.x), "=r"(ret.s0.s0.s1.s0.s1.y), "=r"(ret.s0.s0.s1.s0.s1.z), "=r"(ret.s0.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+96];"  : "=r"(ret.s0.s0.s1.s1.s0.x), "=r"(ret.s0.s0.s1.s1.s0.y), "=r"(ret.s0.s0.s1.s1.s0.z), "=r"(ret.s0.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+112];" : "=r"(ret.s0.s0.s1.s1.s1.x), "=r"(ret.s0.s0.s1.s1.s1.y), "=r"(ret.s0.s0.s1.s1.s1.z), "=r"(ret.s0.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+128];" : "=r"(ret.s0.s1.s0.s0.s0.x), "=r"(ret.s0.s1.s0.s0.s0.y), "=r"(ret.s0.s1.s0.s0.s0.z), "=r"(ret.s0.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+144];" : "=r"(ret.s0.s1.s0.s0.s1.x), "=r"(ret.s0.s1.s0.s0.s1.y), "=r"(ret.s0.s1.s0.s0.s1.z), "=r"(ret.s0.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+160];" : "=r"(ret.s0.s1.s0.s1.s0.x), "=r"(ret.s0.s1.s0.s1.s0.y), "=r"(ret.s0.s1.s0.s1.s0.z), "=r"(ret.s0.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+176];" : "=r"(ret.s0.s1.s0.s1.s1.x), "=r"(ret.s0.s1.s0.s1.s1.y), "=r"(ret.s0.s1.s0.s1.s1.z), "=r"(ret.s0.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+192];" : "=r"(ret.s0.s1.s1.s0.s0.x), "=r"(ret.s0.s1.s1.s0.s0.y), "=r"(ret.s0.s1.s1.s0.s0.z), "=r"(ret.s0.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+208];" : "=r"(ret.s0.s1.s1.s0.s1.x), "=r"(ret.s0.s1.s1.s0.s1.y), "=r"(ret.s0.s1.s1.s0.s1.z), "=r"(ret.s0.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+224];" : "=r"(ret.s0.s1.s1.s1.s0.x), "=r"(ret.s0.s1.s1.s1.s0.y), "=r"(ret.s0.s1.s1.s1.s0.z), "=r"(ret.s0.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+240];" : "=r"(ret.s0.s1.s1.s1.s1.x), "=r"(ret.s0.s1.s1.s1.s1.y), "=r"(ret.s0.s1.s1.s1.s1.z), "=r"(ret.s0.s1.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+256];" : "=r"(ret.s1.s0.s0.s0.s0.x), "=r"(ret.s1.s0.s0.s0.s0.y), "=r"(ret.s1.s0.s0.s0.s0.z), "=r"(ret.s1.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+272];" : "=r"(ret.s1.s0.s0.s0.s1.x), "=r"(ret.s1.s0.s0.s0.s1.y), "=r"(ret.s1.s0.s0.s0.s1.z), "=r"(ret.s1.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+288];" : "=r"(ret.s1.s0.s0.s1.s0.x), "=r"(ret.s1.s0.s0.s1.s0.y), "=r"(ret.s1.s0.s0.s1.s0.z), "=r"(ret.s1.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+304];" : "=r"(ret.s1.s0.s0.s1.s1.x), "=r"(ret.s1.s0.s0.s1.s1.y), "=r"(ret.s1.s0.s0.s1.s1.z), "=r"(ret.s1.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+320];" : "=r"(ret.s1.s0.s1.s0.s0.x), "=r"(ret.s1.s0.s1.s0.s0.y), "=r"(ret.s1.s0.s1.s0.s0.z), "=r"(ret.s1.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+336];" : "=r"(ret.s1.s0.s1.s0.s1.x), "=r"(ret.s1.s0.s1.s0.s1.y), "=r"(ret.s1.s0.s1.s0.s1.z), "=r"(ret.s1.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+352];" : "=r"(ret.s1.s0.s1.s1.s0.x), "=r"(ret.s1.s0.s1.s1.s0.y), "=r"(ret.s1.s0.s1.s1.s0.z), "=r"(ret.s1.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+368];" : "=r"(ret.s1.s0.s1.s1.s1.x), "=r"(ret.s1.s0.s1.s1.s1.y), "=r"(ret.s1.s0.s1.s1.s1.z), "=r"(ret.s1.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+384];" : "=r"(ret.s1.s1.s0.s0.s0.x), "=r"(ret.s1.s1.s0.s0.s0.y), "=r"(ret.s1.s1.s0.s0.s0.z), "=r"(ret.s1.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+400];" : "=r"(ret.s1.s1.s0.s0.s1.x), "=r"(ret.s1.s1.s0.s0.s1.y), "=r"(ret.s1.s1.s0.s0.s1.z), "=r"(ret.s1.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+416];" : "=r"(ret.s1.s1.s0.s1.s0.x), "=r"(ret.s1.s1.s0.s1.s0.y), "=r"(ret.s1.s1.s0.s1.s0.z), "=r"(ret.s1.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+432];" : "=r"(ret.s1.s1.s0.s1.s1.x), "=r"(ret.s1.s1.s0.s1.s1.y), "=r"(ret.s1.s1.s0.s1.s1.z), "=r"(ret.s1.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+448];" : "=r"(ret.s1.s1.s1.s0.s0.x), "=r"(ret.s1.s1.s1.s0.s0.y), "=r"(ret.s1.s1.s1.s0.s0.z), "=r"(ret.s1.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+464];" : "=r"(ret.s1.s1.s1.s0.s1.x), "=r"(ret.s1.s1.s1.s0.s1.y), "=r"(ret.s1.s1.s1.s0.s1.z), "=r"(ret.s1.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+480];" : "=r"(ret.s1.s1.s1.s1.s0.x), "=r"(ret.s1.s1.s1.s1.s0.y), "=r"(ret.s1.s1.s1.s1.s0.z), "=r"(ret.s1.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+496];" : "=r"(ret.s1.s1.s1.s1.s1.x), "=r"(ret.s1.s1.s1.s1.s1.y), "=r"(ret.s1.s1.s1.s1.s1.z), "=r"(ret.s1.s1.s1.s1.s1.w) : __LDG_PTR(ptr));

	return ret;
}

static __device__ __inline__ uintx256 __ldg256(const uintx256 *ptr)
{
	uintx256 ret;
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4];"     : "=r"(ret.s0.s0.s0.s0.s0.s0.x), "=r"(ret.s0.s0.s0.s0.s0.s0.y), "=r"(ret.s0.s0.s0.s0.s0.s0.z), "=r"(ret.s0.s0.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+16];"  : "=r"(ret.s0.s0.s0.s0.s0.s1.x), "=r"(ret.s0.s0.s0.s0.s0.s1.y), "=r"(ret.s0.s0.s0.s0.s0.s1.z), "=r"(ret.s0.s0.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+32];"  : "=r"(ret.s0.s0.s0.s0.s1.s0.x), "=r"(ret.s0.s0.s0.s0.s1.s0.y), "=r"(ret.s0.s0.s0.s0.s1.s0.z), "=r"(ret.s0.s0.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+48];"  : "=r"(ret.s0.s0.s0.s0.s1.s1.x), "=r"(ret.s0.s0.s0.s0.s1.s1.y), "=r"(ret.s0.s0.s0.s0.s1.s1.z), "=r"(ret.s0.s0.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+64];"  : "=r"(ret.s0.s0.s0.s1.s0.s0.x), "=r"(ret.s0.s0.s0.s1.s0.s0.y), "=r"(ret.s0.s0.s0.s1.s0.s0.z), "=r"(ret.s0.s0.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+80];"  : "=r"(ret.s0.s0.s0.s1.s0.s1.x), "=r"(ret.s0.s0.s0.s1.s0.s1.y), "=r"(ret.s0.s0.s0.s1.s0.s1.z), "=r"(ret.s0.s0.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+96];"  : "=r"(ret.s0.s0.s0.s1.s1.s0.x), "=r"(ret.s0.s0.s0.s1.s1.s0.y), "=r"(ret.s0.s0.s0.s1.s1.s0.z), "=r"(ret.s0.s0.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+112];" : "=r"(ret.s0.s0.s0.s1.s1.s1.x), "=r"(ret.s0.s0.s0.s1.s1.s1.y), "=r"(ret.s0.s0.s0.s1.s1.s1.z), "=r"(ret.s0.s0.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+128];" : "=r"(ret.s0.s0.s1.s0.s0.s0.x), "=r"(ret.s0.s0.s1.s0.s0.s0.y), "=r"(ret.s0.s0.s1.s0.s0.s0.z), "=r"(ret.s0.s0.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+144];" : "=r"(ret.s0.s0.s1.s0.s0.s1.x), "=r"(ret.s0.s0.s1.s0.s0.s1.y), "=r"(ret.s0.s0.s1.s0.s0.s1.z), "=r"(ret.s0.s0.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+160];" : "=r"(ret.s0.s0.s1.s0.s1.s0.x), "=r"(ret.s0.s0.s1.s0.s1.s0.y), "=r"(ret.s0.s0.s1.s0.s1.s0.z), "=r"(ret.s0.s0.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+176];" : "=r"(ret.s0.s0.s1.s0.s1.s1.x), "=r"(ret.s0.s0.s1.s0.s1.s1.y), "=r"(ret.s0.s0.s1.s0.s1.s1.z), "=r"(ret.s0.s0.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+192];" : "=r"(ret.s0.s0.s1.s1.s0.s0.x), "=r"(ret.s0.s0.s1.s1.s0.s0.y), "=r"(ret.s0.s0.s1.s1.s0.s0.z), "=r"(ret.s0.s0.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+208];" : "=r"(ret.s0.s0.s1.s1.s0.s1.x), "=r"(ret.s0.s0.s1.s1.s0.s1.y), "=r"(ret.s0.s0.s1.s1.s0.s1.z), "=r"(ret.s0.s0.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+224];" : "=r"(ret.s0.s0.s1.s1.s1.s0.x), "=r"(ret.s0.s0.s1.s1.s1.s0.y), "=r"(ret.s0.s0.s1.s1.s1.s0.z), "=r"(ret.s0.s0.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+240];" : "=r"(ret.s0.s0.s1.s1.s1.s1.x), "=r"(ret.s0.s0.s1.s1.s1.s1.y), "=r"(ret.s0.s0.s1.s1.s1.s1.z), "=r"(ret.s0.s0.s1.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+256];" : "=r"(ret.s0.s1.s0.s0.s0.s0.x), "=r"(ret.s0.s1.s0.s0.s0.s0.y), "=r"(ret.s0.s1.s0.s0.s0.s0.z), "=r"(ret.s0.s1.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+272];" : "=r"(ret.s0.s1.s0.s0.s0.s1.x), "=r"(ret.s0.s1.s0.s0.s0.s1.y), "=r"(ret.s0.s1.s0.s0.s0.s1.z), "=r"(ret.s0.s1.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+288];" : "=r"(ret.s0.s1.s0.s0.s1.s0.x), "=r"(ret.s0.s1.s0.s0.s1.s0.y), "=r"(ret.s0.s1.s0.s0.s1.s0.z), "=r"(ret.s0.s1.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+304];" : "=r"(ret.s0.s1.s0.s0.s1.s1.x), "=r"(ret.s0.s1.s0.s0.s1.s1.y), "=r"(ret.s0.s1.s0.s0.s1.s1.z), "=r"(ret.s0.s1.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+320];" : "=r"(ret.s0.s1.s0.s1.s0.s0.x), "=r"(ret.s0.s1.s0.s1.s0.s0.y), "=r"(ret.s0.s1.s0.s1.s0.s0.z), "=r"(ret.s0.s1.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+336];" : "=r"(ret.s0.s1.s0.s1.s0.s1.x), "=r"(ret.s0.s1.s0.s1.s0.s1.y), "=r"(ret.s0.s1.s0.s1.s0.s1.z), "=r"(ret.s0.s1.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+352];" : "=r"(ret.s0.s1.s0.s1.s1.s0.x), "=r"(ret.s0.s1.s0.s1.s1.s0.y), "=r"(ret.s0.s1.s0.s1.s1.s0.z), "=r"(ret.s0.s1.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+368];" : "=r"(ret.s0.s1.s0.s1.s1.s1.x), "=r"(ret.s0.s1.s0.s1.s1.s1.y), "=r"(ret.s0.s1.s0.s1.s1.s1.z), "=r"(ret.s0.s1.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+384];" : "=r"(ret.s0.s1.s1.s0.s0.s0.x), "=r"(ret.s0.s1.s1.s0.s0.s0.y), "=r"(ret.s0.s1.s1.s0.s0.s0.z), "=r"(ret.s0.s1.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+400];" : "=r"(ret.s0.s1.s1.s0.s0.s1.x), "=r"(ret.s0.s1.s1.s0.s0.s1.y), "=r"(ret.s0.s1.s1.s0.s0.s1.z), "=r"(ret.s0.s1.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+416];" : "=r"(ret.s0.s1.s1.s0.s1.s0.x), "=r"(ret.s0.s1.s1.s0.s1.s0.y), "=r"(ret.s0.s1.s1.s0.s1.s0.z), "=r"(ret.s0.s1.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+432];" : "=r"(ret.s0.s1.s1.s0.s1.s1.x), "=r"(ret.s0.s1.s1.s0.s1.s1.y), "=r"(ret.s0.s1.s1.s0.s1.s1.z), "=r"(ret.s0.s1.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+448];" : "=r"(ret.s0.s1.s1.s1.s0.s0.x), "=r"(ret.s0.s1.s1.s1.s0.s0.y), "=r"(ret.s0.s1.s1.s1.s0.s0.z), "=r"(ret.s0.s1.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+464];" : "=r"(ret.s0.s1.s1.s1.s0.s1.x), "=r"(ret.s0.s1.s1.s1.s0.s1.y), "=r"(ret.s0.s1.s1.s1.s0.s1.z), "=r"(ret.s0.s1.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+480];" : "=r"(ret.s0.s1.s1.s1.s1.s0.x), "=r"(ret.s0.s1.s1.s1.s1.s0.y), "=r"(ret.s0.s1.s1.s1.s1.s0.z), "=r"(ret.s0.s1.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+496];" : "=r"(ret.s0.s1.s1.s1.s1.s1.x), "=r"(ret.s0.s1.s1.s1.s1.s1.y), "=r"(ret.s0.s1.s1.s1.s1.s1.z), "=r"(ret.s0.s1.s1.s1.s1.s1.w) : __LDG_PTR(ptr));

	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+512];" : "=r"(ret.s1.s0.s0.s0.s0.s0.x), "=r"(ret.s1.s0.s0.s0.s0.s0.y), "=r"(ret.s1.s0.s0.s0.s0.s0.z), "=r"(ret.s1.s0.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+528];" : "=r"(ret.s1.s0.s0.s0.s0.s1.x), "=r"(ret.s1.s0.s0.s0.s0.s1.y), "=r"(ret.s1.s0.s0.s0.s0.s1.z), "=r"(ret.s1.s0.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+544];" : "=r"(ret.s1.s0.s0.s0.s1.s0.x), "=r"(ret.s1.s0.s0.s0.s1.s0.y), "=r"(ret.s1.s0.s0.s0.s1.s0.z), "=r"(ret.s1.s0.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+560];" : "=r"(ret.s1.s0.s0.s0.s1.s1.x), "=r"(ret.s1.s0.s0.s0.s1.s1.y), "=r"(ret.s1.s0.s0.s0.s1.s1.z), "=r"(ret.s1.s0.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+576];" : "=r"(ret.s1.s0.s0.s1.s0.s0.x), "=r"(ret.s1.s0.s0.s1.s0.s0.y), "=r"(ret.s1.s0.s0.s1.s0.s0.z), "=r"(ret.s1.s0.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+592];" : "=r"(ret.s1.s0.s0.s1.s0.s1.x), "=r"(ret.s1.s0.s0.s1.s0.s1.y), "=r"(ret.s1.s0.s0.s1.s0.s1.z), "=r"(ret.s1.s0.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+608];" : "=r"(ret.s1.s0.s0.s1.s1.s0.x), "=r"(ret.s1.s0.s0.s1.s1.s0.y), "=r"(ret.s1.s0.s0.s1.s1.s0.z), "=r"(ret.s1.s0.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+624];" : "=r"(ret.s1.s0.s0.s1.s1.s1.x), "=r"(ret.s1.s0.s0.s1.s1.s1.y), "=r"(ret.s1.s0.s0.s1.s1.s1.z), "=r"(ret.s1.s0.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+640];" : "=r"(ret.s1.s0.s1.s0.s0.s0.x), "=r"(ret.s1.s0.s1.s0.s0.s0.y), "=r"(ret.s1.s0.s1.s0.s0.s0.z), "=r"(ret.s1.s0.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+656];" : "=r"(ret.s1.s0.s1.s0.s0.s1.x), "=r"(ret.s1.s0.s1.s0.s0.s1.y), "=r"(ret.s1.s0.s1.s0.s0.s1.z), "=r"(ret.s1.s0.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+672];" : "=r"(ret.s1.s0.s1.s0.s1.s0.x), "=r"(ret.s1.s0.s1.s0.s1.s0.y), "=r"(ret.s1.s0.s1.s0.s1.s0.z), "=r"(ret.s1.s0.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+688];" : "=r"(ret.s1.s0.s1.s0.s1.s1.x), "=r"(ret.s1.s0.s1.s0.s1.s1.y), "=r"(ret.s1.s0.s1.s0.s1.s1.z), "=r"(ret.s1.s0.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+704];" : "=r"(ret.s1.s0.s1.s1.s0.s0.x), "=r"(ret.s1.s0.s1.s1.s0.s0.y), "=r"(ret.s1.s0.s1.s1.s0.s0.z), "=r"(ret.s1.s0.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+720];" : "=r"(ret.s1.s0.s1.s1.s0.s1.x), "=r"(ret.s1.s0.s1.s1.s0.s1.y), "=r"(ret.s1.s0.s1.s1.s0.s1.z), "=r"(ret.s1.s0.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+736];" : "=r"(ret.s1.s0.s1.s1.s1.s0.x), "=r"(ret.s1.s0.s1.s1.s1.s0.y), "=r"(ret.s1.s0.s1.s1.s1.s0.z), "=r"(ret.s1.s0.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+752];" : "=r"(ret.s1.s0.s1.s1.s1.s1.x), "=r"(ret.s1.s0.s1.s1.s1.s1.y), "=r"(ret.s1.s0.s1.s1.s1.s1.z), "=r"(ret.s1.s0.s1.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+768];" : "=r"(ret.s1.s1.s0.s0.s0.s0.x), "=r"(ret.s1.s1.s0.s0.s0.s0.y), "=r"(ret.s1.s1.s0.s0.s0.s0.z), "=r"(ret.s1.s1.s0.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+784];" : "=r"(ret.s1.s1.s0.s0.s0.s1.x), "=r"(ret.s1.s1.s0.s0.s0.s1.y), "=r"(ret.s1.s1.s0.s0.s0.s1.z), "=r"(ret.s1.s1.s0.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+800];" : "=r"(ret.s1.s1.s0.s0.s1.s0.x), "=r"(ret.s1.s1.s0.s0.s1.s0.y), "=r"(ret.s1.s1.s0.s0.s1.s0.z), "=r"(ret.s1.s1.s0.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+816];" : "=r"(ret.s1.s1.s0.s0.s1.s1.x), "=r"(ret.s1.s1.s0.s0.s1.s1.y), "=r"(ret.s1.s1.s0.s0.s1.s1.z), "=r"(ret.s1.s1.s0.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+832];" : "=r"(ret.s1.s1.s0.s1.s0.s0.x), "=r"(ret.s1.s1.s0.s1.s0.s0.y), "=r"(ret.s1.s1.s0.s1.s0.s0.z), "=r"(ret.s1.s1.s0.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+848];" : "=r"(ret.s1.s1.s0.s1.s0.s1.x), "=r"(ret.s1.s1.s0.s1.s0.s1.y), "=r"(ret.s1.s1.s0.s1.s0.s1.z), "=r"(ret.s1.s1.s0.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+864];" : "=r"(ret.s1.s1.s0.s1.s1.s0.x), "=r"(ret.s1.s1.s0.s1.s1.s0.y), "=r"(ret.s1.s1.s0.s1.s1.s0.z), "=r"(ret.s1.s1.s0.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+880];" : "=r"(ret.s1.s1.s0.s1.s1.s1.x), "=r"(ret.s1.s1.s0.s1.s1.s1.y), "=r"(ret.s1.s1.s0.s1.s1.s1.z), "=r"(ret.s1.s1.s0.s1.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+896];" : "=r"(ret.s1.s1.s1.s0.s0.s0.x), "=r"(ret.s1.s1.s1.s0.s0.s0.y), "=r"(ret.s1.s1.s1.s0.s0.s0.z), "=r"(ret.s1.s1.s1.s0.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+912];" : "=r"(ret.s1.s1.s1.s0.s0.s1.x), "=r"(ret.s1.s1.s1.s0.s0.s1.y), "=r"(ret.s1.s1.s1.s0.s0.s1.z), "=r"(ret.s1.s1.s1.s0.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+928];" : "=r"(ret.s1.s1.s1.s0.s1.s0.x), "=r"(ret.s1.s1.s1.s0.s1.s0.y), "=r"(ret.s1.s1.s1.s0.s1.s0.z), "=r"(ret.s1.s1.s1.s0.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+944];" : "=r"(ret.s1.s1.s1.s0.s1.s1.x), "=r"(ret.s1.s1.s1.s0.s1.s1.y), "=r"(ret.s1.s1.s1.s0.s1.s1.z), "=r"(ret.s1.s1.s1.s0.s1.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+960];" : "=r"(ret.s1.s1.s1.s1.s0.s0.x), "=r"(ret.s1.s1.s1.s1.s0.s0.y), "=r"(ret.s1.s1.s1.s1.s0.s0.z), "=r"(ret.s1.s1.s1.s1.s0.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+976];" : "=r"(ret.s1.s1.s1.s1.s0.s1.x), "=r"(ret.s1.s1.s1.s1.s0.s1.y), "=r"(ret.s1.s1.s1.s1.s0.s1.z), "=r"(ret.s1.s1.s1.s1.s0.s1.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+992];" : "=r"(ret.s1.s1.s1.s1.s1.s0.x), "=r"(ret.s1.s1.s1.s1.s1.s0.y), "=r"(ret.s1.s1.s1.s1.s1.s0.z), "=r"(ret.s1.s1.s1.s1.s1.s0.w) : __LDG_PTR(ptr));
	asm("ld.global.nc.v4.u32 {%0,%1,%2,%3}, [%4+1008];" : "=r"(ret.s1.s1.s1.s1.s1.s1.x), "=r"(ret.s1.s1.s1.s1.s1.s1.y), "=r"(ret.s1.s1.s1.s1.s1.s1.z), "=r"(ret.s1.s1.s1.s1.s1.s1.w) : __LDG_PTR(ptr));

	return ret;
}

static __device__ __inline__ ulonglong2 __ldg2(const ulonglong2 *ptr)
{
	ulonglong2 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"  : "=l"(ret.x), "=l"(ret.y) : __LDG_PTR(ptr));
return ret;
}

static __device__ __inline__ ulonglong4 __ldg4(const ulonglong4 *ptr)
{
	ulonglong4 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"  : "=l"(ret.x), "=l"(ret.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.z), "=l"(ret.w) : __LDG_PTR(ptr));
	return ret;
}


static __device__ __inline__ ulonglong2to8 __ldg2to8(const ulonglong2to8 *ptr)
{
	ulonglong2to8 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"     : "=l"(ret.l0.x), "=l"(ret.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.l1.x), "=l"(ret.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+32];"  : "=l"(ret.l2.x), "=l"(ret.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+48];"  : "=l"(ret.l3.x), "=l"(ret.l3.y) : __LDG_PTR(ptr));
	return ret;
}
static __device__ __inline__ ulonglong8to16 __ldg8to16(const ulonglong8to16 *ptr)
{
	ulonglong8to16 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"     : "=l"(ret.lo.l0.x), "=l"(ret.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.lo.l1.x), "=l"(ret.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+32];"  : "=l"(ret.lo.l2.x), "=l"(ret.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+48];"  : "=l"(ret.lo.l3.x), "=l"(ret.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+64];"  : "=l"(ret.hi.l0.x), "=l"(ret.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+80];"  : "=l"(ret.hi.l1.x), "=l"(ret.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+96];"  : "=l"(ret.hi.l2.x), "=l"(ret.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+112];" : "=l"(ret.hi.l3.x), "=l"(ret.hi.l3.y) : __LDG_PTR(ptr));
	return ret;
}

static __device__ __inline__ ulonglonglong __ldgxtralong(const ulonglonglong *ptr)
{
	ulonglonglong ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"     : "=l"(ret.s0.lo.l0.x), "=l"(ret.s0.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.s0.lo.l1.x), "=l"(ret.s0.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+32];"  : "=l"(ret.s0.lo.l2.x), "=l"(ret.s0.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+48];"  : "=l"(ret.s0.lo.l3.x), "=l"(ret.s0.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+64];"  : "=l"(ret.s0.hi.l0.x), "=l"(ret.s0.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+80];"  : "=l"(ret.s0.hi.l1.x), "=l"(ret.s0.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+96];"  : "=l"(ret.s0.hi.l2.x), "=l"(ret.s0.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+112];" : "=l"(ret.s0.hi.l3.x), "=l"(ret.s0.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+128];"  : "=l"(ret.s1.lo.l0.x), "=l"(ret.s1.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+144];"  : "=l"(ret.s1.lo.l1.x), "=l"(ret.s1.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+160];"  : "=l"(ret.s1.lo.l2.x), "=l"(ret.s1.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+176];"  : "=l"(ret.s1.lo.l3.x), "=l"(ret.s1.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+192];"  : "=l"(ret.s1.hi.l0.x), "=l"(ret.s1.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+208];"  : "=l"(ret.s1.hi.l1.x), "=l"(ret.s1.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+224];"  : "=l"(ret.s1.hi.l2.x), "=l"(ret.s1.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+240];"  : "=l"(ret.s1.hi.l3.x), "=l"(ret.s1.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+256];"  : "=l"(ret.s2.lo.l0.x), "=l"(ret.s2.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+272];"  : "=l"(ret.s2.lo.l1.x), "=l"(ret.s2.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+288];"  : "=l"(ret.s2.lo.l2.x), "=l"(ret.s2.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+304];"  : "=l"(ret.s2.lo.l3.x), "=l"(ret.s2.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+320];"  : "=l"(ret.s2.hi.l0.x), "=l"(ret.s2.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+336];"  : "=l"(ret.s2.hi.l1.x), "=l"(ret.s2.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+352];"  : "=l"(ret.s2.hi.l2.x), "=l"(ret.s2.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+368];"  : "=l"(ret.s2.hi.l3.x), "=l"(ret.s2.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+384];"     : "=l"(ret.s3.lo.l0.x), "=l"(ret.s3.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+400];"  : "=l"(ret.s3.lo.l1.x), "=l"(ret.s3.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+416];"  : "=l"(ret.s3.lo.l2.x), "=l"(ret.s3.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+432];"  : "=l"(ret.s3.lo.l3.x), "=l"(ret.s3.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+448];"  : "=l"(ret.s3.hi.l0.x), "=l"(ret.s3.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+464];"  : "=l"(ret.s3.hi.l1.x), "=l"(ret.s3.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+480];"  : "=l"(ret.s3.hi.l2.x), "=l"(ret.s3.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+496];" : "=l"(ret.s3.hi.l3.x), "=l"(ret.s3.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+512];"     : "=l"(ret.s4.lo.l0.x), "=l"(ret.s4.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+528];"  : "=l"(ret.s4.lo.l1.x), "=l"(ret.s4.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+544];"  : "=l"(ret.s4.lo.l2.x), "=l"(ret.s4.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+560];"  : "=l"(ret.s4.lo.l3.x), "=l"(ret.s4.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+576];"  : "=l"(ret.s4.hi.l0.x), "=l"(ret.s4.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+592];"  : "=l"(ret.s4.hi.l1.x), "=l"(ret.s4.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+608];"  : "=l"(ret.s4.hi.l2.x), "=l"(ret.s4.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+624];" : "=l"(ret.s4.hi.l3.x), "=l"(ret.s4.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+640];"     : "=l"(ret.s5.lo.l0.x), "=l"(ret.s5.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+656];"  : "=l"(ret.s5.lo.l1.x), "=l"(ret.s5.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+672];"  : "=l"(ret.s5.lo.l2.x), "=l"(ret.s5.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+688];"  : "=l"(ret.s5.lo.l3.x), "=l"(ret.s5.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+704];"  : "=l"(ret.s5.hi.l0.x), "=l"(ret.s5.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+720];"  : "=l"(ret.s5.hi.l1.x), "=l"(ret.s5.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+736];"  : "=l"(ret.s5.hi.l2.x), "=l"(ret.s5.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+752];" : "=l"(ret.s5.hi.l3.x), "=l"(ret.s5.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+768];"     : "=l"(ret.s6.lo.l0.x), "=l"(ret.s6.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+784];"  : "=l"(ret.s6.lo.l1.x), "=l"(ret.s6.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+800];"  : "=l"(ret.s6.lo.l2.x), "=l"(ret.s6.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+816];"  : "=l"(ret.s6.lo.l3.x), "=l"(ret.s6.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+832];"  : "=l"(ret.s6.hi.l0.x), "=l"(ret.s6.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+848];"  : "=l"(ret.s6.hi.l1.x), "=l"(ret.s6.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+864];"  : "=l"(ret.s6.hi.l2.x), "=l"(ret.s6.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+880];" : "=l"(ret.s6.hi.l3.x), "=l"(ret.s6.hi.l3.y) : __LDG_PTR(ptr));

	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+896];"     : "=l"(ret.s7.lo.l0.x), "=l"(ret.s7.lo.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+912];"  : "=l"(ret.s7.lo.l1.x), "=l"(ret.s7.lo.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+928];"  : "=l"(ret.s7.lo.l2.x), "=l"(ret.s7.lo.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+944];"  : "=l"(ret.s7.lo.l3.x), "=l"(ret.s7.lo.l3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+960];"  : "=l"(ret.s7.hi.l0.x), "=l"(ret.s7.hi.l0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+976];"  : "=l"(ret.s7.hi.l1.x), "=l"(ret.s7.hi.l1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+992];"  : "=l"(ret.s7.hi.l2.x), "=l"(ret.s7.hi.l2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+1008];" : "=l"(ret.s7.hi.l3.x), "=l"(ret.s7.hi.l3.y) : __LDG_PTR(ptr));



	return ret;
}


static __device__ __inline__ ulonglong16 __ldg64(const ulonglong2 *ptr)
{
	ulonglong16 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"     : "=l"(ret.s0.x), "=l"(ret.s0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.s1.x), "=l"(ret.s1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+32];"  : "=l"(ret.s2.x), "=l"(ret.s2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+48];"  : "=l"(ret.s3.x), "=l"(ret.s3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+64];"  : "=l"(ret.s4.x), "=l"(ret.s4.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+80];"  : "=l"(ret.s5.x), "=l"(ret.s5.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+96];"  : "=l"(ret.s6.x), "=l"(ret.s6.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+112];"  : "=l"(ret.s7.x), "=l"(ret.s7.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+128];"  : "=l"(ret.s8.x), "=l"(ret.s8.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+144];"  : "=l"(ret.s9.x), "=l"(ret.s9.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+160];"  : "=l"(ret.sa.x), "=l"(ret.sa.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+176];"  : "=l"(ret.sb.x), "=l"(ret.sb.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+192];"  : "=l"(ret.sc.x), "=l"(ret.sc.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+208];"  : "=l"(ret.sd.x), "=l"(ret.sd.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+224];"  : "=l"(ret.se.x), "=l"(ret.se.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+240];"  : "=l"(ret.sf.x), "=l"(ret.sf.y) : __LDG_PTR(ptr));
	return ret;
}


static __device__ __inline__ ulonglong16 __ldg64b(const ulonglong16 *ptr)
{
	ulonglong16 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"     : "=l"(ret.s0.x), "=l"(ret.s0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.s1.x), "=l"(ret.s1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+32];"  : "=l"(ret.s2.x), "=l"(ret.s2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+48];"  : "=l"(ret.s3.x), "=l"(ret.s3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+64];"  : "=l"(ret.s4.x), "=l"(ret.s4.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+80];"  : "=l"(ret.s5.x), "=l"(ret.s5.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+96];"  : "=l"(ret.s6.x), "=l"(ret.s6.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+112];" : "=l"(ret.s7.x), "=l"(ret.s7.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+128];" : "=l"(ret.s8.x), "=l"(ret.s8.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+144];" : "=l"(ret.s9.x), "=l"(ret.s9.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+160];" : "=l"(ret.sa.x), "=l"(ret.sa.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+176];" : "=l"(ret.sb.x), "=l"(ret.sb.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+192];" : "=l"(ret.sc.x), "=l"(ret.sc.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+208];" : "=l"(ret.sd.x), "=l"(ret.sd.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+224];" : "=l"(ret.se.x), "=l"(ret.se.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+240];" : "=l"(ret.sf.x), "=l"(ret.sf.y) : __LDG_PTR(ptr));
	return ret;
}



static __device__ __inline__ ulonglong16 __ldg64b(const uint32 *ptr)
{
	ulonglong16 ret;
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2];"     : "=l"(ret.s0.x), "=l"(ret.s0.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+16];"  : "=l"(ret.s1.x), "=l"(ret.s1.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+32];"  : "=l"(ret.s2.x), "=l"(ret.s2.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+48];"  : "=l"(ret.s3.x), "=l"(ret.s3.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+64];"  : "=l"(ret.s4.x), "=l"(ret.s4.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+80];"  : "=l"(ret.s5.x), "=l"(ret.s5.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+96];"  : "=l"(ret.s6.x), "=l"(ret.s6.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+112];" : "=l"(ret.s7.x), "=l"(ret.s7.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+128];" : "=l"(ret.s8.x), "=l"(ret.s8.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+144];" : "=l"(ret.s9.x), "=l"(ret.s9.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+160];" : "=l"(ret.sa.x), "=l"(ret.sa.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+176];" : "=l"(ret.sb.x), "=l"(ret.sb.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+192];" : "=l"(ret.sc.x), "=l"(ret.sc.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+208];" : "=l"(ret.sd.x), "=l"(ret.sd.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+224];" : "=l"(ret.se.x), "=l"(ret.se.y) : __LDG_PTR(ptr));
	asm("ld.global.nc.v2.u64 {%0,%1}, [%2+240];" : "=l"(ret.sf.x), "=l"(ret.sf.y) : __LDG_PTR(ptr));
	return ret;
}



static __forceinline__ __device__ uint8 swapvec(const uint8 &buf)
{
	uint8 vec;
	vec.s0 = cuda_swab32(buf.s0);
	vec.s1 = cuda_swab32(buf.s1);
	vec.s2 = cuda_swab32(buf.s2);
	vec.s3 = cuda_swab32(buf.s3);
	vec.s4 = cuda_swab32(buf.s4);
	vec.s5 = cuda_swab32(buf.s5);
	vec.s6 = cuda_swab32(buf.s6);
	vec.s7 = cuda_swab32(buf.s7);
	return vec;
}


static __forceinline__ __device__ uint8 swapvec(const uint8 *buf)
{
	uint8 vec;
	vec.s0 = cuda_swab32(buf[0].s0);
	vec.s1 = cuda_swab32(buf[0].s1);
	vec.s2 = cuda_swab32(buf[0].s2);
	vec.s3 = cuda_swab32(buf[0].s3);
	vec.s4 = cuda_swab32(buf[0].s4);
	vec.s5 = cuda_swab32(buf[0].s5);
	vec.s6 = cuda_swab32(buf[0].s6);
	vec.s7 = cuda_swab32(buf[0].s7);
	return vec;
}

static __forceinline__ __device__ uint16 swapvec(const uint16 *buf)
{
	uint16 vec;
	vec.s0 = cuda_swab32(buf[0].s0);
	vec.s1 = cuda_swab32(buf[0].s1);
	vec.s2 = cuda_swab32(buf[0].s2);
	vec.s3 = cuda_swab32(buf[0].s3);
	vec.s4 = cuda_swab32(buf[0].s4);
	vec.s5 = cuda_swab32(buf[0].s5);
	vec.s6 = cuda_swab32(buf[0].s6);
	vec.s7 = cuda_swab32(buf[0].s7);
	vec.s8 = cuda_swab32(buf[0].s8);
	vec.s9 = cuda_swab32(buf[0].s9);
	vec.sa = cuda_swab32(buf[0].sa);
	vec.sb = cuda_swab32(buf[0].sb);
	vec.sc = cuda_swab32(buf[0].sc);
	vec.sd = cuda_swab32(buf[0].sd);
	vec.se = cuda_swab32(buf[0].se);
	vec.sf = cuda_swab32(buf[0].sf);
	return vec;
}

static __forceinline__ __device__ uint16 swapvec(const uint16 &buf)
{
	uint16 vec;
	vec.s0 = cuda_swab32(buf.s0);
	vec.s1 = cuda_swab32(buf.s1);
	vec.s2 = cuda_swab32(buf.s2);
	vec.s3 = cuda_swab32(buf.s3);
	vec.s4 = cuda_swab32(buf.s4);
	vec.s5 = cuda_swab32(buf.s5);
	vec.s6 = cuda_swab32(buf.s6);
	vec.s7 = cuda_swab32(buf.s7);
	vec.s8 = cuda_swab32(buf.s8);
	vec.s9 = cuda_swab32(buf.s9);
	vec.sa = cuda_swab32(buf.sa);
	vec.sb = cuda_swab32(buf.sb);
	vec.sc = cuda_swab32(buf.sc);
	vec.sd = cuda_swab32(buf.sd);
	vec.se = cuda_swab32(buf.se);
	vec.sf = cuda_swab32(buf.sf);
	return vec;
}

#endif // #ifndef CUDA_VECTOR_H