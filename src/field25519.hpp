#ifndef AMBER_FIELD25519_HPP
#define AMBER_FIELD25519_HPP

/*
 * Copyright (c) 2017-2019, Pelayo Bernedo.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdint.h>
#include <iosfwd>
#include "soname.hpp"
#include "misc.hpp"

// Operations in the field modulo 2²⁵⁵ - 19.

namespace amber {  inline namespace AMBER_SONAME {

// We represent integers of 255 bits in two ways:

// 1. Using five uint64_t limbs which each limb having 51 bits in the
// normalized form.

// 2. Using ten uint32_t limbs using 25, 26, 25, 26, 25, 26, 25, 26, 25, 26
// bits in the normalized form.

// When using the 32 bit limbs we need to multiply two limbs to obtain a 64
// bit result. We can do this using only standard C++11. When using the 64
// bit limbs we need to multiply two limbs to obtain a 128 bit result. This
// is supported by the underlying 64 bit CPUs but is not directly available
// in standard C++11. However GCC supports 128 bit integers on such
// platforms. If 128 bit integers are not available it is still possible
// to have 64 bit limbs, but the multiplication will be done using 32 bit
// chunks. You can select explicitly the representation by defining
// AMBER_LIMB_BITS to either 32, 64 or 128. If AMBER_LIMB_BITS is 32 then
// there will be 10 limbs of uint32_t. If AMBER_LIMB_BITS is 128 there will
// be five limbs of uint64_t and the multiplication will be done using
// uint128_t for the result. If AMBER_LIMB_BITS is 64 then there will be
// five limbs of uint64_t and the multiplication will be done in chunks of
// 32 bits. If AMBER_LIMB_BITS is not defined then the program will select
// 32 if size_t is less than 64 bits. With size_t at least 64 bits then
// AMBER_LIMB_BITS will be set to 128 if using GCC and to 64 otherwise.


//#define AMBER_LIMB_BITS 32

#ifndef AMBER_LIMB_BITS
	#if SIZE_MAX < 0xFFFFFFFFFFFFFFFF
		#define AMBER_LIMB_BITS 32
	#else
		#if defined(__GNUC__)
			#define AMBER_LIMB_BITS 128
		#else
			#define AMBER_LIMB_BITS 64
		#endif
	#endif
#endif

#if AMBER_LIMB_BITS == 128
	typedef unsigned __int128 uint128_t;
#endif


#if AMBER_LIMB_BITS == 32
enum { fecount = 10 };
#elif AMBER_LIMB_BITS >= 64
enum { fecount = 5 };
#endif

enum { mask25 = (1 << 25) - 1, mask26 = (1 << 26) - 1 };
enum { mask51 = 0x7FFFFFFFFFFFF };

// p = 2²⁵⁵ - 19. The lowest limb of p has the representation p0. All other
// limbs of p have either mask25 or mask26.
static const uint32_t p0      = 0x3FFFFED;

// Four times P.
static const uint32_t four_p0 = 4*p0;
static const uint32_t four_mask25 = 4 * mask25;
static const uint32_t four_mask26 = 4 * mask26;

// Same but using 64 bit limbs.
static const uint64_t p0_64 = 0x7FFFFFFFFFFED;
static const uint64_t four_p0_64 = 4 * p0_64;
static const uint64_t four_mask51 = 4 * mask51;

struct Fe32 {
	uint32_t v[10];
};

struct Fe64 {
	uint64_t v[5];
};



// Load the bytes from b into the limb representation.
EXPORTFN
void load (Fe32 &fe, const uint8_t b[32]);

// Reduce the limb representation to the nominal ranges, mod p and store the
// byte representation in b.
EXPORTFN
void reduce_store (uint8_t b[32], Fe32 &fe);

// Reduce to nominal ranges and mod p.
EXPORTFN
void reduce_full (Fe32 &fe);


// Write the result of reduce_store to the output.
EXPORTFN
std::ostream & operator<< (std::ostream &os, const amber::Fe32 &rhs);


// Show the limb values.
EXPORTFN
void show_raw (const char *label, const Fe32 &fe);

// Addition without reduction. OK if the next op is a multiplication.
inline void add_no_reduce (Fe32 &res, const Fe32 &a, const Fe32 &b);

// Arithmetic with reduction. They can be chained as required.
inline void add (Fe32 &res, const Fe32 &a, const Fe32 &b);
inline void sub (Fe32 &res, const Fe32 &a, const Fe32 &b);
inline void negate (Fe32 &res, const Fe32 &a);
inline void mul (Fe32 &res, const Fe32 &f, const Fe32 &g);
inline void square (Fe32 &res, const Fe32 &f);

// Multiply by a small number. res = bs*a
inline void mul_small (Fe32 &res, const Fe32 &a, uint32_t bs);

// Swap if flag is 1. Flag may be either 1 or 0. No other values are accepted.
inline void cswap (Fe32 &a, Fe32 &b, uint32_t flag);

// Same with 64 bit limbs.
EXPORTFN void load (Fe64 &fe, const uint8_t b[32]);
EXPORTFN void reduce_store (uint8_t b[32], Fe64 &fe);
EXPORTFN void reduce_full (Fe64 &fe);
EXPORTFN std::ostream & operator<< (std::ostream &os, const amber::Fe64 &rhs);
EXPORTFN void show_raw (const char *label, const Fe64 &fe);

inline void add_no_reduce (Fe64 &res, const Fe64 &a, const Fe64 &b);
inline void add (Fe64 &res, const Fe64 &a, const Fe64 &b);
inline void sub (Fe64 &res, const Fe64 &a, const Fe64 &b);
inline void negate (Fe64 &res, const Fe64 &a);
inline void mul (Fe64 &res, const Fe64 &f, const Fe64 &g);
inline void square (Fe64 &res, const Fe64 &f);
inline void mul_small (Fe64&res, const Fe64 &a, uint32_t bs);
inline void cswap (Fe64 &a, Fe64 &b, uint64_t flag);

#if AMBER_LIMB_BITS == 32
typedef Fe32 Fe;
#elif AMBER_LIMB_BITS >= 64
typedef Fe64 Fe;
#endif

struct Edwards {
	Fe x, y, z, t;
	// x/z and y/z are the real coordinates. t/z = (x/z)*(y/z)
};


// Compute 1/z by raising z to p-2 = 2²⁵⁵ - 21. It works for all inputs
// except for zero. When z == 0 then it sets res = 0.
EXPORTFN void invert (Fe &res, const Fe &z);

// Raise z to the 2²⁵² - 3 power. Similar to the above computation. Used for
// combined sqrt and division. From the Ed25519 paper: we need to compute the
// square root of a quotient.
/*
   β = sqrt(u/v) = (u/v)^[(p+3)/8], where p is 2²⁵⁵ - 19.
   β = (u/v)^[(p+3)/8] = u^[(p+3)/8] * v^[p-1-(p+3)/8], because x^(p-1) == 1
   β = u^[(p+3)/8] * v^[(7p-11)/8] = uv³(uv⁷)^[(p-5)/8] = uv³(uv⁷)^(2²⁵² - 3)
*/
EXPORTFN void raise_252_3 (Fe &res, const Fe &z);

// res = z ^ (2²⁵³ - 5)
EXPORTFN void raise_253_5 (Fe &res, const Fe &z);

// Raise to 2²⁵⁴ - 10.
EXPORTFN void raise_254_10 (Fe &res, const Fe &z);


// res = sqrt(1/x). Returns 0 if the root exists. Returns 1 otherwise.
// Constant time.
EXPORTFN int invsqrt (Fe &res, const Fe &x);

// Return 0 if there is a square root. 1 if there isn't one. Constant time.
EXPORTFN int sqrt (Fe &res, const Fe &x);

// If u/v is a square *res = +sqrt(u/v) and return 0. If u/v is not a square
// *res = sqrt(iu/v) and return 1. Constant time.
EXPORTFN int sqrt_ratio_m1 (Fe &res, const Fe &u, const Fe &v);



// Return 1 or 0. Constant time.
EXPORTFN uint8_t not_zero (const uint8_t *b, size_t n);


inline int ct_is_zero (const Fe &u)
{
	Fe v = u;
	uint8_t d[32];
	reduce_store (d, v);
	return is_zero (d, 32);
}


// X25519 requires that bit 254 is always set and bits 0-2 are cleared.
// These routines work with anything. In X25519 bits 0-2 are cleared so that
// the scalar is a multiple of the cofactor and bit 254 is set so that other
// variable time implementations become effectively constant time. The
// masking is not required with this implementation. This implementation
// works with any scalar using all 256 bits.

// Normal X only scalar multiplication. It will return 0 on success. It
// rejects points which are not on the curve and small order points.
EXPORTFN int montgomery_ladder_checked (uint8_t res[32], const uint8_t pointx[32], const uint8_t scalar[32], int startbit=254);
// Same but accepts every input. This is the original version by DJB.
EXPORTFN void montgomery_ladder_unchecked (uint8_t res[32], const uint8_t pointx[32], const uint8_t scalar[32], int startbit=254);


// Normal X only scalar multiplication.
EXPORTFN void montgomery_ladder (Fe &res, const Fe &xp, const uint8_t scalar[32], int startbit=254);
EXPORTFN void montgomery_ladder (Fe &u, Fe &z, const Fe &xp, const uint8_t scalar[32], int startbit=254);


// Montgomery ladder with recovery of Y coordinate. bu and bv are the affine
// coordinates of the point being multiplied. They take only about 1% more
// time than the X only multiplication.

// Result in projective Montgomery coordinates.
EXPORTFN void montgomery_ladder_uv (Fe &resu, Fe &resv, Fe &resz, const Fe &bu,
                                    const Fe &bv, const uint8_t scalar[32], int startbit=254);
// Result in affine Montgomery coordinates.
EXPORTFN void montgomery_ladder_uv (Fe &resu, Fe &resv, const Fe &bu, const Fe &bv,
                                    const uint8_t scalar[32], int startbit=254);
// Result in Edwards coordinates.
EXPORTFN void montgomery_ladder (Edwards &res, const Fe &bu, const Fe &bv,
                                 const uint8_t scalar[32], int startbit=254);

// Edwards to Edwards. Internal conversion to Montgomery affine coordinates
// and then the ladder.
EXPORTFN void montgomery_ladder (Edwards &res, const Edwards &p, const uint8_t scalar[32], int startbit=254);


// Scalar multiplication of base point using the Montgomery ladder. Return
// the result in projective Montgomery, Edwards coordinates or affine
// Montgomery. The first two take equal time and less than the third one.
EXPORTFN void montgomery_base (Fe &u, Fe &v, Fe &z, const uint8_t scalar[32], int startbit=254);
EXPORTFN void montgomery_base (Edwards &e, const uint8_t scalar[32], int startbit=254);
EXPORTFN void montgomery_base (Fe &u, Fe &v, const uint8_t scalar[32], int startbit=254);

// Directly store as the montgomery u coordinate with the sign bit of the
// Edwards x coordinate.
EXPORTFN void montgomery_base (uint8_t mx[32], const uint8_t scalar[32], int startbit=254);

// Full conversion between Montgomery and Edwards.
EXPORTFN void edwards_to_mont (Fe &u, Fe &v, const Edwards &e);
EXPORTFN void mont_to_edwards (Edwards &e, const Fe &u, const Fe &v, const Fe &z);


// Return 1 if v > lim. Return 0 otherwise. Constant time.
EXPORTFN uint32_t gt_than (const uint8_t v[32], const uint8_t lim[32]);

// Elligator as Fe. Note that r is < (p-1)/2. When putting it into bytes the
// upper two bits will be zero and they should be set to random values to
// ensure that r is not distinguishable from random. You pass a point and it
// will compute r if it exists (return value == 0)

// From Edwards.
EXPORTFN int elligator2_p2r (Fe &r, Fe &u, const Edwards &p);
// Direct entry from affine Montgomery coordinates.
EXPORTFN int elligator2_p2r (Fe &r, const Fe &u, const Fe &v);

// Inverse function.
EXPORTFN void elligator2_r2u (Fe &u, const Fe &r);

// Increment the scalar by delta*8. It assumes that the scalar has already
// been masked.
EXPORTFN void increment (uint8_t scalar[32], int delta=1);






// Inline implementations.

inline void add_no_reduce (Fe32 &res, const Fe32 &a, const Fe32 &b)
{
	res.v[0] = a.v[0] + b.v[0];
	res.v[1] = a.v[1] + b.v[1];
	res.v[2] = a.v[2] + b.v[2];
	res.v[3] = a.v[3] + b.v[3];
	res.v[4] = a.v[4] + b.v[4];
	res.v[5] = a.v[5] + b.v[5];
	res.v[6] = a.v[6] + b.v[6];
	res.v[7] = a.v[7] + b.v[7];
	res.v[8] = a.v[8] + b.v[8];
	res.v[9] = a.v[9] + b.v[9];
}

inline void add (Fe32 &res, const Fe32 &a, const Fe32 &b)
{
	uint32_t c;
	c = a.v[0] + b.v[0];    res.v[0] = c & mask26;  c >>= 26;
	c += a.v[1] + b.v[1];   res.v[1] = c & mask25;  c >>= 25;
	c += a.v[2] + b.v[2];   res.v[2] = c & mask26;  c >>= 26;
	c += a.v[3] + b.v[3];   res.v[3] = c & mask25;  c >>= 25;
	c += a.v[4] + b.v[4];   res.v[4] = c & mask26;  c >>= 26;
	c += a.v[5] + b.v[5];   res.v[5] = c & mask25;  c >>= 25;
	c += a.v[6] + b.v[6];   res.v[6] = c & mask26;  c >>= 26;
	c += a.v[7] + b.v[7];   res.v[7] = c & mask25;  c >>= 25;
	c += a.v[8] + b.v[8];   res.v[8] = c & mask26;  c >>= 26;
	c += a.v[9] + b.v[9];   res.v[9] = c & mask25;  c >>= 25;
	res.v[0] += 19 * c;
}


// Perform 4P + a - b. Avoids underflow to negative numbers.
inline void sub (Fe32 &res, const Fe32 &a, const Fe32 &b)
{
	uint32_t c;
	c = four_p0 + a.v[0] - b.v[0];          res.v[0] = c & mask26;  c >>= 26;
	c += four_mask25 + a.v[1] - b.v[1];     res.v[1] = c & mask25;  c >>= 25;
	c += four_mask26 + a.v[2] - b.v[2];     res.v[2] = c & mask26;  c >>= 26;
	c += four_mask25 + a.v[3] - b.v[3];     res.v[3] = c & mask25;  c >>= 25;
	c += four_mask26 + a.v[4] - b.v[4];     res.v[4] = c & mask26;  c >>= 26;
	c += four_mask25 + a.v[5] - b.v[5];     res.v[5] = c & mask25;  c >>= 25;
	c += four_mask26 + a.v[6] - b.v[6];     res.v[6] = c & mask26;  c >>= 26;
	c += four_mask25 + a.v[7] - b.v[7];     res.v[7] = c & mask25;  c >>= 25;
	c += four_mask26 + a.v[8] - b.v[8];     res.v[8] = c & mask26;  c >>= 26;
	c += four_mask25 + a.v[9] - b.v[9];     res.v[9] = c & mask25;  c >>= 25;
	res.v[0] += c * 19;
}


// Perform 4P - a. Avoids underflow to negative numbers.
inline void negate (Fe32 &res, const Fe32 &a)
{
	uint32_t c;
	c = four_p0 - a.v[0];          res.v[0] = c & mask26;  c >>= 26;
	c += four_mask25 - a.v[1];     res.v[1] = c & mask25;  c >>= 25;
	c += four_mask26 - a.v[2];     res.v[2] = c & mask26;  c >>= 26;
	c += four_mask25 - a.v[3];     res.v[3] = c & mask25;  c >>= 25;
	c += four_mask26 - a.v[4];     res.v[4] = c & mask26;  c >>= 26;
	c += four_mask25 - a.v[5];     res.v[5] = c & mask25;  c >>= 25;
	c += four_mask26 - a.v[6];     res.v[6] = c & mask26;  c >>= 26;
	c += four_mask25 - a.v[7];     res.v[7] = c & mask25;  c >>= 25;
	c += four_mask26 - a.v[8];     res.v[8] = c & mask26;  c >>= 26;
	c += four_mask25 - a.v[9];     res.v[9] = c & mask25;  c >>= 25;
	res.v[0] += c * 19;
}

// 64 bit result.
inline uint64_t mul (uint32_t a, uint32_t b)
{
	return uint64_t(a) * uint64_t(b);
}

// Normal multiplication. Produce 64 bit values, which are then reduced.
inline void mul (Fe32 &res, const Fe32 &f, const Fe32 &g)
{
	uint32_t f0 = f.v[0], f1 = f.v[1], f2 = f.v[2], f3 = f.v[3], f4 = f.v[4];
	uint32_t f5 = f.v[5], f6 = f.v[6], f7 = f.v[7], f8 = f.v[8], f9 = f.v[9];
	uint32_t g0 = g.v[0], g1 = g.v[1], g2 = g.v[2], g3 = g.v[3], g4 = g.v[4];
	uint32_t g5 = g.v[5], g6 = g.v[6], g7 = g.v[7], g8 = g.v[8], g9 = g.v[9];

	uint32_t f1_2  =  2 * f1;
	uint32_t f1_38 = 38 * f1;
	uint32_t f2_19 = 19 * f2;
	uint32_t f3_2  =  2 * f3;
	uint32_t f3_38 = 38 * f3;
	uint32_t f4_19 = 19 * f4;
	uint32_t f5_2  =  2 * f5;
	uint32_t f5_19 = 19 * f5;
	uint32_t f5_38 = 38 * f5;
	uint32_t f6_19 = 19 * f6;
	uint32_t f7_19 = 19 * f7;
	uint32_t f7_38 = 38 * f7;
	uint32_t f8_19 = 19 * f8;
	uint32_t f9_19 = 19 * f9;
	uint32_t f9_38 = 38 * f9;

	uint64_t h0 = mul(f0,g0)    + mul(f1_38,g9) + mul(f2_19,g8) + mul(f3_38,g7)
				+ mul(f4_19,g6) + mul(f5_38,g5) + mul(f6_19,g4) + mul(f7_38,g3)
				+ mul(f8_19,g2) + mul(f9_38,g1);

	uint64_t h1 = mul(f0,g1)    + mul(f1,g0)    + mul(f2_19,g9) + mul(f3*19,g8)
				+ mul(f4_19,g7) + mul(f5_19,g6) + mul(f6_19,g5) + mul(f7_19,g4)
				+ mul(f8_19,g3) + mul(f9_19,g2);

	uint64_t h2 = mul(f0,g2)    + mul(f1_2,g1)  + mul(f2,g0)    + mul(f3_38,g9)
				+ mul(f4_19,g8) + mul(f5_38,g7) + mul(f6_19,g6) + mul(f7_38,g5)
				+ mul(f8_19,g4) + mul(f9_38,g3);

	uint64_t h3 = mul(f0, g3)   + mul(f1,g2)    + mul(f2, g1)   + mul(f3,g0)
				+ mul(f4_19,g9) + mul(f5_19,g8) + mul(f6_19,g7) + mul(f7_19,g6)
				+ mul(f8_19,g5) + mul(f9_19,g4);

	uint64_t h4 = mul(f0,g4)    + mul(f1_2,g3)  + mul(f2,g2)    + mul(f3_2,g1)
				+ mul(f4,g0)    + mul(f5_38,g9) + mul(f6_19,g8) + mul(f7_38,g7)
				+ mul(f8_19,g6) + mul(f9_38,g5);

	uint64_t h5 = mul(f0,g5)    + mul(f1,g4)    + mul(f2,g3)    + mul(f3,g2)
				+ mul(f4,g1)    + mul(f5,g0)    + mul(f6_19,g9) + mul(f7_19,g8)
				+ mul(f8_19,g7) + mul(f9_19,g6);

	uint64_t h6 = mul(f0,g6)    + mul(f1_2,g5)  + mul(f2,g4)    + mul(f3_2,g3)
				+ mul(f4,g2)    + mul(f5_2,g1)  + mul(f6,g0)    + mul(f7_38,g9)
				+ mul(f8_19,g8) + mul(f9_38,g7);

	uint64_t h7 = mul(f0,g7)    + mul(f1,g6)    + mul(f2,g5)    + mul(f3,g4)
				+ mul(f4,g3)    + mul(f5,g2)    + mul(f6,g1)    + mul(f7,g0)
				+ mul(f8_19,g9) + mul(f9_19,g8);

	uint64_t h8 = mul(f0,g8)    + mul(f1_2,g7)  + mul(f2,g6)    + mul(f3_2,g5)
				+ mul(f4,g4)    + mul(f5_2,g3)  + mul(f6,g2)    + mul(f7*2,g1)
				+ mul(f8,g0)    + mul(f9_38,g9);

	uint64_t h9 = mul(f0,g9)    + mul(f1,g8)    + mul(f2,g7)    + mul(f3,g6)
				+ mul(f4,g5)    + mul(f5,g4)    + mul(f6,g3)    + mul(f7,g2)
				+ mul(f8,g1)    + mul(f9,g0);


	uint64_t c = h0;    res.v[0] = c & mask26;   c >>= 26;
	c += h1;            res.v[1] = c & mask25;   c >>= 25;
	c += h2;            res.v[2] = c & mask26;   c >>= 26;
	c += h3;            res.v[3] = c & mask25;   c >>= 25;
	c += h4;            res.v[4] = c & mask26;   c >>= 26;
	c += h5;            res.v[5] = c & mask25;   c >>= 25;
	c += h6;            res.v[6] = c & mask26;   c >>= 26;
	c += h7;            res.v[7] = c & mask25;   c >>= 25;
	c += h8;            res.v[8] = c & mask26;   c >>= 26;
	c += h9;            res.v[9] = c & mask25;   c >>= 25;
	c = res.v[0] + c * 19;      res.v[0] = c & mask26;   c >>= 26;
	res.v[1] += c;
}


// Same as before but with fewer multiplications.
inline void square (Fe32 &res, const Fe32 &f)
{
	uint32_t f0 = f.v[0], f1 = f.v[1], f2 = f.v[2], f3 = f.v[3], f4 = f.v[4];
	uint32_t f5 = f.v[5], f6 = f.v[6], f7 = f.v[7], f8 = f.v[8], f9 = f.v[9];

	uint32_t f1_2  =  2 * f1;
	uint32_t f1_38 = 38 * f1;
	uint32_t f2_19 = 19 * f2;
	uint32_t f3_2  =  2 * f3;
	uint32_t f3_38 = 38 * f3;
	uint32_t f4_19 = 19 * f4;
	uint32_t f5_19 = 19 * f5;
	uint32_t f5_38 = 38 * f5;
	uint32_t f6_19 = 19 * f6;
	uint32_t f7_19 = 19 * f7;
	uint32_t f7_38 = 38 * f7;
	uint32_t f8_19 = 19 * f8;
	uint32_t f9_38 = 38 * f9;

	uint64_t h0 = mul(f0,f0)
				+ 2*(mul(f1_38,f9) + mul(f2_19,f8) + mul(f3_38,f7) + mul(f4_19,f6))
				+ mul(f5_38,f5);

	uint64_t h1 = 2 * (mul(f0,f1)  + mul(f2_19,f9) + mul(f3*19,f8)
					   + mul(f4_19,f7) + mul(f5_19,f6));

	uint64_t h2 = 2 * (mul(f0,f2)    + mul(f1,f1)  + mul(f3_38,f9)
					   + mul(f4_19,f8) + mul(f5_38,f7))  + mul(f6_19,f6);

	uint64_t h3 = 2 * (mul(f0,f3)   + mul(f1,f2) + mul(f4_19,f9) + mul(f5_19,f8) + mul(f6_19,f7));

	uint64_t h4 = 2 * (mul(f0,f4) + mul(f1_2,f3) + mul(f5_38,f9) + mul(f6_19,f8))
				+ mul(f2,f2) + mul(f7_38,f7);

	uint64_t h5 = 2 * (mul(f0,f5) + mul(f1,f4) + mul(f2,f3) + mul(f6_19,f9) + mul(f7_19,f8));

	uint64_t h6 = 2 * (mul(f0,f6) + mul(f1_2,f5) + mul(f2,f4) + mul(f7_38,f9))
				+ mul(f3_2,f3) + mul(f8_19,f8);

	uint64_t h7 = 2 * (mul(f0,f7) + mul(f1,f6) + mul(f2,f5) + mul(f3,f4) + mul(f8_19,f9));

	uint64_t h8 = 2 * (mul(f0,f8) + mul(f1_2,f7) + mul(f2,f6) + mul(f3_2,f5))
				+ mul(f4,f4) + mul(f9_38,f9);

	uint64_t h9 = 2 * (mul(f0,f9) + mul(f1,f8) + mul(f2,f7) + mul(f3,f6) + mul(f4,f5));



	uint64_t c = h0;    res.v[0] = c & mask26;   c >>= 26;
	c += h1;            res.v[1] = c & mask25;   c >>= 25;
	c += h2;            res.v[2] = c & mask26;   c >>= 26;
	c += h3;            res.v[3] = c & mask25;   c >>= 25;
	c += h4;            res.v[4] = c & mask26;   c >>= 26;
	c += h5;            res.v[5] = c & mask25;   c >>= 25;
	c += h6;            res.v[6] = c & mask26;   c >>= 26;
	c += h7;            res.v[7] = c & mask25;   c >>= 25;
	c += h8;            res.v[8] = c & mask26;   c >>= 26;
	c += h9;            res.v[9] = c & mask25;   c >>= 25;
	c = res.v[0] + c * 19;      res.v[0] = c & mask26;   c >>= 26;
	res.v[1] += c;
}


// Multiply the number by a small number that fits in 32 bits.
inline void mul_small (Fe32 &res, const Fe32 &a, uint32_t bs)
{
	uint64_t c, b = bs;
	c  = a.v[0] * b;   res.v[0] = c & mask26;   c >>= 26;
	c += a.v[1] * b;   res.v[1] = c & mask25;   c >>= 25;
	c += a.v[2] * b;   res.v[2] = c & mask26;   c >>= 26;
	c += a.v[3] * b;   res.v[3] = c & mask25;   c >>= 25;
	c += a.v[4] * b;   res.v[4] = c & mask26;   c >>= 26;
	c += a.v[5] * b;   res.v[5] = c & mask25;   c >>= 25;
	c += a.v[6] * b;   res.v[6] = c & mask26;   c >>= 26;
	c += a.v[7] * b;   res.v[7] = c & mask25;   c >>= 25;
	c += a.v[8] * b;   res.v[8] = c & mask26;   c >>= 26;
	c += a.v[9] * b;   res.v[9] = c & mask25;   c >>= 25;
	c = res.v[0] + c * 19;      res.v[0] = c & mask26;   c >>= 26;
	res.v[1] += c;
}

inline void cswap (Fe32 &a, Fe32 &b, uint32_t flag)
{
	flag = ~ (flag - 1);
	uint32_t c;
	c = (a.v[0] ^ b.v[0]) & flag;  a.v[0] ^= c;  b.v[0] ^= c;
	c = (a.v[1] ^ b.v[1]) & flag;  a.v[1] ^= c;  b.v[1] ^= c;
	c = (a.v[2] ^ b.v[2]) & flag;  a.v[2] ^= c;  b.v[2] ^= c;
	c = (a.v[3] ^ b.v[3]) & flag;  a.v[3] ^= c;  b.v[3] ^= c;
	c = (a.v[4] ^ b.v[4]) & flag;  a.v[4] ^= c;  b.v[4] ^= c;
	c = (a.v[5] ^ b.v[5]) & flag;  a.v[5] ^= c;  b.v[5] ^= c;
	c = (a.v[6] ^ b.v[6]) & flag;  a.v[6] ^= c;  b.v[6] ^= c;
	c = (a.v[7] ^ b.v[7]) & flag;  a.v[7] ^= c;  b.v[7] ^= c;
	c = (a.v[8] ^ b.v[8]) & flag;  a.v[8] ^= c;  b.v[8] ^= c;
	c = (a.v[9] ^ b.v[9]) & flag;  a.v[9] ^= c;  b.v[9] ^= c;
}

inline void select (Fe32 &res, const Fe32 &a, const Fe32 &b, uint32_t first)
{
	uint32_t discard = first - 1;   // All zero if first == 1, all 1 if first == 0;
	uint32_t keep = ~discard;       // All one if first == 1, all 0 if first == 0

	for (int i = 0; i < fecount; ++i) {
		res.v[i] = (a.v[i] & keep) | (b.v[i] & discard);
	}
}


inline void convert (Fe32 &res, const Fe64 &f)
{
	res.v[0] = f.v[0] & mask26;
	res.v[1] = f.v[0] >> 26;
	res.v[2] = f.v[1] & mask26;
	res.v[3] = f.v[1] >> 26;
	res.v[4] = f.v[2] & mask26;
	res.v[5] = f.v[2] >> 26;
	res.v[6] = f.v[3] & mask26;
	res.v[7] = f.v[3] >> 26;
	res.v[8] = f.v[4] & mask26;
	res.v[9] = f.v[4] >> 26;
}

inline void convert (Fe64 &res, const Fe32 &f)
{
	res.v[0] = f.v[0] + (uint64_t(f.v[1]) << 26);
	res.v[1] = f.v[2] + (uint64_t(f.v[3]) << 26);
	res.v[2] = f.v[4] + (uint64_t(f.v[5]) << 26);
	res.v[3] = f.v[6] + (uint64_t(f.v[7]) << 26);
	res.v[4] = f.v[8] + (uint64_t(f.v[9]) << 26);
}

// 64 bit limbs

inline void add_no_reduce (Fe64 &res, const Fe64 &a, const Fe64 &b)
{
	res.v[0] = a.v[0] + b.v[0];
	res.v[1] = a.v[1] + b.v[1];
	res.v[2] = a.v[2] + b.v[2];
	res.v[3] = a.v[3] + b.v[3];
	res.v[4] = a.v[4] + b.v[4];
}

inline void add (Fe64 &res, const Fe64 &a, const Fe64 &b)
{
	uint64_t c;
	c = a.v[0] + b.v[0];    res.v[0] = c & mask51;  c >>= 51;
	c += a.v[1] + b.v[1];   res.v[1] = c & mask51;  c >>= 51;
	c += a.v[2] + b.v[2];   res.v[2] = c & mask51;  c >>= 51;
	c += a.v[3] + b.v[3];   res.v[3] = c & mask51;  c >>= 51;
	c += a.v[4] + b.v[4];   res.v[4] = c & mask51;  c >>= 51;
	res.v[0] += 19 * c;
}


// Perform 4P + a - b. Avoids underflow to negative numbers.
inline void sub (Fe64 &res, const Fe64 &a, const Fe64 &b)
{
	uint64_t c;
	c = four_p0_64 + a.v[0] - b.v[0];       res.v[0] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[1] - b.v[1];     res.v[1] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[2] - b.v[2];     res.v[2] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[3] - b.v[3];     res.v[3] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[4] - b.v[4];     res.v[4] = c & mask51;  c >>= 51;
	res.v[0] += c * 19;
}


// Perform 4P - a. Avoids underflow to negative numbers.
inline void negate (Fe64 &res, const Fe64 &a)
{
	uint64_t c;
	c = four_p0_64 - a.v[0];       res.v[0] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[1];     res.v[1] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[2];     res.v[2] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[3];     res.v[3] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[4];     res.v[4] = c & mask51;  c >>= 51;
	res.v[0] += c * 19;
}


inline void cswap (Fe64 &a, Fe64 &b, uint64_t flag)
{
	flag = ~ (flag - 1);
	uint64_t c;
	c = (a.v[0] ^ b.v[0]) & flag;  a.v[0] ^= c;  b.v[0] ^= c;
	c = (a.v[1] ^ b.v[1]) & flag;  a.v[1] ^= c;  b.v[1] ^= c;
	c = (a.v[2] ^ b.v[2]) & flag;  a.v[2] ^= c;  b.v[2] ^= c;
	c = (a.v[3] ^ b.v[3]) & flag;  a.v[3] ^= c;  b.v[3] ^= c;
	c = (a.v[4] ^ b.v[4]) & flag;  a.v[4] ^= c;  b.v[4] ^= c;
}

inline void select (Fe64 &res, const Fe64 &a, const Fe64 &b, uint64_t first)
{
	uint64_t discard = first - 1;   // All zero if first == 1, all 1 if first == 0;
	uint64_t keep = ~discard;       // All one if first == 1, all 0 if first == 0

	for (int i = 0; i < fecount; ++i) {
		res.v[i] = (a.v[i] & keep) | (b.v[i] & discard);
	}
}



#if AMBER_LIMB_BITS == 128

// Use uint128_t for the result of multiplying two 64 bit limbs.

// Multiply the number by a small number that fits in 32 bits.
inline void mul_small (Fe64 &res, const Fe64 &a, uint32_t bs)
{
	uint128_t c, b = bs;
	c  = a.v[0] * b;   res.v[0] = c & mask51;   c >>= 51;
	c += a.v[1] * b;   res.v[1] = c & mask51;   c >>= 51;
	c += a.v[2] * b;   res.v[2] = c & mask51;   c >>= 51;
	c += a.v[3] * b;   res.v[3] = c & mask51;   c >>= 51;
	c += a.v[4] * b;   res.v[4] = c & mask51;   c >>= 51;
	c = res.v[0] + c * 19;      res.v[0] = c & mask51;   c >>= 51;
	res.v[1] += c;
}

// 128 bit result.
inline uint128_t mulw (uint64_t a, uint64_t b)
{
	return uint128_t(a) * uint128_t(b);
}

inline void mul (Fe64 &res, const Fe64 &f, const Fe64 &g)
{
	uint128_t h0, h1, h2, h3, h4;

	h0 = mulw(f.v[0], g.v[0]) + 19 * (mulw(f.v[1], g.v[4]) +
			mulw(f.v[2], g.v[3]) + mulw(f.v[3], g.v[2]) +
			mulw(f.v[4], g.v[1]));
	h1 = mulw(f.v[0], g.v[1]) + mulw(f.v[1], g.v[0]) + 19 * (
			mulw(f.v[2], g.v[4]) + mulw(f.v[3], g.v[3]) +
			mulw(f.v[4], g.v[2]));
	h2 = mulw(f.v[0], g.v[2]) + mulw(f.v[1], g.v[1]) + mulw(f.v[2], g.v[0]) +
			19 * (mulw(f.v[3], g.v[4]) + mulw(f.v[4], g.v[3]));
	h3 = mulw(f.v[0], g.v[3]) + mulw(f.v[1], g.v[2]) + mulw(f.v[2], g.v[1]) +
			mulw(f.v[3], g.v[0]) + 19 * mulw(f.v[4], g.v[4]);
	h4 = mulw(f.v[0], g.v[4]) + mulw(f.v[1], g.v[3]) + mulw(f.v[2], g.v[2]) +
			mulw(f.v[3], g.v[1]) + mulw(f.v[4], g.v[0]);

	uint128_t c = h0;   res.v[0] = c & mask51;   c >>= 51;
	c += h1;            res.v[1] = c & mask51;   c >>= 51;
	c += h2;            res.v[2] = c & mask51;   c >>= 51;
	c += h3;            res.v[3] = c & mask51;   c >>= 51;
	c += h4;            res.v[4] = c & mask51;   c >>= 51;
	c = res.v[0] + c * 19;      res.v[0] = c & mask51;   c >>= 51;
	res.v[1] += c;
}

inline void square (Fe64 &res, const Fe64 &f)
{
	uint128_t h0, h1, h2, h3, h4;

	uint128_t f0f1 = mulw (f.v[0], f.v[1]);
	uint128_t f0f2 = mulw (f.v[0], f.v[2]);
	uint128_t f0f3 = mulw (f.v[0], f.v[3]);
	uint128_t f0f4 = mulw (f.v[0], f.v[4]);

	uint128_t f1f2 = mulw (f.v[1], f.v[2]);
	uint128_t f1f3 = mulw (f.v[1], f.v[3]);
	uint128_t f1f4 = mulw (f.v[1], f.v[4]);

	uint128_t f2f3 = mulw (f.v[2], f.v[3]);
	uint128_t f2f4 = mulw (f.v[2], f.v[4]);

	uint128_t f3f4 = mulw (f.v[3], f.v[4]);

	h0 = mulw(f.v[0], f.v[0]) + 38 * (f1f4 + f2f3);
	h1 = 2*f0f1 + 38*f2f4 + 19 * mulw(f.v[3], f.v[3]);
	h2 = 2*f0f2 + mulw(f.v[1], f.v[1]) + 38*f3f4;
	h3 = 2*(f0f3 + f1f2) + 19 * mulw(f.v[4], f.v[4]);
	h4 = 2*(f0f4 + f1f3) + mulw(f.v[2], f.v[2]);

	uint128_t c = h0;   res.v[0] = c & mask51;   c >>= 51;
	c += h1;            res.v[1] = c & mask51;   c >>= 51;
	c += h2;            res.v[2] = c & mask51;   c >>= 51;
	c += h3;            res.v[3] = c & mask51;   c >>= 51;
	c += h4;            res.v[4] = c & mask51;   c >>= 51;
	c = res.v[0] + c * 19;      res.v[0] = c & mask51;   c >>= 51;
	res.v[1] += c;
}

#elif AMBER_LIMB_BITS == 64

// We multiply two 64 bit limbs by decomposing them into two sublimbs with 25
// and 26 bits each. This mimics the decomposition into 25/26 bit limbs for
// the uint32_t representation.

// Multiply the number by a small number that fits in 32 bits.
inline void mul_small (Fe64 &res, const Fe64 &a, uint32_t bs)
{
	uint64_t c, b = bs;
	uint64_t a0, a1, r0, r1;
	c = 0;
	for (int i = 0; i < 5; ++i) {
		a0 = a.v[i] & mask26;
		a1 = a.v[i] >> 26;
		c += a0 * b;    r0 = c & mask26;     c >>= 26;
		c += a1 * b;    r1 = c & mask25;     c >>= 25;
		res.v[i] = (r1 << 26) | r0;
	}

	c = res.v[0] + c * 19;      res.v[0] = c & mask51;  c >>= 51;
	res.v[1] += c;
}




inline void mul (Fe64 &res, const Fe64 &f, const Fe64 &g)
{
	uint32_t f0 = f.v[0] & mask26, f1 = f.v[0] >> 26;
	uint32_t f2 = f.v[1] & mask26, f3 = f.v[1] >> 26;
	uint32_t f4 = f.v[2] & mask26, f5 = f.v[2] >> 26;
	uint32_t f6 = f.v[3] & mask26, f7 = f.v[3] >> 26;
	uint32_t f8 = f.v[4] & mask26, f9 = f.v[4] >> 26;

	uint32_t g0 = g.v[0] & mask26, g1 = g.v[0] >> 26;
	uint32_t g2 = g.v[1] & mask26, g3 = g.v[1] >> 26;
	uint32_t g4 = g.v[2] & mask26, g5 = g.v[2] >> 26;
	uint32_t g6 = g.v[3] & mask26, g7 = g.v[3] >> 26;
	uint32_t g8 = g.v[4] & mask26, g9 = g.v[4] >> 26;

	uint32_t f1_2  =  2 * f1;
	uint32_t f1_38 = 38 * f1;
	uint32_t f2_19 = 19 * f2;
	uint32_t f3_2  =  2 * f3;
	uint32_t f3_38 = 38 * f3;
	uint32_t f4_19 = 19 * f4;
	uint32_t f5_2  =  2 * f5;
	uint32_t f5_19 = 19 * f5;
	uint32_t f5_38 = 38 * f5;
	uint32_t f6_19 = 19 * f6;
	uint32_t f7_19 = 19 * f7;
	uint32_t f7_38 = 38 * f7;
	uint32_t f8_19 = 19 * f8;
	uint32_t f9_19 = 19 * f9;
	uint32_t f9_38 = 38 * f9;

	uint64_t h0 = mul(f0,g0)    + mul(f1_38,g9) + mul(f2_19,g8) + mul(f3_38,g7)
				+ mul(f4_19,g6) + mul(f5_38,g5) + mul(f6_19,g4) + mul(f7_38,g3)
				+ mul(f8_19,g2) + mul(f9_38,g1);

	uint64_t h1 = mul(f0,g1)    + mul(f1,g0)    + mul(f2_19,g9) + mul(f3*19,g8)
				+ mul(f4_19,g7) + mul(f5_19,g6) + mul(f6_19,g5) + mul(f7_19,g4)
				+ mul(f8_19,g3) + mul(f9_19,g2);

	uint64_t h2 = mul(f0,g2)    + mul(f1_2,g1)  + mul(f2,g0)    + mul(f3_38,g9)
				+ mul(f4_19,g8) + mul(f5_38,g7) + mul(f6_19,g6) + mul(f7_38,g5)
				+ mul(f8_19,g4) + mul(f9_38,g3);

	uint64_t h3 = mul(f0, g3)   + mul(f1,g2)    + mul(f2, g1)   + mul(f3,g0)
				+ mul(f4_19,g9) + mul(f5_19,g8) + mul(f6_19,g7) + mul(f7_19,g6)
				+ mul(f8_19,g5) + mul(f9_19,g4);

	uint64_t h4 = mul(f0,g4)    + mul(f1_2,g3)  + mul(f2,g2)    + mul(f3_2,g1)
				+ mul(f4,g0)    + mul(f5_38,g9) + mul(f6_19,g8) + mul(f7_38,g7)
				+ mul(f8_19,g6) + mul(f9_38,g5);

	uint64_t h5 = mul(f0,g5)    + mul(f1,g4)    + mul(f2,g3)    + mul(f3,g2)
				+ mul(f4,g1)    + mul(f5,g0)    + mul(f6_19,g9) + mul(f7_19,g8)
				+ mul(f8_19,g7) + mul(f9_19,g6);

	uint64_t h6 = mul(f0,g6)    + mul(f1_2,g5)  + mul(f2,g4)    + mul(f3_2,g3)
				+ mul(f4,g2)    + mul(f5_2,g1)  + mul(f6,g0)    + mul(f7_38,g9)
				+ mul(f8_19,g8) + mul(f9_38,g7);

	uint64_t h7 = mul(f0,g7)    + mul(f1,g6)    + mul(f2,g5)    + mul(f3,g4)
				+ mul(f4,g3)    + mul(f5,g2)    + mul(f6,g1)    + mul(f7,g0)
				+ mul(f8_19,g9) + mul(f9_19,g8);

	uint64_t h8 = mul(f0,g8)    + mul(f1_2,g7)  + mul(f2,g6)    + mul(f3_2,g5)
				+ mul(f4,g4)    + mul(f5_2,g3)  + mul(f6,g2)    + mul(f7*2,g1)
				+ mul(f8,g0)    + mul(f9_38,g9);

	uint64_t h9 = mul(f0,g9)    + mul(f1,g8)    + mul(f2,g7)    + mul(f3,g6)
				+ mul(f4,g5)    + mul(f5,g4)    + mul(f6,g3)    + mul(f7,g2)
				+ mul(f8,g1)    + mul(f9,g0);


	uint64_t c = h0;    res.v[0] = c & mask26;   c >>= 26;
	c += h1;            res.v[0] |= (c & mask25) << 26;   c >>= 25;
	c += h2;            res.v[1] = c & mask26;   c >>= 26;
	c += h3;            res.v[1] |= (c & mask25) << 26;   c >>= 25;
	c += h4;            res.v[2] = c & mask26;   c >>= 26;
	c += h5;            res.v[2] |= (c & mask25) << 26;   c >>= 25;
	c += h6;            res.v[3] = c & mask26;   c >>= 26;
	c += h7;            res.v[3] |= (c & mask25) << 26;   c >>= 25;
	c += h8;            res.v[4] = c & mask26;   c >>= 26;
	c += h9;            res.v[4] |= (c & mask25) << 26;   c >>= 25;
	res.v[0] += c*19;
}

inline void square (Fe64 &res, const Fe64 &f)
{
	uint32_t f0 = f.v[0] & mask26, f1 = f.v[0] >> 26;
	uint32_t f2 = f.v[1] & mask26, f3 = f.v[1] >> 26;
	uint32_t f4 = f.v[2] & mask26, f5 = f.v[2] >> 26;
	uint32_t f6 = f.v[3] & mask26, f7 = f.v[3] >> 26;
	uint32_t f8 = f.v[4] & mask26, f9 = f.v[4] >> 26;

	uint32_t f1_2  =  2 * f1;
	uint32_t f1_38 = 38 * f1;
	uint32_t f2_19 = 19 * f2;
	uint32_t f3_2  =  2 * f3;
	uint32_t f3_38 = 38 * f3;
	uint32_t f4_19 = 19 * f4;
	uint32_t f5_19 = 19 * f5;
	uint32_t f5_38 = 38 * f5;
	uint32_t f6_19 = 19 * f6;
	uint32_t f7_19 = 19 * f7;
	uint32_t f7_38 = 38 * f7;
	uint32_t f8_19 = 19 * f8;
	uint32_t f9_38 = 38 * f9;

	uint64_t h0 = mul(f0,f0)
				+ 2*(mul(f1_38,f9) + mul(f2_19,f8) + mul(f3_38,f7) + mul(f4_19,f6))
				+ mul(f5_38,f5);

	uint64_t h1 = 2 * (mul(f0,f1)  + mul(f2_19,f9) + mul(f3*19,f8)
					   + mul(f4_19,f7) + mul(f5_19,f6));

	uint64_t h2 = 2 * (mul(f0,f2)    + mul(f1,f1)  + mul(f3_38,f9)
					   + mul(f4_19,f8) + mul(f5_38,f7))  + mul(f6_19,f6);

	uint64_t h3 = 2 * (mul(f0,f3)   + mul(f1,f2) + mul(f4_19,f9) + mul(f5_19,f8) + mul(f6_19,f7));

	uint64_t h4 = 2 * (mul(f0,f4) + mul(f1_2,f3) + mul(f5_38,f9) + mul(f6_19,f8))
				+ mul(f2,f2) + mul(f7_38,f7);

	uint64_t h5 = 2 * (mul(f0,f5) + mul(f1,f4) + mul(f2,f3) + mul(f6_19,f9) + mul(f7_19,f8));

	uint64_t h6 = 2 * (mul(f0,f6) + mul(f1_2,f5) + mul(f2,f4) + mul(f7_38,f9))
				+ mul(f3_2,f3) + mul(f8_19,f8);

	uint64_t h7 = 2 * (mul(f0,f7) + mul(f1,f6) + mul(f2,f5) + mul(f3,f4) + mul(f8_19,f9));

	uint64_t h8 = 2 * (mul(f0,f8) + mul(f1_2,f7) + mul(f2,f6) + mul(f3_2,f5))
				+ mul(f4,f4) + mul(f9_38,f9);

	uint64_t h9 = 2 * (mul(f0,f9) + mul(f1,f8) + mul(f2,f7) + mul(f3,f6) + mul(f4,f5));



	uint64_t c = h0;    res.v[0] = c & mask26;   c >>= 26;
	c += h1;            res.v[0] |= (c & mask25) << 26;   c >>= 25;
	c += h2;            res.v[1] = c & mask26;   c >>= 26;
	c += h3;            res.v[1] |= (c & mask25) << 26;   c >>= 25;
	c += h4;            res.v[2] = c & mask26;   c >>= 26;
	c += h5;            res.v[2] |= (c & mask25) << 26;   c >>= 25;
	c += h6;            res.v[3] = c & mask26;   c >>= 26;
	c += h7;            res.v[3] |= (c & mask25) << 26;   c >>= 25;
	c += h8;            res.v[4] = c & mask26;   c >>= 26;
	c += h9;            res.v[4] |= (c & mask25) << 26;   c >>= 25;
	res.v[0] += c*19;
}

#endif

}}


#endif


