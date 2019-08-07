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


#include "group25519.hpp"
#include "misc.hpp"
#include "blake2.hpp"
#include <iostream>
#include <iomanip>
#include <string.h>
#include <fstream>
#include "sha2.hpp"
#include "hasopt.hpp"

namespace amber {   namespace AMBER_SONAME {


static const Fe fezero = { 0 };
static const Fe feone = { 1 };
static const Edwards edzero = { fezero, feone, feone, fezero };

#if AMBER_LIMB_BITS == 32
// p = 2²⁵⁵-19
static const Fe p = { 0x3FFFFED, mask25, mask26, mask25, mask26,
                     mask25, mask26, mask25, mask26, mask25 };


// d = -121665/121666
static const Fe edwards_d = {  0x35978a3, 0x0d37284, 0x3156ebd, 0x06a0a0e, 0x001c029,
                               0x179e898, 0x3a03cbb, 0x1ce7198, 0x2e2b6ff, 0x1480db3 };


static const Fe edwards_2d = { 0x2b2f159, 0x1a6e509, 0x22add7a, 0x0d4141d, 0x0038052,
                               0x0f3d130, 0x3407977, 0x19ce331, 0x1c56dff, 0x0901b67 };

// sqrt(-1) = 2^(2²⁵³ - 5)
static const Fe root_minus_1 = { 0x20ea0b0, 0x186c9d2, 0x08f189d, 0x035697f, 0x0bd0c60,
                                 0x1fbd7a7, 0x2804c9e, 0x1e16569, 0x004fc1d, 0x0ae0c92 };

// C = sqrt(-A-2)
static const Fe C = { 0x0ba81e7, 0x07ed540, 0x0afa672, 0x175a417, 0x0e978b0,
                      0x003b081, 0x27b91fe, 0x12885b0, 0x0b9f5ff, 0x1c36448 };

// Base point. This is 9 in Montgomery.
static const Edwards edwards_base = {
	{ 0x325d51a, 0x18b5823, 0x0f6592a, 0x104a92d, 0x1a4b31d,
	  0x1d6dc5c, 0x27118fe, 0x07fd814, 0x13cd6e5, 0x085a4db },
	{ 0x2666658, 0x1999999, 0x0cccccc, 0x1333333, 0x1999999,
	  0x0666666, 0x3333333, 0x0cccccc, 0x2666666, 0x1999999 },
	{ 0x0000001, 0x0000000, 0x0000000, 0x0000000, 0x0000000,
	  0x0000000, 0x0000000, 0x0000000, 0x0000000, 0x0000000 },
	{ 0x1b7dda3, 0x1a2ace9, 0x25eadbb, 0x003ba8a, 0x083c27e,
	  0x0abe37d, 0x1274732, 0x0ccacdd, 0x0fd78b7, 0x19e1d7c }
};

static const Fe d_minus_one_sq    = { 0x0ed4d20, 0x156aa91, 0x3332635, 0x16580f0, 0x34a7928, 0x09b4eeb, 0x26997a9, 0x048299b, 0x3af66c2, 0x165a2cd };
static const Fe one_minus_d_sq    = { 0x05fc176, 0x1027065, 0x2a1fc4f, 0x1c66af1, 0x0b20684, 0x070dfe4, 0x255eedf, 0x01af332, 0x28b2b3e, 0x00a41ca };
static const Fe invsqrt_a_minus_d = { 0x05d40ea, 0x03f6aa0, 0x257d339, 0x0bad20b, 0x274bc58, 0x001d840, 0x13dc8ff, 0x19442d8, 0x05cfaff, 0x1e1b224 };
static const Fe sqrt_ad_minus_one = { 0x17b2e1b, 0x1fda812, 0x297afd2, 0x060dbc2, 0x2be7638, 0x1f5d1fd, 0x27e6498, 0x11581e7, 0x3f2b834, 0x0dda4c6 };


#elif AMBER_LIMB_BITS >= 64

static const Fe p = { p0_64, mask51, mask51, mask51, mask51 };


// d = -121665/121666
static const Fe edwards_d = {  0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029,
                               0x739c663a03cbb, 0x52036cee2b6ff };

static const Fe edwards_2d = { 0x69b9426b2f159, 0x35050762add7a, 0x3cf44c0038052,
                               0x6738cc7407977, 0x2406d9dc56dff };

// sqrt(-1) = 2^(2²⁵³ - 5)
static const Fe root_minus_1 = { 0x61b274a0ea0b0, 0xd5a5fc8f189d, 0x7ef5e9cbd0c60,
                                 0x78595a6804c9e, 0x2b8324804fc1d };

// C = sqrt(-A-2)
static const Fe C = { 0x1fb5500ba81e7, 0x5d6905cafa672, 0xec204e978b0, 0x4a216c27b91fe,
                      0x70d9120b9f5ff };

// Base point. This is 9 in Montgomery.
static const Edwards edwards_base = {
	{ 0x62d608f25d51a, 0x412a4b4f6592a, 0x75b7171a4b31d, 0x1ff60527118fe, 0x216936d3cd6e5 },
	{ 0x6666666666658, 0x4cccccccccccc, 0x1999999999999, 0x3333333333333, 0x6666666666666 },
	{ 0x0000001, 0x0000000, 0x0000000, 0x0000000, 0x0000000 },
	{ 0x68ab3a5b7dda3, 0xeea2a5eadbb, 0x2af8df483c27e, 0x332b375274732, 0x67875f0fd78b7 }
};

static const Fe invsqrt_a_minus_d = { 0xfdaa805d40ea, 0x2eb482e57d339, 0x7610274bc58,
                                      0x6510b613dc8ff, 0x786c8905cfaff };
static const Fe one_minus_d_sq    = { 0x409c1945fc176, 0x719abc6a1fc4f, 0x1c37f90b20684,
                                      0x6bccca55eedf, 0x29072a8b2b3e };
static const Fe d_minus_one_sq    = { 0x55aaa44ed4d20, 0x59603c3332635, 0x26d3baf4a7928,
                                      0x120a66e6997a9, 0x5968b37af66c2 };
static const Fe sqrt_ad_minus_one = { 0x7f6a0497b2e1b, 0x1836f0a97afd2, 0x7d747f6be7638,
                                      0x456079e7e6498, 0x376931bf2b834 };


#endif

const Edwards edwards_base_point = edwards_base;


#if 0  // Used for debugging.
static void show_edwards (std::ostream &os, const char *label, const Edwards &ed)
{
	os << label << ": \n";
	os << "    x: " << ed.x << '\n';
	os << "    y: " << ed.y << '\n';
	os << "    z: " << ed.z << '\n';
	os << "    t: " << ed.t << '\n';
}
#endif


// Store the point as Montgomery x with the sign bit in bit 255.
/*
	u = (Z + Y)/(Z - Y)
	x = X/Z
	Combine the two inversions.
	h = 1/(Z(Z-Y))
	u = Z(Z+Y)h = Z(Z+Y)/Z/(Z-Y) = (Z+Y)/(Z-Y)
	x = X(Z-Y)h = X(Z-Y)/Z/(Z-Y) = X/Z

*/

void edwards_to_mxs (uint8_t res[32], const Edwards &p)
{
	Fe zmy, h;
	sub (zmy, p.z, p.y);
	mul (h, zmy, p.z);
	invert (h, h);
	mul (zmy, zmy, h);
	mul (zmy, zmy, p.x);
	reduce_store (res, zmy);
	uint8_t sign = res[0] & 1;

	add_no_reduce (zmy, p.z, p.y);
	mul (zmy, zmy, p.z);
	mul (zmy, zmy, h);
	reduce_store (res, zmy);
	res[31] |= sign << 7;
}

// Store the point as Edwards y with the sign bit in bit 255.

void edwards_to_eys (uint8_t res[32], const Edwards &p)
{
	Fe inv, tmp;
	invert (inv, p.z);
	mul (tmp, p.x, inv);
	reduce_store (res, tmp);
	uint8_t sign = res[0] & 1;

	mul (tmp, p.y, inv);
	reduce_store (res, tmp);
	res[31] |= sign << 7;
}

// Convert simultaneously to compressed Montgomery and Edwards.
/*
	u = (Z + Y)/(Z - Y)
	x = X/Z
	Combine the two inversions.
	h = 1/(Z(Z-Y))
	u = Z(Z+Y)h = Z(Z+Y)/Z/(Z-Y) = (Z+Y)/(Z-Y)
	w = (Z-Y)h = (Z-Y)/Z/(Z-Y) = 1/Z
	x = wX
	y = wY

*/

void edwards_to_eys_mxs (uint8_t ey[32], uint8_t mx[32], const Edwards &p)
{
	Fe zmy, h, w;
	sub (zmy, p.z, p.y);
	mul (h, zmy, p.z);
	invert (h, h);
	mul (w, zmy, h);

	mul (zmy, w, p.x);
	reduce_store (ey, zmy);
	uint8_t sign = ey[0] & 1;

	mul (zmy, w, p.y);
	reduce_store (ey, zmy);
	ey[31] |= sign << 7;

	add_no_reduce (zmy, p.z, p.y);
	mul (zmy, zmy, p.z);
	mul (zmy, zmy, h);
	reduce_store (mx, zmy);
	mx[31] |= sign << 7;
}


// Load to Edwards coordinates starting from the Montgomery x coordinate.
// The Montgomery x coordinate contains the parity of the Edwards x
// coordinate in the most significant bit of the last byte. This is as fast
// as unpacking the Edwards Y coordinate. See
// https://moderncrypto.org/mail-archive/curves/2015/000376.html
/*  x = Cu/v      C = sqrt(-1)*sqrt(A+2)
	y = (u-1)/(u+1).
	where v = sqrt(u³+Au²+u)
	We combine the inversions and the square root into one exponential.
	v² = u³+Au²+u
	h = v²*(u+1)²
	s = 1/sqrt(h) = h³(h⁷)^((p-5)/8) = h³(h⁷)^(2²⁵²-3) From Ed25519 paper.
	s is now 1/(v(u+1))
	x = C*u*(u+1)*s
	1/(u+1) = s²*v²*(u+1)
	y = (u-1)/(u+1) = (u-1)*(u+1)*s²*v²
*/



// Expansion of compressed Montgomery X plus sign bit of Edwards X to Edwards
// coordinates. It will return 0 on success. If the compressed point mx is
// not on the curve or if the input is mx==0 or mx==-1 then it will return a
// non zero value.

// If neg is true then select the negative value.

int mxs_to_edwards (Edwards &res, const uint8_t mx[32], bool neg)
{
	Fe u, t1, t2, a, b, h, s;
	enum { A = 486662 };

	load (u, mx);
	square (t1, u);
	mul_small (t2, u, A);
	add (t1, t1, t2);
	add_no_reduce (t1, t1, feone);
	mul (a, t1, u);         // a = u(1 + Au + u²) = v²

	add_no_reduce (b, u, feone);      // b = u + 1
	mul (h, a, b);
	mul (h, h, b);          // h = ab²

	if (0 != invsqrt (s, h)) {
		return -1;
	}    // s = 1/sqrt(h);

	// y = (u - 1)*a*b*s²
	sub (t1, u, feone);
	mul (t1, t1, a);
	mul (t1, t1, b);
	square (t2, s);
	mul (res.y, t1, t2);

	// x = C*u*b*s
	mul (res.x, C, u);
	mul (res.x, res.x, b);
	mul (res.x, res.x, s);

	uint8_t check[32];
	int signbit = mx[31] >> 7;
	reduce_store (check, res.x);

	if (neg) signbit = !signbit;
	// Select the correct sign bit/
	if ((check[0] & 1) != signbit) {
		negate (res.x, res.x);
	}
	mul (res.t, res.x, res.y);
	res.z = feone;

	return 0;
}

inline bool is_zero_vartime (Fe &fe)
{
	uint8_t bytes[32];
	reduce_store (bytes, fe);

	for (int i = 0; i < fecount; ++i) {
		if (fe.v[i] != 0) return false;
	}
	return true;
}

/* -x² + y² = 1 + dx²y²
	y² - 1 = x² + dx²y²
	x = sqrt((y² - 1)/(1 + dy²))
*/

// Return 0 if ok. -1 on errors.

int eys_to_edwards (Edwards &res, const uint8_t ey[32], bool neg)
{
	Fe u, v, y, y2, tmp1, tmp2, v4, x2;

	load (y, ey);
	square (y2, y);
	sub (u, y2, feone);     // u = y² - 1
	mul (v, edwards_d, y2);
	add (v, v, feone);      // v = dy² + 1

	// Compute sqrt(u/v) as uv³(uv⁷)^[(q-5)/8]
	square (tmp1, v);
	square (v4, tmp1);
	mul (tmp1, tmp1, u);
	mul (tmp1, tmp1, v);  // tmp1 = uv³

	mul (tmp2, tmp1, v4);
	raise_252_3 (tmp2, tmp2);   // tmp2 = sqrt(u/v)
	mul (res.x, tmp1, tmp2);

	// Now check if the root fits the equation x²v =  u
	square (x2, res.x);
	mul (tmp1, x2, v);
	sub (tmp2, tmp1, u);
	if (!is_zero_vartime (tmp2)) {
		// Check if -x² works:
		add (tmp2, tmp1, u);
		if (!is_zero_vartime (tmp2)) {
			return -1;
		}
		mul (res.x, res.x, root_minus_1);
	}

	// Choose the correct sign value.
	uint8_t bytes[32];
	reduce_store (bytes, res.x);
	int signbit = ey[31] >> 7;
	if (neg) signbit = !signbit;
	if ((bytes[0] & 1) != signbit) {
		// Wrong sign bit. Select the negative value.
		negate (res.x, res.x);
	}
	res.y = y;
	mul (res.t, res.x, res.y);
	res.z = feone;
	return 0;
}


// Convert compressed Edwards y to compressed Montgomery x, with sign bits.

// The y=1 (identity point) it maps to u = ∞ (the identity point in
// Montgomery). However our routine maps it to u=0.

void eys_to_mxs (uint8_t mx[32], const uint8_t ey[32])
{
	Fe y, t1, t2;

	// u = (1+y)/(1-y)

	load (y, ey);
	add_no_reduce (t1, y, feone);
	sub (t2, feone, y);
	invert (t2, t2);
	mul (t1, t1, t2);
	reduce_store (mx, t1);
	mx[31] |= ey[31] & 0x80;
}

// Convert compressed Montgomery x to compressed Edwards y, with sign bits.
// When u == -1 this fails and returns ey == 0.

void mxs_to_eys (uint8_t ey[32], const uint8_t mx[32])
{
	// y = (u - 1)/(u + 1)
	Fe x, y, tmp0, tmp1;

	load (x, mx);
	sub (tmp0, x, feone);
	add_no_reduce (tmp1, x, feone);
	invert (tmp1, tmp1);
	mul (y, tmp0, tmp1);
	reduce_store (ey, y);
	ey[31] |= mx[31] & 0x80;
}


std::ostream & operator<< (std::ostream &os, const Edwards &rhs)
{
	uint8_t ey[32];
	edwards_to_eys (ey, rhs);

	os << std::hex << std::setfill ('0');
	int count = 0;
	for (int i = 0; i < 32; ++i) {
		os << std::setw(2) << unsigned(ey[i]);
		if (++count == 4) {
			os << ' ';
			count = 0;
		}
	}
	os << std::dec << std::setfill (' ');
	return os;
}




// Precomputed values that are stored without z. z is assumed to be 1.
struct Precomputed {
	// Store the values required for the addition. z is assumed to be 1.
	// y + x, y - x, x*y*2*d
	Fe ypx, ymx, xy2d;
};


// Precomputed values that are stored with z.
struct Summand {
	// y + x, y - x, t*2*d, z*2
	Fe ypx, ymx, t2d, z2;
};


// These formulae are given in RFC 8032.

// res = p + q
inline void point_add (Edwards &res, const Edwards &p, const Edwards &q)
{
	Fe a, b, c, d, e, f, g, h, t;

	sub (a, p.y, p.x);
	sub (t, q.y, q.x);
	mul (a, a, t);
	add_no_reduce (b, p.x, p.y);
	add_no_reduce (t, q.x, q.y);
	mul (b, b, t);
	mul (c, p.t, q.t);
	mul (c, c, edwards_2d);
	mul (d, p.z, q.z);
	add_no_reduce (d, d, d);
	sub (e, b, a);
	sub (f, d, c);
	add_no_reduce (g, d, c);
	add_no_reduce (h, b, a);

	mul (res.x, e, f);
	mul (res.y, h, g);
	mul (res.t, e, h);
	mul (res.z, f, g);
}


void add (Edwards &res, const Edwards &a, const Edwards &b)
{
	point_add (res, a, b);
}


inline void point_add (Edwards &res, const Edwards &p, const Precomputed &q)
{
	Fe a, b, c, d, e, f, g, h;

	sub (a, p.y, p.x);
	mul (a, a, q.ymx);
	add_no_reduce (b, p.x, p.y);
	mul (b, b, q.ypx);
	mul (c, p.t, q.xy2d);
	add_no_reduce (d, p.z, p.z);
	sub (e, b, a);
	sub (f, d, c);
	add_no_reduce (g, d, c);
	add_no_reduce (h, b, a);

	mul (res.x, e, f);
	mul (res.y, h, g);
	mul (res.t, e, h);
	mul (res.z, f, g);
}

inline void point_add (Edwards &res, const Edwards &p, const Summand &q)
{
	Fe a, b, c, d, e, f, g, h;

	sub (a, p.y, p.x);
//    sub (t, q.y, q.x);
	mul (a, a, q.ymx);
	add_no_reduce (b, p.x, p.y);
//    add_no_reduce (t, q.x, q.y);
	mul (b, b, q.ypx);
	mul (c, p.t, q.t2d);
//    mul (c, c, edwards_2d);
	mul (d, p.z, q.z2);
//    add_no_reduce (d, d, d);
	sub (e, b, a);
	sub (f, d, c);
	add_no_reduce (g, d, c);
	add_no_reduce (h, b, a);

	mul (res.x, e, f);
	mul (res.y, h, g);
	mul (res.t, e, h);
	mul (res.z, f, g);
}

inline void point_add (Summand &res, const Summand &p, const Edwards &q)
{
	Fe a, b, c, d, e, f, g, h, t;

//    sub (a, p.y, p.x);
	sub (t, q.y, q.x);
	mul (a, p.ymx, t);
//    add_no_reduce (b, p.x, p.y);
	add_no_reduce (t, q.x, q.y);
	mul (b, p.ypx, t);
	mul (c, p.t2d, q.t);
//    mul (c, c, edwards_2d);
	mul (d, p.z2, q.z);
//    add_no_reduce (d, d, d);
	sub (e, b, a);
	sub (f, d, c);
	add_no_reduce (g, d, c);
	add_no_reduce (h, b, a);

	Fe x, y;
	mul (x, e, f);
	mul (y, h, g);
	add_no_reduce (res.ypx, x, y);
	sub (res.ymx, y, x);
	mul (res.t2d, e, h);
	mul (res.t2d, res.t2d, edwards_2d);
	mul (res.z2, f, g);
	add_no_reduce (res.z2, res.z2, res.z2);
}


// res = p - q
inline void point_sub (Edwards &res, const Edwards &p, const Edwards &q)
{
	Fe a, b, c, d, e, f, g, h, t;

	sub (a, p.y, p.x);
	add (t, q.y, q.x);
	mul (a, a, t);
	add_no_reduce (b, p.x, p.y);
	sub (t, q.y, q.x);
	mul (b, b, t);
	negate (c, q.t);
	mul (c, p.t, c);
	mul (c, c, edwards_2d);
	mul (d, p.z, q.z);
	add_no_reduce (d, d, d);
	sub (e, b, a);
	sub (f, d, c);
	add_no_reduce (g, d, c);
	add_no_reduce (h, b, a);

	mul (res.x, e, f);
	mul (res.y, h, g);
	mul (res.t, e, h);
	mul (res.z, f, g);
}

void sub (Edwards &res, const Edwards &a, const Edwards &b)
{
	point_sub (res, a, b);
}

inline void point_sub (Edwards &res, const Edwards &p, const Summand &q)
{
	Fe a, b, c, d, e, f, g, h;

	sub (a, p.y, p.x);
//    add (t, q.y, q.x);
	mul (a, a, q.ypx);
	add_no_reduce (b, p.x, p.y);
//    sub (t, q.y, q.x);
	mul (b, b, q.ymx);
	negate (c, q.t2d);
	mul (c, p.t, c);
//    mul (c, c, edwards_2d);
	mul (d, p.z, q.z2);
//  add_no_reduce (d, d, d);
	sub (e, b, a);
	sub (f, d, c);
	add_no_reduce (g, d, c);
	add_no_reduce (h, b, a);

	mul (res.x, e, f);
	mul (res.y, h, g);
	mul (res.t, e, h);
	mul (res.z, f, g);
}




inline void point_double (Edwards &res, const Edwards &p)
{
	Fe a, b, c, h, e, g, f;
	square (a, p.x);
	square (b, p.y);
	square (c, p.z);
	add (c, c, c);
	add (h, a, b);
	add_no_reduce (e, p.x, p.y);
	square (e, e);
	sub (e, h, e);
	sub (g, a, b);
	add_no_reduce (f, c, g);
	mul (res.x, e, f);
	mul (res.y, g, h);
	mul (res.t, e, h);
	mul (res.z, f, g);
}

void pdouble (Edwards &res, const Edwards &x)
{
	point_double (res, x);
}



void negate (Edwards &res, const Edwards &p)
{
	// Works even if res and p point to the same memory.
	negate (res.x, p.x);
	res.y = p.y;
	res.z = p.z;
	negate (res.t, p.t);
}

// Swap a and b if flag == 1. Flag must be exactly 1 or 0. No other values.
inline void cswap (Edwards &a, Edwards &b, uint32_t flag)
{
	cswap (a.x, b.x, flag);
	cswap (a.y, b.y, flag);
	cswap (a.z, b.z, flag);
	cswap (a.t, b.t, flag);
}

// res = sP

void scalarmult (Edwards &res, const Edwards &p, const uint8_t s[32])
{
	int i;
	res.x = fezero;
	res.y = feone;
	res.z = feone;
	res.t = fezero;

	Edwards tmp = p;

	for (i = 255; i >= 0; --i) {
		uint32_t b = (s[i/8] >> (i&7)) & 1;
		cswap (res, tmp, b);
		point_add (tmp, tmp, res);
		point_double (res, res);
		cswap (res, tmp, b);
	}
}


// return a == b in constant time.
inline uint32_t equal (uint32_t a, uint32_t b)
{
	uint32_t diff = a ^ b;
	return (diff - 1) >> 31;
}


// If flag == 1 then res = p. Flag can be either 0 or 1, no other values
// allowed.
inline void select (Edwards &res, const Edwards &p, uint32_t flag)
{
	typedef decltype(p.x.v[0]) Limbint;
	Limbint liflag = flag;
	Limbint discard = liflag - 1;  // All zero if flag == 1, all 1 if flag == 0
	Limbint keep = ~discard;     // All one if flag == 1, all 0 if flag == 0

	for (int i = 0; i < fecount; ++i) {
		res.x.v[i] = (res.x.v[i] & discard) | (p.x.v[i] & keep);
		res.y.v[i] = (res.y.v[i] & discard) | (p.y.v[i] & keep);
		res.z.v[i] = (res.z.v[i] & discard) | (p.z.v[i] & keep);
		res.t.v[i] = (res.t.v[i] & discard) | (p.t.v[i] & keep);
	}
}

// Fixed window, 4 bits at a time.

void scalarmult_fw (Edwards &res, const Edwards &p, const uint8_t s[32])
{
	int i;
	res.x = fezero;
	res.y = feone;
	res.z = feone;
	res.t = fezero;

	Edwards pmul[16];

	pmul[0] = res;
	pmul[1] = p;
	point_double (pmul[2],  pmul[1]);
	point_add    (pmul[3],  pmul[2], pmul[1]);
	point_double (pmul[4],  pmul[2]);
	point_add    (pmul[5],  pmul[4], pmul[1]);
	point_double (pmul[6],  pmul[3]);
	point_add    (pmul[7],  pmul[6], pmul[1]);
	point_double (pmul[8],  pmul[4]);
	point_add    (pmul[9],  pmul[8], pmul[1]);
	point_double (pmul[10], pmul[5]);
	point_add    (pmul[11], pmul[10], pmul[1]);
	point_double (pmul[12], pmul[6]);
	point_add    (pmul[13], pmul[12], pmul[1]);
	point_double (pmul[14], pmul[7]);
	point_add    (pmul[15], pmul[14], pmul[1]);


	Edwards tmp;

	for (i = 31; i >= 0; --i) {
		uint32_t v = s[i] >> 4;

		point_double (res, res);
		point_double (res, res);
		point_double (res, res);
		point_double (res, res);

		for (int j = 0; j < 16; ++j) {
			select (tmp, pmul[j], equal (j, v));
		}
		point_add (res, res, tmp);

		v = s[i] & 0xF;

		point_double (res, res);
		point_double (res, res);
		point_double (res, res);
		point_double (res, res);

		for (int j = 0; j < 16; ++j) {
			select (tmp, pmul[j], equal (j, v));
		}
		point_add (res, res, tmp);
	}
}




static
void edwards_to_precomp (Precomputed &pc, const Edwards &e)
{
	Fe nx, ny, inv;
	invert (inv, e.z);
	mul (nx, e.x, inv);
	mul (ny, e.y, inv);
	add (pc.ypx, nx, ny);
	sub (pc.ymx, ny, nx);
	mul (pc.xy2d, nx, ny);
	mul (pc.xy2d, pc.xy2d, edwards_2d);
}

static
void edwards_to_summand (Summand &s, const Edwards &e)
{
	add (s.ypx, e.y, e.x);
	sub (s.ymx, e.y, e.x);
	mul (s.t2d, e.t, edwards_2d);
	add (s.z2, e.z, e.z);
}

#if 0 // Used for debugging.
static
void summand_to_edwards (Edwards &e, const Summand &s)
{
	add (e.y, s.ypx, s.ymx);
	sub (e.x, s.ypx, s.ymx);
	mul (e.t, e.x, e.y);
	e.z = s.z2;
	Fe inv;
	invert (inv, e.z);
	mul (e.t, e.t, inv);
}
#endif

// This file was created with
// write_base_multiples("group25519_basemult.hpp"); 30 kbytes
#if AMBER_LIMB_BITS == 32
	#include "group25519_basemult_32.hpp"
#elif AMBER_LIMB_BITS >= 64
	#include "group25519_basemult_64.hpp"
#endif

static
void write_coeffs (std::ostream &os, const Fe &fe)
{
	os << "{ " << std::hex << std::setfill('0');
	for (int i = 0; i < fecount; ++i) {
		os << "0x" << std::setw(7) << fe.v[i];
		if (i != 9) {
			os << ", ";
		}
	}
	os << " }" << std::setfill(' ') << std::dec;
}

void write_base_multiples (const char *name)
{
	std::ofstream os(name);
	os << "static const Precomputed basemult[32][8] = {\n";
	Edwards p;
	Precomputed pc;
	uint8_t scalar[32];
	for (int i = 0; i < 32; ++i) {
		memset (scalar, 0, 32);
		os << " { // 16^" << i*2 << "*B\n";
		for (int j = 1; j < 9; ++j) {
			scalar[i] = j;
			scalarmult (p, edwards_base, scalar);
			edwards_to_precomp (pc, p);
			os << "   { // " << j << "*16^" << i*2 << "*B\n";
			os << "     ";  write_coeffs (os, pc.ypx);   os << ",\n";
			os << "     ";  write_coeffs (os, pc.ymx);   os << ",\n";
			os << "     ";  write_coeffs (os, pc.xy2d);  os << '\n';
			os << "   }";
			if (j == 8) {
				os << "\n  }";
				if (i != 31) {
					os << ",";
				}
			} else {
				os << ",\n";
			}
		}
	}
	os << "};\n";
}





// If flag == 1 then res = p. If flag == 0 then leave res unchanged. Flag can
// be either 0 or 1, no other values allowed.
inline void select (Precomputed &res, const Precomputed &p, uint32_t flag)
{
	typedef decltype(p.ypx.v[0]) Limbint;
	Limbint liflag = flag;
	Limbint discard = liflag - 1;  // All zero if flag == 1, all 1 if flag == 0
	Limbint keep = ~discard;     // All one if flag == 1, all 0 if flag == 0

	for (int i = 0; i < fecount; ++i) {
		res.ypx.v[i] = (res.ypx.v[i] & discard) | (p.ypx.v[i] & keep);
		res.ymx.v[i] = (res.ymx.v[i] & discard) | (p.ymx.v[i] & keep);
		res.xy2d.v[i] = (res.xy2d.v[i] & discard) | (p.xy2d.v[i] & keep);
	}
}

// Compute the absolute value using bit manipulation.
inline int32_t iabs (int32_t x)
{
	int32_t y = x >> 31;
	int32_t a = (x ^ y) - y;
	return a;
}

// Select the correct multiple and sign. It returns res = smult*16^(i*2)*B
static void compute_multiple (Precomputed &res, int8_t smult, int i)
{
	uint32_t negative = (smult & 0x80) >> 7;    // Only 1 or 0.
	uint32_t mult = iabs (smult);
	res = { feone, feone, fezero };  // Zero element.
	for (int j = 1; j <= 8; ++j) {
		// Load the multiple corresponding to the absolute value.
		select (res, basemult[i][j-1], equal (mult, j));
	}
	// Compute the negative of the multiple.
	Precomputed neg;
	neg.ypx = res.ymx;
	neg.ymx = res.ypx;
	negate (neg.xy2d, res.xy2d);
	// Select the negative one if smult < 0.
	select (res, neg, negative);
}

// This is base_point^2²⁵⁶

#if AMBER_LIMB_BITS == 32
static const Edwards bm = {
	{ 0x23c9847, 0x0b2d5e7, 0x2ddfa9c, 0x02375e9, 0x3cd01b5, 0x1a2738f, 0x09db05c, 0x1105ca3, 0x37ae0ea, 0x08aae4e },
	{ 0x3801e2f, 0x0002e2b, 0x28af68f, 0x14aa073, 0x1938654, 0x009e462, 0x36f9f83, 0x0b0df04, 0x1e39fb5, 0x1f8bade },
	{ 0x2eb300f, 0x0d354d4, 0x18846f0, 0x13cbc39, 0x0913f4f, 0x0c5f5a3, 0x0f41a9c, 0x062db53, 0x036b61a, 0x1789558 },
	{ 0x2f7d68d, 0x098e371, 0x13a0391, 0x041f04c, 0x31931ef, 0x030a46b, 0x38de645, 0x154c5a0, 0x0ac216f, 0x13d7df0 }
};

#else

static const Edwards bm = {
	{ 0x2cb579e3c9847, 0x8dd7a6ddfa9c, 0x689ce3fcd01b5, 0x441728c9db05c, 0x22ab93b7ae0ea },
	{ 0xb8af801e2f, 0x52a81ce8af68f, 0x279189938654, 0x2c37c136f9f83, 0x7e2eb79e39fb5 },
	{ 0x34d5352eb300f, 0x4f2f0e58846f0, 0x317d68c913f4f, 0x18b6d4cf41a9c, 0x5e2556036b61a },
	{ 0x2638dc6f7d68d, 0x107c1313a0391, 0xc291af1931ef, 0x55316838de645, 0x4f5f7c0ac216f }
};
#endif

void scalarbase (Edwards &res, const uint8_t scalar[32])
{
	int8_t sc[64];

	// Store the scalar in sc with 4 bit limbs, taking values between 0 and
	// 15.
	for (int i = 0; i < 32; ++i) {
		sc[2*i]     = scalar[i] & 0xF;
		sc[2*i + 1] = scalar[i] >> 4;
	}

	// Store the scalar in sc with limbs taking values between -8 and +7.
	int8_t carry = 0;
	for (int i = 0; i < 64; ++i) {
		sc[i] += carry;
		// Set carry to 1 if sc[i] >= 8
		carry = (sc[i] + 8) >> 4;
		// Substract 16 if sc[i] >= 8
		sc[i] -= carry << 4;
	}
	// Carry may still be 1 if we have the most significant bit of the scalar
	// set. This does not happen in pure X25519/Ed25519 but we allow scalars
	// of 256 bits. If carry is set we need to add base^2²⁵⁶ at the  end.

	// Now compute res = P0 + 16P1, with P0 = sc₀*16⁰B + sc₂*16²B + sc₄*16⁴B
	// + sc₆*16⁶B + ... + sc₆₂*16⁶²B and P1 = sc₁*16⁰B + sc₃*16²B + sc₅*16⁴B
	// + sc₇*16⁶B + ... + sc₆₃*16⁶²B. Note that we only need to store the
	// multiples of 16^i*B where i is even. Furthermore we just store the
	// positive values. Negative values are treated by obtaining its
	// corresponding positive value and substracting.

	// Set res to carry * base^2²⁵⁶ as the initial value. Using this initial
	// value we do not need to do anything else to support 256 bits.
	res = edzero;
	select (res, bm, carry);

	Edwards res1 = edzero;
	Precomputed tmp;
	for (int i = 0; i < 32; ++i) {
		compute_multiple (tmp, sc[i*2], i);
		point_add (res, res, tmp);
		compute_multiple (tmp, sc[i*2 + 1], i);
		point_add (res1, res1, tmp);
	}
	point_double (res1, res1);  // *2
	point_double (res1, res1);  // *4
	point_double (res1, res1);  // *8
	point_double (res1, res1);  // *16
	point_add (res, res, res1);
}


// Reduce taken from Tweet NaCl.

typedef int32_t Limbtype;

// This is the order of the group in packed form.
static const Limbtype L[32] =  {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0x10
};

// L is 2²⁵² + δ, with δ having 128 bits. Tweet NaCl takes advantage of this
// structure to reduce the upper bytes by substracting a multiple of L. For
// instance to remove the byte at position i, with value x[i] substract
// L*x[i] << (i*8-4). If we proceed from the highest byte to the last bit to
// remove then we remove the upper bits. We may end up with a negative
// number. The last step removes L*carry, with carry being signed.

void modL (uint8_t r[32], Limbtype x[64])
{
	Limbtype carry;
	int i, j;
	// First remove the upper bytes by substracting x[i]*L << (i*8 - 4)
	for (i = 63; i >= 32; --i) {
		carry = 0;
		for (j = i - 32; j < i - 12; ++j) {
			x[j] += carry - 16 * x[i] * L[j - (i - 32)];
			// Keep each limb between -128 and 127.
			carry = (x[j] + 128) >> 8;
			x[j] -= carry << 8;
		}
		x[j] += carry;
		x[i] = 0;
	}
	carry = 0;
	// Remove the upper 4 bits of byte 31.
	for (j = 0; j < 32; ++j) {
		x[j] += carry - (x[31] >> 4) * L[j];
		carry = x[j] >> 8;
		x[j] &= 255;
	}
	// Signed carry. Substract or add L depending on sign of carry.
	for (j = 0; j < 32; ++j) {
		x[j] -= carry * L[j];
	}
	// Reduce the coefficients.
	for (i = 0; i < 32; ++i) {
		x[i+1] += x[i] >> 8;
		r[i] = x[i] & 255;
	}
}



void reduce (uint8_t *dst, const uint8_t src[64])
{
	Limbtype x[64];
	for (unsigned i = 0; i < 64; ++i) {
		x[i] = (uint64_t) src[i];
	}
	modL(dst, x);
}

void reduce32 (uint8_t *dst, const uint8_t src[32])
{
	Limbtype x[64];
	for (int i = 0; i < 32; ++i) {
		x[i] = (uint64_t) src[i];
	}
	for (int i = 32; i < 64; ++i) {
		x[i] = 0;
	}
	modL(dst, x);
}

// End of reduce from Tweet NaCl.



// See
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#w-ary_non
// -adjacent_form_.28wNAF.29_method

// d will contain the coefficients for the addition, so that sP = ΣdᵢPⁱ,
// where dᵢ can take values from -2^(w-1) to +2^(w-1). In addition all dᵢ
// will be odd. At most one dᵢ out of every w values of i will be non zero.

void compute_naf_window (int8_t d[257], const uint8_t s[32], int w = 5)
{
	// Ensure that the last bit is always zero. We accept scalars with all
	// 256 bits set. This is more than what X25519.
	d[256] = 0;
	// First extract the bits so that they can be handled easily.
	for (int i = 0; i < 256; ++i) {
		d[i] = (s[i >> 3] >> (i & 7)) & 1;
	}

	// Half window value.
	int wm1 = 1 << (w-1);
	// Full window value.
	int wm2 = 1 << w;

	for (int i = 0; i < 257; ++i) {
		if (d[i]) {
			// Collect a window's value.
			int collect = d[i];
			int j;
			for (j = 1; j < w && (i + j < 257); ++j) {
				if (d[i + j]) {
					collect += d[i + j] << j;
					d[i + j] = 0;
				}
			}
			// If it is more than half a window value, then use the negative
			// value and increase the rest. We keep flipping bits until we
			// reach a zero bit.
			if (collect >= wm1) {
				int k = i + j;
				// Add 1 after the window.
				while (k < 257) {
					if (d[k]) {
						d[k] = 0;
					} else {
						d[k] = 1;
						break;
					}
					++k;
				}
				// Use the negative value.
				d[i] = collect - wm2;
			} else {
				d[i] = collect;
			}
			i += w - 1;
			// The collected value will always be odd, because we skip zero
			// bits at the beginning.
		}
	}
}

// Variable time res = sB

void scalarmult_wnaf (Edwards &res, const Edwards &p, const uint8_t s[32])
{
	int8_t d[257];
	compute_naf_window (d, s, 5);

	Edwards p2;
	Summand mulp[8];
	edwards_to_summand (mulp[0], p);
	point_double (p2, p);
	for (int i = 1; i < 8; ++i) {
		// mulp[i] = p + i*2*p = { P, 3P, 5P, 7P, 9P, 11P, 13P, 15P }
		point_add (mulp[i], mulp[i-1], p2);
	}

	res = edzero;
	for (int j = 256; j >= 0; --j) {
		point_double (res, res);
		if (d[j] > 0) {
			point_add (res, res, mulp[d[j]/2]);
		} else if (d[j] < 0) {
			point_sub (res, res, mulp[-d[j]/2]);
		}
	}
}



void write_summands (const char *name)
{
	std::ofstream os (name);

	os << "static const Summand base_summands[8] = {\n";

	Edwards res = edwards_base;
	Edwards p2;
	point_double (p2, res);
	for (int i = 0; i < 16; ++i) {
		Summand s;
		edwards_to_summand (s, res);
		os << "  { // " << i*2 + 1 << "B\n";
		os << "    ";  write_coeffs (os, s.ypx);  os << ",\n";
		os << "    ";  write_coeffs (os, s.ymx);  os << ",\n";
		os << "    ";  write_coeffs (os, s.t2d);  os << ",\n";
		os << "    ";  write_coeffs (os, s.z2);  os << "\n";
		os << "  }";
		if (i != 7) os << ",";
		os << "\n";

		point_add (res, res, p2);
	}
	os << "};\n";
}

#if AMBER_LIMB_BITS == 32
// 2560 bytes.
static const Summand base_summands[16] = {
  { // 1B
	{ 0x18c3b85, 0x124f1bd, 0x1c325f7, 0x037dc60, 0x33e4cb7, 0x03d42c2, 0x1a44c32, 0x14ca4e1, 0x3a33d4b, 0x01f3e74 },
	{ 0x340913e, 0x00e4175, 0x3d673a2, 0x02e8a05, 0x3f4e67c, 0x08f8a09, 0x0c21a34, 0x04cf4b8, 0x1298f81, 0x113f4be },
	{ 0x37aaa68, 0x0448161, 0x093d579, 0x11e6556, 0x09b67a0, 0x143598c, 0x1bee5ee, 0x0b50b43, 0x289f0c6, 0x1bc45ed },
	{ 0x0000002, 0x0000000, 0x0000000, 0x0000000, 0x0000000, 0x0000000, 0x0000000, 0x0000000, 0x0000000, 0x0000000 }
  },
  { // 3B
	{ 0x1981549, 0x0d85d3c, 0x200fa59, 0x05f6681, 0x10cdcd2, 0x1d6c016, 0x1fe47ff, 0x1070cb3, 0x248aa08, 0x1c6d965 },
	{ 0x076562d, 0x0cda6be, 0x0a62cf4, 0x192afd2, 0x01f59bb, 0x030038d, 0x2ddecfe, 0x15d44cf, 0x3452d48, 0x1889c86 },
	{ 0x06d9bdb, 0x18c1a98, 0x1d46c22, 0x16f79a2, 0x368649d, 0x1220306, 0x22a6cbf, 0x00890fd, 0x05c80eb, 0x1dc7a9b },
	{ 0x374d3db, 0x1e2cecf, 0x0c9d7e6, 0x0449d52, 0x2c679e0, 0x0480592, 0x20c159a, 0x190ae53, 0x0a10759, 0x08080fa }
  },
  { // 5B
	{ 0x1b6817b, 0x1d9c1ac, 0x36a0d29, 0x0666f67, 0x302e6e7, 0x049b3d8, 0x2e7fcc9, 0x0a69d72, 0x33693b0, 0x16e0998 },
	{ 0x072f49a, 0x0e06ff0, 0x22b130b, 0x16258b5, 0x0d9e37f, 0x1f4f5a6, 0x1616ee0, 0x1613fe9, 0x056fe2a, 0x05d770a },
	{ 0x21137a2, 0x0d31525, 0x04b6018, 0x0215658, 0x011c47a, 0x0cb2501, 0x2b07806, 0x07422d4, 0x20ab451, 0x10f5029 },
	{ 0x002881e, 0x018752f, 0x3e88d71, 0x0471697, 0x0610313, 0x1629c4b, 0x058ff67, 0x1464761, 0x08b95be, 0x1b9e078 }
  },
  { // 7B
	{ 0x31395e9, 0x0050e12, 0x2de17d4, 0x0bea4e8, 0x302676c, 0x05dc8bc, 0x015625d, 0x088bc5a, 0x0a14e92, 0x1093bc3 },
	{ 0x3946a6a, 0x1b326f4, 0x2c47498, 0x0566d66, 0x02e433e, 0x06f5825, 0x29d038a, 0x1419994, 0x15461c0, 0x169333b },
	{ 0x365fcbf, 0x0237d58, 0x1340fec, 0x0801354, 0x06d0e2e, 0x0864448, 0x1d1b5ff, 0x0e8835e, 0x2f3ddfb, 0x18d2e22 },
	{ 0x0a909c6, 0x1fa6b06, 0x220dd0b, 0x046f78f, 0x01eddb0, 0x0fe29c3, 0x38fdc04, 0x1049d3e, 0x1d41bec, 0x1203b71 }
  },
  { // 9B
	{ 0x1eb45e9, 0x06d5820, 0x21e0fa6, 0x0b4d871, 0x0a1eb1b, 0x062b649, 0x03d3cb0, 0x186f3ea, 0x3a741c7, 0x07bbb0c },
	{ 0x1cb4b99, 0x17b0d4b, 0x3f6a36a, 0x1865ec0, 0x2ecab48, 0x01e2577, 0x378ad2d, 0x0067ff8, 0x29b4ded, 0x1481ea8 },
	{ 0x1fa8b23, 0x1c14944, 0x05ba310, 0x12ea82b, 0x27014d7, 0x14da9ed, 0x0154457, 0x0fd84b6, 0x2d1e352, 0x18a99be },
	{ 0x37569c9, 0x0d16876, 0x3c073c8, 0x059240b, 0x0a4dd44, 0x06d3ed6, 0x2689fe1, 0x1d62fc8, 0x28003f1, 0x0ef441e }
  },
  { // 11B
	{ 0x339c1dc, 0x1348af1, 0x1de2507, 0x1134d1a, 0x3bca636, 0x12ebe14, 0x15c910c, 0x14ce3af, 0x392b959, 0x1ed90df },
	{ 0x3b4402c, 0x05656c3, 0x0805465, 0x16b20e9, 0x1c0ea84, 0x1837059, 0x3bd2cf8, 0x1c86dd0, 0x19999f5, 0x16576ad },
	{ 0x01945ba, 0x04e4977, 0x15274fc, 0x16c67d7, 0x152547c, 0x11c5f77, 0x388706a, 0x1ca56af, 0x310f8d1, 0x1b6d29b },
	{ 0x08c3d9b, 0x1455d2e, 0x0548991, 0x152720a, 0x163f474, 0x129fd07, 0x036a0ff, 0x07c63df, 0x252b3ac, 0x07d52e8 }
  },
  { // 13B
	{ 0x27b920f, 0x12bd8d6, 0x3dfd86f, 0x1488b0d, 0x15f4c06, 0x000d7e0, 0x29c416f, 0x1e6cb60, 0x05a90fe, 0x109e2ea },
	{ 0x0a6ee7a, 0x1a08654, 0x3f81bf7, 0x00a045e, 0x10c96c3, 0x13344ed, 0x234bcf7, 0x09e2500, 0x00b0b4e, 0x02d82b3 },
	{ 0x2a59649, 0x0d4c8d0, 0x01da325, 0x1ecf3c5, 0x03627b7, 0x1d84eef, 0x23e79ad, 0x1a052c3, 0x3e3ef4d, 0x0a66bac },
	{ 0x35b0031, 0x161bc0d, 0x14c2044, 0x10b8c49, 0x26503fd, 0x17b56a3, 0x05fc9c4, 0x09c5f44, 0x23952b4, 0x09ef203 }
  },
  { // 15B
	{ 0x0fd4ea3, 0x0e3f79a, 0x114bb85, 0x02ad4db, 0x2b6cc02, 0x15b6dcd, 0x0bda380, 0x1ac033b, 0x3cbd0ef, 0x061f904 },
	{ 0x0c5dcd9, 0x03cbf6c, 0x3977894, 0x0a852e6, 0x3057095, 0x0bce9a4, 0x1f642b7, 0x1124fae, 0x0ca9c9f, 0x156373f },
	{ 0x3af830d, 0x0291b78, 0x291cf49, 0x0802523, 0x2cf4077, 0x00cb4e9, 0x0655923, 0x1203b34, 0x17f5671, 0x012410f },
	{ 0x33d848c, 0x1c09f1c, 0x0ec2b32, 0x1e4555e, 0x25feb09, 0x1a9551a, 0x08e8e61, 0x1878583, 0x003833b, 0x0320a70 }
  },
  { // 17B
	{ 0x2e6c4f2, 0x187bc9e, 0x23762fb, 0x0d0763d, 0x271ff77, 0x0d3b468, 0x2402f51, 0x16daa1e, 0x3bd9523, 0x0f427d6 },
	{ 0x2d7a28d, 0x042e043, 0x27fa852, 0x1620680, 0x321f6b6, 0x0af8af3, 0x1370285, 0x17979db, 0x162e9d8, 0x1ef4321 },
	{ 0x1398b0a, 0x183d2a6, 0x1cc0d8a, 0x0bf97e3, 0x0a69843, 0x196c72e, 0x03dc6ea, 0x05cb3fe, 0x16d757b, 0x0ad21dd },
	{ 0x1cace16, 0x1018d87, 0x0e9c4d2, 0x163f765, 0x1c5fd2a, 0x1a718f9, 0x320d72d, 0x1f0ba62, 0x19f73fe, 0x0b598bd }
  },
  { // 19B
	{ 0x25f10c1, 0x1c9306f, 0x0bc647d, 0x13b3773, 0x18a661f, 0x063e030, 0x2731b1b, 0x1fc9fe9, 0x345bb10, 0x01472d9 },
	{ 0x0df9c6a, 0x147a6fe, 0x1771c29, 0x0734ed3, 0x16223d8, 0x19918cc, 0x365bd3d, 0x0351bbc, 0x29dc6c7, 0x0914330 },
	{ 0x0b712f3, 0x103a2ea, 0x24ff6ff, 0x1921703, 0x341de64, 0x173fb66, 0x04a3c02, 0x040124d, 0x2c138af, 0x14024d2 },
	{ 0x2a7e09b, 0x0576804, 0x09ab9a0, 0x16ca9ff, 0x0800d31, 0x1935429, 0x0106628, 0x05a1a4b, 0x31423f7, 0x0677026 }
  },
  { // 21B
	{ 0x27e1c83, 0x1b39c21, 0x134a00a, 0x1d88319, 0x23c2700, 0x1de2282, 0x3a0dd81, 0x15a82c1, 0x0d1602b, 0x165c7b0 },
	{ 0x02c5b51, 0x01d9136, 0x060b2a7, 0x1137e33, 0x37b5a39, 0x09a9dd7, 0x03291dd, 0x19a0cb2, 0x0ab0912, 0x1560840 },
	{ 0x2a1a7fe, 0x082c692, 0x11515bb, 0x0a27edc, 0x209b0b1, 0x0cc3dd6, 0x0563ced, 0x18fe361, 0x15583f7, 0x0e1ee52 },
	{ 0x3b82f0a, 0x0933680, 0x0a09b6f, 0x01b83d5, 0x0d00afc, 0x059a435, 0x25705f4, 0x0d21064, 0x27e6a32, 0x1e6c7b8 }
  },
  { // 23B
	{ 0x2345cfa, 0x04f13d9, 0x1f74ed5, 0x0cf6953, 0x04d5bf3, 0x037d4f7, 0x0ec4189, 0x18a49b8, 0x39d15ee, 0x16d1896 },
	{ 0x00b1e70, 0x1790b89, 0x1a24bd0, 0x1f1dc17, 0x1c8effd, 0x005bd19, 0x046bc47, 0x0474daf, 0x1b796e5, 0x0030467 },
	{ 0x12184c2, 0x0d461d4, 0x3e46290, 0x0b53fcc, 0x192956a, 0x19001a4, 0x32a50d3, 0x1d95ff2, 0x1b4c404, 0x070ee01 },
	{ 0x15550f2, 0x16db2d5, 0x315d06c, 0x160eceb, 0x16a482a, 0x15af9e1, 0x0510a0d, 0x188c996, 0x1630eb9, 0x0d2c013 }
  },
  { // 25B
	{ 0x20d0388, 0x01cb9bd, 0x3a43bc4, 0x15ea6b7, 0x1d66905, 0x05fcb6d, 0x3ca5fbd, 0x164f0d4, 0x04b9259, 0x11303c8 },
	{ 0x04efc10, 0x0d9c406, 0x223b0bf, 0x1ffff00, 0x24fb34d, 0x15ef596, 0x1912729, 0x05708fb, 0x0b44a5d, 0x12d37b7 },
	{ 0x3e1b1c0, 0x032a28b, 0x00039ce, 0x176a832, 0x32b5d9d, 0x1e11070, 0x1aba81f, 0x04569c1, 0x014bcc6, 0x1505eb4 },
	{ 0x3682397, 0x147e5c3, 0x1d84a1a, 0x11a2db0, 0x3328e72, 0x19213d8, 0x1654fdb, 0x17d3d34, 0x29cc2bb, 0x03f6982 }
  },
  { // 27B
	{ 0x228d6ba, 0x0f428fc, 0x13a662a, 0x0e6e708, 0x0304b54, 0x0694cc8, 0x35f94cc, 0x03e7c0c, 0x23eba65, 0x196226a },
	{ 0x0eb205c, 0x09e1d61, 0x1bc72d4, 0x0fb37ee, 0x0e5baa6, 0x1461091, 0x01e70fe, 0x1f7e7ad, 0x2e10421, 0x0935681 },
	{ 0x07e5489, 0x1a06b47, 0x0b91a46, 0x091814e, 0x0c50e5b, 0x153e903, 0x18245c7, 0x18c78c1, 0x336bf7d, 0x0c3e3ba },
	{ 0x13b6083, 0x0450752, 0x174bc5f, 0x17b78d9, 0x2205587, 0x1e63ee3, 0x0b1b7b9, 0x0fa32f8, 0x3cde659, 0x04f0ad4 }
  },
  { // 29B
	{ 0x3796035, 0x1fea23a, 0x369929a, 0x16a3ec3, 0x19af326, 0x0ae9778, 0x3380789, 0x1a3c035, 0x1688341, 0x13c56b9 },
	{ 0x1b58f71, 0x1150396, 0x3114fac, 0x0b0fb9d, 0x096de78, 0x093fb8b, 0x169b48f, 0x0f70899, 0x0dc4315, 0x02b08d9 },
	{ 0x10bc87d, 0x096b511, 0x06848bd, 0x04a20a3, 0x2aa2bb9, 0x1f648c2, 0x0ada667, 0x0ea1d89, 0x1919aaa, 0x12d471c },
	{ 0x026e313, 0x020a855, 0x164494d, 0x06eb494, 0x1afa851, 0x0396bd7, 0x1c0a3ff, 0x1a15803, 0x1eecdad, 0x12b3f30 }
  },
  { // 31B
	{ 0x2cf97a8, 0x10aa713, 0x21627d6, 0x19deea5, 0x150daa3, 0x02a72b1, 0x2c576f1, 0x0fffb22, 0x3560f32, 0x04a3839 },
	{ 0x149528c, 0x10c3d85, 0x2ca4faa, 0x0c9df60, 0x2070345, 0x1f54ed7, 0x1b862a6, 0x07ff1fb, 0x1545d50, 0x16515ac },
	{ 0x03f69a7, 0x18985a7, 0x26798a1, 0x0a0c94b, 0x2f441d2, 0x00c20bd, 0x1338546, 0x1eefec3, 0x2e342c1, 0x07ba962 },
	{ 0x17e904e, 0x0373558, 0x24b5ef7, 0x1b02dab, 0x209de20, 0x07f764c, 0x2f34f8e, 0x1498f7e, 0x2c05e75, 0x12dd8fa }
  }
};

#elif AMBER_LIMB_BITS >= 64
static const Summand base_summands[16] = {
  { // 1B
	{ 0x493c6f58c3b85, 0xdf7181c325f7, 0xf50b0b3e4cb7, 0x5329385a44c32, 0x7cf9d3a33d4b,  },
	{ 0x3905d740913e, 0xba2817d673a2, 0x23e2827f4e67c, 0x133d2e0c21a34, 0x44fd2f9298f81,  },
	{ 0x11205877aaa68, 0x479955893d579, 0x50d66309b67a0, 0x2d42d0dbee5ee, 0x6f117b689f0c6,  },
	{ 0x0000002, 0x0000000, 0x0000000, 0x0000000, 0x0000000,  }
  },
  { // 3B
	{ 0x36174f1981549, 0x17d9a0600fa59, 0x75b00590cdcd2, 0x41c32cdfe47ff, 0x71b659648aa08,  },
	{ 0x3369af876562d, 0x64abf48a62cf4, 0xc00e341f59bb, 0x575133eddecfe, 0x622721b452d48,  },
	{ 0x6306a606d9bdb, 0x5bde689d46c22, 0x4880c1b68649d, 0x2243f62a6cbf, 0x771ea6c5c80eb,  },
	{ 0x78b3b3f74d3db, 0x1127548c9d7e6, 0x120164ac679e0, 0x642b94e0c159a, 0x20203e8a10759,  }
  },
  { // 5B
	{ 0x76706b1b6817b, 0x199bd9f6a0d29, 0x126cf6302e6e7, 0x29a75cae7fcc9, 0x5b826633693b0,  },
	{ 0x381bfc072f49a, 0x58962d62b130b, 0x7d3d698d9e37f, 0x584ffa5616ee0, 0x175dc2856fe2a,  },
	{ 0x34c54961137a2, 0x8559604b6018, 0x32c940411c47a, 0x1d08b52b07806, 0x43d40a60ab451,  },
	{ 0x61d4bc02881e, 0x11c5a5fe88d71, 0x58a712c610313, 0x5191d8458ff67, 0x6e781e08b95be,  }
  },
  { // 7B
	{ 0x14384b1395e9, 0x2fa93a2de17d4, 0x17722f302676c, 0x222f16815625d, 0x424ef0ca14e92,  },
	{ 0x6cc9bd3946a6a, 0x159b59ac47498, 0x1bd60942e433e, 0x50666529d038a, 0x5a4cced5461c0,  },
	{ 0x8df56365fcbf, 0x2004d51340fec, 0x21911206d0e2e, 0x3a20d79d1b5ff, 0x634b88af3ddfb,  },
	{ 0x7e9ac18a909c6, 0x11bde3e20dd0b, 0x3f8a70c1eddb0, 0x41274fb8fdc04, 0x480edc5d41bec,  }
  },
  { // 9B
	{ 0x1b56081eb45e9, 0x2d361c61e0fa6, 0x18ad924a1eb1b, 0x61bcfa83d3cb0, 0x1eeec33a741c7,  },
	{ 0x5ec352dcb4b99, 0x6197b03f6a36a, 0x7895deecab48, 0x19ffe378ad2d, 0x5207aa29b4ded,  },
	{ 0x7052511fa8b23, 0x4baa0ac5ba310, 0x536a7b67014d7, 0x3f612d8154457, 0x62a66fad1e352,  },
	{ 0x345a1db7569c9, 0x164902fc073c8, 0x1b4fb58a4dd44, 0x758bf22689fe1, 0x3bd107a8003f1,  }
  },
  { // 11B
	{ 0x4d22bc739c1dc, 0x44d3469de2507, 0x4baf853bca636, 0x5338ebd5c910c, 0x7b6437f92b959,  },
	{ 0x1595b0fb4402c, 0x5ac83a4805465, 0x60dc165c0ea84, 0x721b743bd2cf8, 0x595dab59999f5,  },
	{ 0x13925dc1945ba, 0x5b19f5d5274fc, 0x4717ddd52547c, 0x7295abf88706a, 0x6db4a6f10f8d1,  },
	{ 0x51574b88c3d9b, 0x549c828548991, 0x4a7f41d63f474, 0x1f18f7c36a0ff, 0x1f54ba252b3ac,  }
  },
  { // 13B
	{ 0x4af635a7b920f, 0x5222c37dfd86f, 0x35f815f4c06, 0x79b2d829c416f, 0x4278ba85a90fe,  },
	{ 0x6821950a6ee7a, 0x28117bf81bf7, 0x4cd13b50c96c3, 0x278940234bcf7, 0xb60acc0b0b4e,  },
	{ 0x3532342a59649, 0x7b3cf141da325, 0x7613bbc3627b7, 0x6814b0e3e79ad, 0x299aeb3e3ef4d,  },
	{ 0x586f0375b0031, 0x42e31254c2044, 0x5ed5a8e6503fd, 0x2717d105fc9c4, 0x27bc80e3952b4,  }
  },
  { // 15B
	{ 0x38fde68fd4ea3, 0xab536d14bb85, 0x56db736b6cc02, 0x6b00cecbda380, 0x187e413cbd0ef,  },
	{ 0xf2fdb0c5dcd9, 0x2a14b9b977894, 0x2f3a693057095, 0x4493eb9f642b7, 0x558dcfcca9c9f,  },
	{ 0xa46de3af830d, 0x200948e91cf49, 0x32d3a6cf4077, 0x480ecd0655923, 0x49043d7f5671,  },
	{ 0x7027c733d848c, 0x7915578ec2b32, 0x6a5546a5feb09, 0x61e160c8e8e61, 0xc829c003833b,  }
  },
  { // 17B
	{ 0x61ef27ae6c4f2, 0x341d8f63762fb, 0x34ed1a271ff77, 0x5b6a87a402f51, 0x3d09f5bbd9523,  },
	{ 0x10b810ed7a28d, 0x5881a027fa852, 0x2be2bcf21f6b6, 0x5e5e76d370285, 0x7bd0c8562e9d8,  },
	{ 0x60f4a99398b0a, 0x2fe5f8dcc0d8a, 0x65b1cb8a69843, 0x172cff83dc6ea, 0x2b487756d757b,  },
	{ 0x406361dcace16, 0x58fdd94e9c4d2, 0x69c63e5c5fd2a, 0x7c2e98b20d72d, 0x2d662f59f73fe,  }
  },
  { // 19B
	{ 0x724c1be5f10c1, 0x4ecddccbc647d, 0x18f80c18a661f, 0x7f27fa6731b1b, 0x51cb6745bb10,  },
	{ 0x51e9bf8df9c6a, 0x1cd3b4d771c29, 0x66463316223d8, 0xd46ef365bd3d, 0x2450cc29dc6c7,  },
	{ 0x40e8ba8b712f3, 0x6485c0e4ff6ff, 0x5cfed9b41de64, 0x10049344a3c02, 0x500934ac138af,  },
	{ 0x15da012a7e09b, 0x5b2a7fc9ab9a0, 0x64d50a4800d31, 0x168692c106628, 0x19dc09b1423f7,  }
  },
  { // 21B
	{ 0x6ce70867e1c83, 0x7620c6534a00a, 0x7788a0a3c2700, 0x56a0b07a0dd81, 0x5971ec0d1602b,  },
	{ 0x7644d82c5b51, 0x44df8cc60b2a7, 0x26a775f7b5a39, 0x66832c83291dd, 0x5582100ab0912,  },
	{ 0x20b1a4aa1a7fe, 0x289fb711515bb, 0x330f75a09b0b1, 0x63f8d84563ced, 0x387b9495583f7,  },
	{ 0x24cda03b82f0a, 0x6e0f54a09b6f, 0x16690d4d00afc, 0x34841925705f4, 0x79b1ee27e6a32,  }
  },
  { // 23B
	{ 0x13c4f66345cfa, 0x33da54df74ed5, 0xdf53dc4d5bf3, 0x62926e0ec4189, 0x5b4625b9d15ee,  },
	{ 0x5e42e240b1e70, 0x7c7705da24bd0, 0x16f465c8effd, 0x11d36bc46bc47, 0xc119db796e5,  },
	{ 0x35187512184c2, 0x2d4ff33e46290, 0x640069192956a, 0x7657fcb2a50d3, 0x1c3b805b4c404,  },
	{ 0x5b6cb555550f2, 0x583b3af15d06c, 0x56be7856a482a, 0x6232658510a0d, 0x34b004d630eb9,  }
  },
  { // 25B
	{ 0x72e6f60d0388, 0x57a9adfa43bc4, 0x17f2db5d66905, 0x593c353ca5fbd, 0x44c0f204b9259,  },
	{ 0x36710184efc10, 0x7fffc0223b0bf, 0x57bd65a4fb34d, 0x15c23ed912729, 0x4b4dedcb44a5d,  },
	{ 0xca8a2fe1b1c0, 0x5daa0c80039ce, 0x78441c32b5d9d, 0x115a705aba81f, 0x5417ad014bcc6,  },
	{ 0x51f970f682397, 0x468b6c1d84a1a, 0x6484f63328e72, 0x5f4f4d1654fdb, 0xfda60a9cc2bb,  }
  },
  { // 27B
	{ 0x3d0a3f228d6ba, 0x39b9c213a662a, 0x1a53320304b54, 0xf9f0335f94cc, 0x65889aa3eba65,  },
	{ 0x2787584eb205c, 0x3ecdfb9bc72d4, 0x5184244e5baa6, 0x7df9eb41e70fe, 0x24d5a06e10421,  },
	{ 0x681ad1c7e5489, 0x2460538b91a46, 0x54fa40cc50e5b, 0x631e3058245c7, 0x30f8eeb36bf7d,  },
	{ 0x1141d493b6083, 0x5ede36574bc5f, 0x798fb8e205587, 0x3e8cbe0b1b7b9, 0x13c2b53cde659,  }
  },
  { // 29B
	{ 0x7fa88eb796035, 0x5a8fb0f69929a, 0x2ba5de19af326, 0x68f00d7380789, 0x4f15ae5688341,  },
	{ 0x4540e59b58f71, 0x2c3ee77114fac, 0x24fee2c96de78, 0x3dc226569b48f, 0xac2364dc4315,  },
	{ 0x25ad4450bc87d, 0x128828c6848bd, 0x7d9230aaa2bb9, 0x3a87624ada667, 0x4b51c71919aaa,  },
	{ 0x82a15426e313, 0x1bad25164494d, 0xe5af5dafa851, 0x685600dc0a3ff, 0x4acfcc1eecdad,  }
  },
  { // 31B
	{ 0x42a9c4ecf97a8, 0x677ba961627d6, 0xa9cac550daa3, 0x3ffec8ac576f1, 0x128e0e7560f32,  },
	{ 0x430f61549528c, 0x3277d82ca4faa, 0x7d53b5e070345, 0x1ffc7edb862a6, 0x59456b1545d50,  },
	{ 0x626169c3f69a7, 0x283252e6798a1, 0x3082f6f441d2, 0x7bbfb0d338546, 0x1eea58ae342c1,  },
	{ 0xdcd5617e904e, 0x6c0b6ae4b5ef7, 0x1fdd93209de20, 0x5263dfaf34f8e, 0x4b763eac05e75,  }
  }
};
#endif


// Variable time res = s1*B + s2*P, where B is the base point.

void scalarmult_wnaf (Edwards &res, const uint8_t s1[32],
                      const Edwards &p, const uint8_t s2[32])
{
	int8_t d1[257], d2[257];
	compute_naf_window (d1, s1, 6);
	compute_naf_window (d2, s2, 5);

	Edwards p2;
	Summand mulp[8];
	edwards_to_summand (mulp[0], p);
	point_double (p2, p);
	for (int i = 1; i < 8; ++i) {
		point_add (mulp[i], mulp[i-1], p2);
	}

	res = edzero;
	for (int j = 256; j >= 0; --j) {
		point_double (res, res);
		if (d1[j] > 0) {
			point_add (res, res, base_summands[d1[j]/2]);
		} else if (d1[j] < 0) {
			point_sub (res, res, base_summands[-d1[j]/2]);
		}
		if (d2[j] > 0) {
			point_add (res, res, mulp[d2[j]/2]);
		} else if (d2[j] < 0) {
			point_sub (res, res, mulp[-d2[j]/2]);
		}
	}
}





// In the normal Ed25519: {seckey,r1} = hash(seed). We communicate R=rB,
// where r = hash(r1, msg). If Eve wants to go from R to seckey she will
// have to reverse a scalar multiplication and two hashes. We use r1 =
// hash(seckey). In our scheme Eve also has to reverse a scalar
// multiplication and two hashes.

// We follow RFC 8032 and Keccak and allow a context prefix for the hash
// function. This transforms the hash function H(X) into H(prefix||X). We
// store both R and A as Montgomery u with Edwards sign bit. The sign bit of
// A is also stored as the most significant bit of the signature.

void sign_bmx (const char *prefix, const uint8_t *m, size_t mlen,
               const uint8_t A[32], const uint8_t scalar[32], uint8_t sig[64])
{
	uint8_t hr[64], r[32], hram[64], rhram[32];

	blake2b (hr, 32, scalar, 32, NULL, 0);

	size_t plen;
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		plen = strlen (prefix) + 1;
		blake2b_update (&bs, prefix, plen); // Include the terminating null.
	}
	blake2b_update (&bs, hr, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hr);
	reduce (r, hr);

	// R = rB
	Edwards R;
	scalarbase (R, r);
	edwards_to_mxs (sig, R);

	// rhram = H(R,A,m)
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, A, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);
	reduce (rhram, hram);

	// x = r + H(RAM)a
	Limbtype x[64];
	for (unsigned i = 0; i < 32; ++i) {
		x[i] = (Limbtype) r[i];
	}
	for (unsigned i = 32; i < 64; ++i) {
		x[i] = 0;
	}
	for (unsigned i = 0; i < 32; ++i) {
		for (unsigned j = 0; j < 32; ++j) {
			x[i+j] += rhram[i] * (Limbtype) scalar[j];
		}
	}

	// S = (r + H(RAM)a) mod L
	modL (sig + 32, x);
	// Store the sign bit.
	sig[63] |= A[31] & 0x80;
}




// Order of the group.
static const uint8_t order[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};


// Verify the signature. The most significant bit of the signature is ored
// with the most significant bit of mx before verifying.
int verify_bmx (const char *prefix, const uint8_t *m, size_t mlen,
                const uint8_t sig[64], const uint8_t mx[32])
{
	uint8_t s[32];
	memcpy (s, sig + 32, 32);
	s[31] &= 0x7F;

	uint8_t mxs[32];
	memcpy (mxs, mx, 32);
	mxs[31] |= sig[63] & 0x80;


	// Do not allow values of S bigger than the order. Avoids malleability.
	if (!gt_than (order, s)) {
		return -1;
	}

	Edwards p;
	// p = - mx
	if (mxs_to_edwards (p, mxs, true) != 0) {
		return -1;
	}

	uint8_t hram[64];
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		size_t n = strlen (prefix);
		blake2b_update (&bs, prefix, n + 1);    // Include terminating null to establish a unique prefix.
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, mxs, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	Edwards newr;
	// R = SB - hA
	scalarmult_wnaf (newr, s, p, rhram);
	uint8_t newrp[32];
	edwards_to_mxs (newrp, newr);
	return crypto_neq (sig, newrp, 32);
}


void ed25519_seed_to_scalar (uint8_t scalar[32], const uint8_t seed[32])
{
	uint8_t scalar_r[64];
	sha512 (seed, 32, scalar_r);
	memcpy (scalar, scalar_r, 32);
	mask_scalar (scalar);
}


void sign_sey (const uint8_t *m, size_t mlen,
               const uint8_t A[32], const uint8_t seed[32], uint8_t sig[64])
{
	uint8_t hr[64], r[32], hram[64], rhram[32];
	uint8_t scalar_r[64];
	Sha512 hs;

	// Take the seed and compute the scalar and the hash prefix.
	hs.update (seed, 32);
	hs.final (scalar_r);
	mask_scalar (scalar_r);

	hs.reset();
	hs.update (scalar_r + 32, 32);
	hs.update (m, mlen);
	hs.final (hr);
	reduce (r, hr);

	// R = rB
	Edwards R;
	scalarbase (R, r);
	edwards_to_eys (sig, R);

	// rhram = H(R,A,m)
	hs.reset();
	hs.update (sig, 32);
	hs.update (A, 32);
	hs.update (m, mlen);
	hs.final (hram);
	reduce (rhram, hram);

	// x = r + H(RAM)a
	Limbtype x[64];
	for (unsigned i = 0; i < 32; ++i) {
		x[i] = (Limbtype) r[i];
	}
	for (unsigned i = 32; i < 64; ++i) {
		x[i] = 0;
	}

	for (unsigned i = 0; i < 32; ++i) {
		for (unsigned j = 0; j < 32; ++j) {
			x[i+j] += rhram[i] * (Limbtype) scalar_r[j];
		}
	}
	// S = (r + H(RAM)a) mod L
	modL (sig + 32, x);
}


int verify_sey (const uint8_t *m, size_t mlen, const uint8_t sig[64],
                const uint8_t A[32])
{
	if (!gt_than (order, sig + 32)) {
		return -1;
	}

	Edwards p;
	if (eys_to_edwards (p, A, true) != 0) {
		return -1;
	}

	uint8_t hram[64];
	Sha512 hs;
	hs.update (sig, 32);
	hs.update (A, 32);
	hs.update (m, mlen);
	hs.final (hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	Edwards newr;
	scalarmult_wnaf (newr, sig + 32, p, rhram);
	uint8_t newrp[32];
	edwards_to_eys (newrp, newr);
	return crypto_neq (sig, newrp, 32);
}


void ed25519_seed_to_ey (uint8_t ey[32], const uint8_t seed[32])
{
	uint8_t h[64];
	sha512 (seed, 32, h);
	mask_scalar (h);
	Edwards e;
	scalarbase (e, h);
	edwards_to_eys (ey, e);
}



// L - 1.
static const uint8_t L1[32] = { 0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12,
                                 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                                 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0x10};

// Compute negx = - x mod m. This is the same as computing negx = (m-1)*x mod
// = (m*x - x) mod m = m*x mod m - x mod m. But m*x mod m = 0. So multiplying
// by m-1 mod m is the same as negating.

void negate_scalar (uint8_t negx[32], const uint8_t x[32])
{
	Limbtype r[64];
	for (unsigned i = 0; i < 64; ++i) {
		r[i] = 0;
	}

	for (unsigned i = 0; i < 32; ++i) {
		for (unsigned j = 0; j < 32; ++j) {
			r[i+j] += x[i] * (Limbtype) L1[j];
		}
	}
	modL (negx, r);
}


void sign_sha (const uint8_t *m, size_t mlen, const uint8_t A[32],
               const uint8_t scalar[32], uint8_t sig[64])
{
	uint8_t hr[64], r[32], hram[64], rhram[32];
	uint8_t prefix[64];
	// Take the seed and compute the scalar and the hash prefix.
	sha512 (scalar, 32, prefix);

	Sha512 hs;
	hs.update (prefix, 32);
	hs.update (m, mlen);
	hs.final (hr);
	reduce (r, hr);

	// R = rB
	Edwards R;
	scalarbase (R, r);
	edwards_to_eys (sig, R);

	// rhram = H(R,A,m)
	hs.reset();
	hs.update (sig, 32);
	hs.update (A, 32);
	hs.update (m, mlen);
	hs.final (hram);
	reduce (rhram, hram);

	// x = r + H(RAM)a
	Limbtype x[64];
	for (unsigned i = 0; i < 32; ++i) {
		x[i] = (Limbtype) r[i];
	}
	for (unsigned i = 32; i < 64; ++i) {
		x[i] = 0;
	}

	for (unsigned i = 0; i < 32; ++i) {
		for (unsigned j = 0; j < 32; ++j) {
			x[i+j] += rhram[i] * (Limbtype) scalar[j];
		}
	}
	// S = (r + H(RAM)a) mod L
	modL (sig + 32, x);
}




// Pass as input xs, filled with random bytes. The function will adjust xs
// and will compute xp and the corresponding representative.

void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Mon *xp, Cu25519Ell *rep)
{
	mask_scalar (xs->b);
	Edwards e;
	Fe fr, fmx;
	xs->b[0] -= 8;
	// Keep trying until we find a point which has a representative.
	do {
		increment (xs->b);
		scalarbase (e, xs->b);
	} while (elligator2_p2r (fr, fmx, e) != 0);

	reduce_store (rep->b, fr);
	reduce_store (xp->b, fmx);

	// The representative point has been selected to be fr < (p-1)/2. It fits
	// in 253 bits. Therefore the top most bits of the representative will be
	// zero. We must fill them with two random bits in order to make them
	// indistinguishable from random.
	uint8_t b;
	randombytes_buf (&b, 1);
	rep->b[31] |= b & 0xC0;
}


void cu25519_elligator2_rev (Cu25519Mon *u, const Cu25519Ell & rep)
{
	Fe fr, fu;
	load (fr, rep.b);

	// Ignore the last bit of fr. Load already discards bit 254. We must also
	// discard bit 253 because r < (p-1)/2 and the top two bits had been
	// filled with random bits.
#if AMBER_LIMB_BITS == 32
	fr.v[9] &= (1 << 24) - 1;
#elif AMBER_LIMB_BITS >= 64
	fr.v[4] &= (1ULL << 50) - 1;
#endif

	elligator2_r2u (fu, fr);
	reduce_store (u->b, fu);

}


// Same as Ed25519 sign but R is encoded as the Montgomery u.

void curvesig (const char *prefix, const uint8_t *m, size_t mlen,
               const uint8_t A[32], const uint8_t scalar[32], uint8_t sig[64])
{
	uint8_t hr[64], r[32], hram[64], rhram[32];

	blake2b (hr, 32, scalar, 32, NULL, 0);

	size_t plen;
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		plen = strlen (prefix) + 1;
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, hr, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hr);
	reduce (r, hr);

	// R = rB
	Edwards p;
	scalarbase (p, r);
	Fe fu, fz;
	add (fu, p.y, p.z);
	sub (fz, p.z, p.y);
	invert (fz, fz);
	mul (fu, fu, fz);
	reduce_store (sig, fu);

	// rhram = H(R,A,m)
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, A, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);
	reduce (rhram, hram);

	// x = r + H(RAM)a
	Limbtype x[64];
	for (unsigned i = 0; i < 32; ++i) {
		x[i] = (Limbtype) r[i];
	}
	for (unsigned i = 32; i < 64; ++i) {
		x[i] = 0;
	}
	for (unsigned i = 0; i < 32; ++i) {
		for (unsigned j = 0; j < 32; ++j) {
			x[i+j] += rhram[i] * (Limbtype) scalar[j];
		}
	}

	// S = (r + H(RAM)a) mod L
	modL (sig + 32, x);
}

// Verify without Edwards arithmetic. See the paper "Fast and compact
// elliptic curve cryptography" for a method to verify signatures without
// performing point addition (see the appendix). We want to verify that
/*            P1 = ±P2 ± P3   */
// where the affine coordinates are u1, u2 and u3 and the projective
// coordinates of P2 and P3 are U2/Z2, U3/Z3. The condition is:
/*
	4(u1 + u2 + u3 + A)(u1u2u3) = (1 - u1u2 - u2u3 - u3u1)²
	4 (U1.Z2.Z3 + U2.Z1.Z3 + U3.Z1.Z2 + A.Z1.Z2.Z3) (U1.U2.U3) = (Z1.Z2.Z3 - U1.U2.Z3 - U2.U3.Z1 - U3.U1.Z2)²

	given that Z1 == 1.

	4 (U1.Z2.Z3 + U2.Z3 + U3.Z2 + A.Z2.Z3) (U1.U2.U3) = (Z2.Z3 - U1.U2.Z3 - U2.U3 - U3.U1.Z2)²

	This scheme is also known as qDSA.
*/

int curverify_mont (const char *prefix, const uint8_t *m, size_t mlen,
                    const uint8_t sig[64], const uint8_t mx[32])
{
	if (!gt_than (order, sig + 32)) {
		return -1;
	}

	uint8_t hram[64];
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	size_t plen;
	if (prefix != NULL) {
		plen = strlen (prefix) + 1;
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, mx, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	// R == ±SB ± hA
	Fe fu1, fu2, fz2, fu3, fz3;
	Fe tmp, s1, s2, femx;
	static const Fe ubase = { 9 };
	montgomery_ladder (fu2, fz2, ubase, sig + 32);
	load (femx, mx);
	montgomery_ladder (fu3, fz3, femx, rhram);
	load (fu1, sig);

	// We have computed sB and hA, which are in fu2/fz2 and fu3/fz3. Check if
	// R == ±SB ± hA

	Fe z2z3, u3z2, u1u2;
	mul (z2z3, fz2, fz3);
	mul (s1, z2z3, fu1);
	mul (tmp, fu2, fz3);            add (s1, s1, tmp);
	mul (u3z2, fu3, fz2);           add (s1, s1, u3z2);
	mul_small (tmp, z2z3, 486662);  add (s1, s1, tmp);
	mul (u1u2, fu1, fu2);
	mul (s1, s1, u1u2);
	mul (s1, s1, fu3);
	mul_small (s1, s1, 4);

	mul (s2, u1u2, fz3);
	mul (tmp, fu2, fu3);
	add (s2, s2, tmp);
	mul (tmp, u3z2, fu1);
	add (s2, s2, tmp);
	sub (s2, z2z3, s2);
	square (s2, s2);

	sub (s1, s1, s2);

	uint8_t res[32];
	reduce_store (res, s1);

	return !is_zero (res, 32);
}

int curverify (const char *prefix, const uint8_t *m, size_t mlen,
               const uint8_t sig[64], const uint8_t mx[32])
{
	if (!gt_than (order, sig + 32)) {
		return -1;
	}

	uint8_t hram[64];
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	size_t plen;
	if (prefix != NULL) {
		plen = strlen (prefix) + 1;
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, mx, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	// R == ±SB ± hA
	Fe fu1, fu2, fz2, fu3, fz3;
	Fe tmp, s1, s2, femx;
	Edwards sB;
	scalarbase (sB, sig + 32);
	// u = (Z + Y)/(Z - Y)
	add (fu2, sB.z, sB.y);
	sub (fz2, sB.z, sB.y);
	load (femx, mx);
	montgomery_ladder (fu3, fz3, femx, rhram);
	load (fu1, sig);

	// We have computed sB and hA, which are in fu2/fz2 and fu3/fz3. Check if
	// R == ±SB ± hA

	Fe z2z3, u3z2, u1u2;
	mul (z2z3, fz2, fz3);
	mul (s1, z2z3, fu1);
	mul (tmp, fu2, fz3);            add (s1, s1, tmp);
	mul (u3z2, fu3, fz2);           add (s1, s1, u3z2);
	mul_small (tmp, z2z3, 486662);  add (s1, s1, tmp);
	mul (u1u2, fu1, fu2);
	mul (s1, s1, u1u2);
	mul (s1, s1, fu3);
	mul_small (s1, s1, 4);

	mul (s2, u1u2, fz3);
	mul (tmp, fu2, fu3);
	add (s2, s2, tmp);
	mul (tmp, u3z2, fu1);
	add (s2, s2, tmp);
	sub (s2, z2z3, s2);
	square (s2, s2);

	sub (s1, s1, s2);

	uint8_t res[32];
	reduce_store (res, s1);

	return !is_zero (res, 32);
}


void cu25519_generate (Cu25519Sec *xs, Cu25519Mon *xp)
{
	Edwards e;
	mask_scalar (xs->b);
	scalarbase (e, xs->b);
	edwards_to_mxs (xp->b, e);
}

void cu25519_generate (Cu25519Pair *pair)
{
	Edwards e;
	mask_scalar (pair->xs.b);
	scalarbase (e, pair->xs.b);
	edwards_to_ristretto (pair->xp.b, e);
}


// Ristretto support.

inline int ct_is_negative (const Fe &u)
{
	Fe v = u;
	uint8_t d[32];
	reduce_store (d, v);
	return d[0] & 1;
}

void edwards_to_ristretto (uint8_t s[32], const Edwards p)
{
	Fe u1, u2, isr;
	add (u1, p.z, p.y);
	sub (u2, p.z, p.y);
	mul (u1, u1, u2);
	mul (u2, p.x, p.y);

	square (isr, u2);
	mul (isr, isr, u1);
	invsqrt (isr, isr);

	Fe den1, den2, z_inv;
	mul (den1, isr, u1);
	mul (den2, isr, u2);
	mul (z_inv, den1, den2);
	mul (z_inv, z_inv, p.t);

	Fe ix0, iy0;
	mul (ix0, p.x, root_minus_1);
	mul (iy0, p.y, root_minus_1);

	Fe enden;
	mul (enden, den1, invsqrt_a_minus_d);

	Fe tmp;
	mul (tmp, p.t, z_inv);
	int rotate = ct_is_negative (tmp);
	Fe x, y, z;
	select (x, iy0, p.x, rotate);
	select (y, ix0, p.y, rotate);
	z = p.z;

	Fe den_inv;
	select (den_inv, enden, den2, rotate);

	mul (tmp, x, z_inv);
	int isneg = ct_is_negative (tmp);
	negate (tmp, y);
	select (y, tmp, y, isneg);

	sub (tmp, z, y);
	Fe spos, sneg;
	mul (spos, tmp, den_inv);
	negate (sneg, spos);
	select (spos, sneg, spos, ct_is_negative (spos));

	reduce_store (s, spos);
}

int ristretto_to_edwards (Edwards &res, const uint8_t sc[32])
{
	Fe s, ss, u1, u2, u2_sqr, v;
	load (s, sc);

	square (ss, s);
	sub (u1, feone, ss);
	add (u2, feone, ss);
	square (u2_sqr, u2);

	square (v, u1);
	mul (v, v, edwards_d);
	add (v, v, u2_sqr);
	negate (v, v);

	Fe insrt, vu22;
	mul (vu22, v, u2_sqr);
//    int not_square = sqrt_ratio_m1 (insrt, feone, vu22);
	int not_square = invsqrt (insrt, vu22);

	Fe den_x, den_y;
	mul (den_x, insrt, u2);
	mul (den_y, insrt, den_x);
	mul (den_y, den_y, v);

	Fe xpos, xneg;
	mul (xpos, s, den_x);
	add (xpos, xpos, xpos);
	negate (xneg, xpos);
	select (res.x, xneg, xpos, ct_is_negative (xpos));

	mul (res.y, u1, den_y);
	mul (res.t, res.x, res.y);
	res.z = feone;

	uint8_t yr[32];
	reduce_store (yr, res.y);
	return not_square | ct_is_negative (res.t) | is_zero (yr, 32) | (sc[0] & 1);
}

/******************
  Conversion from Ristretto to Edwards and Montgomery with a single
  exponentiation.
		 1 - s²
	y = -------
		 1 + s²

						2s
	x = abs (--------------------------)
			 sqrt[-d(1-s²)² - (1+s²)²]

check xy >= 0 && y != 0

Montgomery from s:

u = (1 + y)/(1 - y);
v = Cu/x, where C = sqrt(-A-2)

u = (1 + (1-s²)/(1+s²))/(1 - (1-s²)/(1+s²)) =
  = (1 + s² + 1 - s²) / (1 + s² - 1 + s²) = 2 / (2s²) = 1/s²

u = 1/s²

			sqrt[-d(1-s²)² - (1+s²)²]
v = C*abs (--------------------------)
					  2s³


Combine all inversions and sqrt():

u₁ = 1 - s²
u₂ = 1 + s²
u₃ = -du₁² - u₂²
u₄ = u₂*4s³

						  1     1                1
I = 1 / sqrt (u₃*u₄²)  = --- -------- -------------------------
						 2s³  1 + s²  sqrt[-d(1-s²)² - (1+s²)²]

x = I*u₂*4*s⁴
v = C*I*u₂*u₃
y = u₁*u₂*u₃*I²*4*s⁶
u = u₂²*u₃*I²*4*s⁴

-----------

w₁ = I*u₂           Iu₂
w₂ = w1*C           CIu₂
w₃ = s²             s²
w₄ = 2w₃            2s²
w₅ = w₄²            4s⁴
x = w₁*w₅           Iu₂4s⁴ = 2s/sqrt[-d(1-s²)² - (1+s²)²]
v = w₂*u₃           CIu₂u₃ = C*sqrt[-d(1-s²)² - (1+s²)²]/2/s³
w₆ = w₁*u₃*I*w₅     u₂u₃I²4s⁴
y = w₆*u₁*w₃        u₁u₂u₃I²4s⁶
u = w₆*u₂           u₂²u₃I²4s⁴

*********************************/


int ristretto_to_mont (Edwards &ed, Fe &u, Fe &v, const uint8_t sc[32])
{
	Fe s, u1, u2, u3, u4, I, is;
	Fe w1, w2, w3, w4, w5, w6;
	load (s, sc);

	// w₃ = s²
	square (w3, s);
	// u₁ = 1 - s²
	sub (u1, feone, w3);
	// u₂ = 1 + s²
	add (u2, feone, w3);
	// u₃ = -du₁² - u₂²
	square (u3, u1);
	mul (u3, u3, edwards_d);
	square (u4, u2);
	add (u3, u3, u4);
	negate (u3, u3);
	// u₄ = u₂*2s³
	mul (u4, u2, w3);
	mul (u4, u4, s);
	add (u4, u4, u4);

	// I = 1 / sqrt (u₃*u₄²)
	square (is, u4);
	mul (is, is, u3);
//    int not_square = sqrt_ratio_m1 (I, feone, is);
	int not_square = invsqrt (I, is);

	// w₁ = I*u₂ = Iu₂
	mul (w1, I, u2);
	// w₂ = w1*C = CIu₂
	mul (w2, C, w1);
	// w₄ = 2w₃ = 2s²
	mul_small (w4, w3, 2);
	// w₅ = w₄² = 4s⁴
	square (w5, w4);
	// x = w₁*w₅ = Iu₂4s⁴ = 2s/sqrt[-d(1-s²)² - (1+s²)²]
	mul (ed.x, w1, w5);
	// v = w₂*u₃ = CIu₂u₃ = C*sqrt[-d(1-s²)² - (1+s²)²]/2/s³
	mul (v, w2, u3);
	// w₆ = w₁*u₃*I*w₅ = u₂u₃I²4s⁴
	mul (w6, w1, u3);
	mul (w6, w6, I);
	mul (w6, w6, w5);
	// y = w₆*u₁*w₃ = u₁u₂u₃I²4s⁶
	mul (ed.y, w6, u1);
	mul (ed.y, ed.y, w3);

	// u = w₆*u₂ = u₂²u₃I²4s⁴
	mul (u, w6, u2);

	int x_is_neg = ct_is_negative(ed.x);
	Fe xneg;
	negate (xneg, ed.x);
	select (ed.x, xneg, ed.x, x_is_neg);
	// We must perform the same sign inversion for v.
	Fe vneg;
	negate (vneg, v);
	select (v, vneg, v, x_is_neg);

	mul (ed.t, ed.x, ed.y);
	ed.z = feone;

	uint8_t yr[32];
	reduce_store (yr, ed.y);
	return not_square | ct_is_negative (ed.t) | is_zero (yr, 32) | (sc[0] & 1);
}






bool ristretto_equal (const Edwards &p1, const Edwards &p2)
{
	Fe t1, t2, t3;
	mul (t1, p1.x, p2.y);
	mul (t3, p1.y, p2.x);
	sub (t1, t1, t3);

	mul (t2, p1.y, p2.y);
	mul (t3, p1.x, p2.x);
	sub (t2, t2, t3);

	int v = ct_is_zero (t1) | ct_is_zero (t2);
	return v;
}

static void ristretto_map (Edwards &p, const Fe t)
{
	Fe r, u, v, c, tmp, s;

	square (r, t);
	mul (r, r, root_minus_1);
	add (u, r, feone);
	mul (u, u, one_minus_d_sq);
	negate (c, feone);

	mul (tmp, r, edwards_d);
	sub (v, c, tmp);
	add (tmp, r, edwards_d);
	mul (v, v, tmp);

	int not_square = sqrt_ratio_m1 (s, u, v);

	Fe s_prime, spos, sneg;
	mul (spos, s, t);
	negate (sneg, spos);
	select (s_prime, spos, sneg, ct_is_negative(spos));
	select (s, s_prime, s, not_square);
	select (c, r, c, not_square);

	Fe N;
	sub (tmp, r, feone);
	mul (tmp, tmp, c);
	mul (tmp, tmp, d_minus_one_sq);
	sub (N, tmp, v);

	Fe w0, w1, w2, w3;
	mul (w0, s, v);
	add (w0, w0, w0);
	mul (w1, N, sqrt_ad_minus_one);
	square (tmp, s);
	sub (w2, feone, tmp);
	add (w3, feone, tmp);
	mul (p.x, w0, w3);
	mul (p.y, w2, w1);
	mul (p.z, w1, w3);
	mul (p.t, w0, w2);
}

void ristretto_from_uniform (Edwards &p, const uint8_t b[64])
{
	Fe r0, r1;
	load (r0, b);
	load (r1, b + 32);
	Edwards p1, p2;
	ristretto_map (p1, r0);
	ristretto_map (p2, r1);
	point_add (p, p1, p2);
}

// Ed25519 in Ristretto format with Blake2b.
void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
                   const Cu25519Ris &A, const Cu25519Sec &scalar, uint8_t sig[64])
{
	uint8_t hr[64], r[32], hram[64], rhram[32];

	blake2b (hr, 32, scalar.b, 32, NULL, 0);

	size_t plen;
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		plen = strlen (prefix) + 1;
		blake2b_update (&bs, prefix, plen); // Include the terminating null.
	}
	blake2b_update (&bs, hr, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hr);
	reduce (r, hr);

	// R = rB
	Edwards R;
	scalarbase (R, r);
	edwards_to_ristretto (sig, R);

	// rhram = H(R,A,m)
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, A.b, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);
	reduce (rhram, hram);

	// x = r + H(RAM)a
	Limbtype x[64];
	for (unsigned i = 0; i < 32; ++i) {
		x[i] = (Limbtype) r[i];
	}
	for (unsigned i = 32; i < 64; ++i) {
		x[i] = 0;
	}
	for (unsigned i = 0; i < 32; ++i) {
		for (unsigned j = 0; j < 32; ++j) {
			x[i+j] += rhram[i] * (Limbtype) scalar.b[j];
		}
	}

	// S = (r + H(RAM)a) mod L
	modL (sig + 32, x);
}

int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen,
                    const uint8_t sig[64], const Cu25519Ris &A)
{
	if (!gt_than (order, sig + 32)) {
		return -1;
	}

	Edwards p;
	// p = - A
	if (ristretto_to_edwards (p, A.b) != 0) {
		return -1;
	}
	negate (p, p);

	uint8_t hram[64];
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		size_t n = strlen (prefix);
		blake2b_update (&bs, prefix, n + 1);    // Include terminating null to establish a unique prefix.
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, A.b, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	Edwards newr;
	// R = SB - hA
	scalarmult_wnaf (newr, sig + 32, p, rhram);
	uint8_t newrp[32];
	edwards_to_ristretto (newrp, newr);

	return crypto_neq (sig, newrp, 32);
}

void cu25519_generate_no_mask (const Cu25519Sec &scalar, Cu25519Ris *ris)
{
	Edwards p;
	scalarbase (p, scalar.b);
	edwards_to_ristretto (ris->b, p);
}
void cu25519_generate (Cu25519Sec *scalar, Cu25519Ris *ris)
{
	Edwards p;
	mask_scalar (scalar->b);
	scalarbase (p, scalar->b);
	edwards_to_ristretto (ris->b, p);
}

// From the decaf paper: The Montgomery u corresponding to the Ristretto
// representative s is 1/s². We would need to perform an inversion for
// this. However note that both u = 1/s² and 1/u = s² belong to the same
// coset: the set of points differing only by a small order point.
// Therefore we use u = s² as input to the ladder and then clear the
// small order component by multiplying by the cofactor. We require that the
// scalar is a multiple of 8 for this function. We reject resulting points
// which are in the twist and we reject small order points. This produces
// results that are compatible with the Montgomery representation. For
// instance you may use a long term key in Ristretto format and an ephemeral
// key in Elligator or Montgomery format. Alice uses a*B with B in Ristretto
// format and Bob uses b*A with A in Montgomery format and both produce the
// same result. Therefore we can mix Ristretto and Montgomery for DH.

static int ristretto_ladder_imp_checked (uint8_t res[32], const Cu25519Ris &A, const uint8_t scalar[32], int startbit=255)
{
	// s must be even for valid ristretto encodings.
	if (A.b[0] & 1) return -1;
	Fe s2;
	load (s2, A.b);
	square (s2, s2);
	Fe fu, fz;
	montgomery_ladder (fu, fz, s2, scalar, startbit);

	// We multiply by the cofactor. Therefore the result is the result of
	// doubling a point. In Montgomery coordinates points which are the
	// result of doubling have the x coordinate square. The invsqrt will
	// also fail f u == 0 (small order point). Therefore we detect both
	// small order points and points on the twist.
	Fe fres;
	mul (fres, fu, fz);
	int err = invsqrt (fres, fres);
	mul (fres, fres, fu);
	square (fres, fres);
	reduce_store (res, fres);
	return err;
}

static void ristretto_ladder_imp_unchecked (uint8_t res[32], const Cu25519Ris &A, const uint8_t scalar[32], int startbit=255)
{
	// s must be even for valid ristretto encodings.
//  if (A.b[0] & 1) return -1;
	Fe s2;
	load (s2, A.b);
	square (s2, s2);
	Fe fu, fz;
	montgomery_ladder (fu, fz, s2, scalar, startbit);
	invert (fz, fz);
	mul (fu, fu, fz);
	reduce_store (res, fu);
}


// The scalar must be a multiple of eight.
int cu25519_shared_secret_checked (uint8_t res[32], const Cu25519Ris &A, const Cu25519Sec &scalar)
{
	return ristretto_ladder_imp_checked (res, A, scalar.b);
}
void cu25519_shared_secret_unchecked (uint8_t res[32], const Cu25519Ris &A, const Cu25519Sec &scalar)
{
	ristretto_ladder_imp_unchecked (res, A, scalar.b);
}

void cu25519_shared_secret (uint8_t res[32], const Cu25519Ris &A,
                            const Cu25519Sec &scalar)
{
	if (ristretto_ladder_imp_checked (res, A, scalar.b) != 0) {
		throw std::runtime_error (_("Wrong public key shared secret (Ris)."));
	}
}


// Multiply the scalar by eight.
inline void shift8_scalar (uint8_t newsc[33], const uint8_t oldsc[32])
{
	int bits = 0;
	for (int i = 0; i < 32; ++i) {
		bits = (bits & 0x7) | (int(oldsc[i]) << 3);
		newsc[i] = bits;
		bits >>= 8;
	}
	newsc[32] = bits;
}

// Works with any scalar. If first multiplies the scalar by 8 and then
// performs the scalar multiplication.
int cu25519_shared_secret_cof_checked (uint8_t res[32], const Cu25519Ris &A, const Cu25519Sec &scalar)
{
	uint8_t nsc[33];
	shift8_scalar (nsc, scalar.b);
	// Given the input with 256 bits we now have 259 bits of scalar. The
	// actual ladder routine works with any number of bits.
	return ristretto_ladder_imp_checked (res, A, nsc, 258);
}

void cu25519_shared_secret_cof_unchecked (uint8_t res[32], const Cu25519Ris &A, const Cu25519Sec &scalar)
{
	uint8_t nsc[33];
	shift8_scalar (nsc, scalar.b);
	// Given the input with 256 bits we now have 259 bits of scalar. The
	// actual ladder routine works with any number of bits.
	ristretto_ladder_imp_unchecked (res, A, nsc, 258);
}

void cu25519_shared_secret_cof (uint8_t res[32], const Cu25519Ris &A,
                                const Cu25519Sec &scalar)
{
	if (cu25519_shared_secret_cof_checked (res, A, scalar) != 0) {
		throw std::runtime_error (_("Wrong public key shared secret cofactor (Ris)."));
	}
}


void cu25519_shared_secret (uint8_t sh[32], const Cu25519Mon &mon,
                            const Cu25519Sec &scalar)
{
	if (cu25519_shared_secret_checked (sh, mon, scalar) != 0) {
		throw std::runtime_error (_("Wrong public key shared secret (Mon)."));
	}
}



// Verify a ristretto signature using qdsa, no Edwards arithmetic.
int ristretto_qdsa_verify (const char *prefix, const uint8_t *m, size_t mlen,
                           const uint8_t sig[64], const Cu25519Ris &A)
{
	if (!gt_than (order, sig + 32)) {
		return -1;
	}

	uint8_t hram[64];
	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	if (prefix != NULL) {
		size_t n = strlen (prefix);
		blake2b_update (&bs, prefix, n + 1);    // Include terminating null to establish a unique prefix.
	}
	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, A.b, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	// We shall check 8R == ±8SB ± 8hA

	// Multiply the scalars by eight. They still fit in 256 bits because they
	// were < group order.
	uint8_t r8[33], s8[33];
	shift8_scalar (r8, rhram);
	shift8_scalar (s8, sig + 32);

	Fe fau, fu1, fz1, fu2, fz2, fu3, fz3;
	load (fau, A.b);
	square (fau, fau);
	montgomery_ladder (fu2, fz2, fau, r8);
	static const Fe fmb = { 9 };
	montgomery_ladder (fu3, fz3, fmb, s8);

	uint8_t sc8 = 8;
	Fe fr;
	load (fr, sig);
	square (fr, fr);
	montgomery_ladder (fu1, fz1, fr, &sc8, 3);

	// Check that u1/z1 = ±u2/z2 ± u3/z3

	// 4 (U1.Z2.Z3 + U2.Z1.Z3 + U3.Z1.Z2 + A.Z1.Z2.Z3) (U1.U2.U3) =
	//    (Z1.Z2.Z3 - U1.U2.Z3 - U2.U3.Z1 - U3.U1.Z2)²

	Fe tmp1, tmp2, tmp3, u1z2, u2z1, u3z1, z1z2z3, u1u2;
	mul (u1z2, fu1, fz2);
	mul (tmp1, u1z2, fz3);

	mul (u2z1, fu2, fz1);
	mul (tmp2, u2z1, fz3);
	add_no_reduce (tmp1, tmp1, tmp2);

	mul (u3z1, fu3, fz1);
	mul (tmp2, u3z1, fz2);
	add_no_reduce (tmp1, tmp1, tmp2);

	mul (z1z2z3, fz1, fz2);
	mul (z1z2z3, z1z2z3, fz3);
	mul_small (tmp2, z1z2z3, 486662);
	add_no_reduce (tmp1, tmp1, tmp2);

	mul (u1u2, fu1, fu2);
	mul (tmp1, tmp1, u1u2);
	mul (tmp1, tmp1, fu3);
	add_no_reduce (tmp1, tmp1, tmp1);
	add_no_reduce (tmp1, tmp1, tmp1);

	mul (tmp2, u1u2, fz3);
	mul (tmp3, u3z1, fu2);
	add_no_reduce (tmp2, tmp2, tmp3);
	mul (tmp3, u1z2, fu3);
	add_no_reduce (tmp2, tmp2, tmp3);
	sub (tmp2, z1z2z3, tmp2);
	square (tmp2, tmp2);

	sub (tmp1, tmp1, tmp2);
	uint8_t res[32];
	reduce_store (res, tmp1);
	return !is_zero (res, 32);
}



}}

