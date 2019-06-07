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

#include "field25519.hpp"
#include "hasopt.hpp"
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <string.h>

#include "misc.hpp"
#include "symmetric.hpp"

namespace amber {  namespace AMBER_SONAME {

#if AMBER_LIMB_BITS == 32

// p = 2²⁵⁵-19
static const Fe32 p = { 0x3FFFFED, mask25, mask26, mask25, mask26,
                        mask25, mask26, mask25, mask26, mask25 };

// sqrt(-1) = 2^(2²⁵³ - 5)
static const Fe32 root_minus_1 = { 0x20ea0b0, 0x186c9d2, 0x08f189d, 0x035697f, 0x0bd0c60,
                                   0x1fbd7a7, 0x2804c9e, 0x1e16569, 0x004fc1d, 0x0ae0c92 };

#elif AMBER_LIMB_BITS >= 64

static const Fe64 p = { p0_64, mask51, mask51, mask51, mask51 };
static const Fe64 root_minus_1 = { 0x61b274a0ea0b0, 0xd5a5fc8f189d, 0x7ef5e9cbd0c60,
                                   0x78595a6804c9e, 0x2b8324804fc1d };

#endif

// Load a byte string into the limb form.
void load (Fe32 &fe, const uint8_t b[32])
{
	// Loads 255 bits from b. Ignores the top most bit.
	fe.v[0] = (uint32_t(b[ 0])   ) | (uint32_t(b[ 1]) << 8) | (uint32_t(b[ 2]) << 16) | (uint32_t(b[ 3] & 0x3) << 24);  // 26
	fe.v[1] = (uint32_t(b[ 3]) >> 2) | (uint32_t(b[ 4]) << 6) | (uint32_t(b[ 5]) << 14) | (uint32_t(b[ 6] & 0x7) << 22);  // 25
	fe.v[2] = (uint32_t(b[ 6]) >> 3) | (uint32_t(b[ 7]) << 5) | (uint32_t(b[ 8]) << 13) | (uint32_t(b[ 9] & 0x1F) << 21); // 26
	fe.v[3] = (uint32_t(b[ 9]) >> 5) | (uint32_t(b[10]) << 3) | (uint32_t(b[11]) << 11) | (uint32_t(b[12] & 0x3F) << 19); // 25
	fe.v[4] = (uint32_t(b[12]) >> 6) | (uint32_t(b[13]) << 2) | (uint32_t(b[14]) << 10) | (uint32_t(b[15]       ) << 18); // 26
	fe.v[5] = (uint32_t(b[16])     ) | (uint32_t(b[17]) << 8) | (uint32_t(b[18]) << 16) | (uint32_t(b[19] & 0x1) << 24);  // 25
	fe.v[6] = (uint32_t(b[19]) >> 1) | (uint32_t(b[20]) << 7) | (uint32_t(b[21]) << 15) | (uint32_t(b[22] & 0x7) << 23);  // 26
	fe.v[7] = (uint32_t(b[22]) >> 3) | (uint32_t(b[23]) << 5) | (uint32_t(b[24]) << 13) | (uint32_t(b[25] & 0xF) << 21);  // 25
	fe.v[8] = (uint32_t(b[25]) >> 4) | (uint32_t(b[26]) << 4) | (uint32_t(b[27]) << 12) | (uint32_t(b[28] & 0x3F) << 20); // 26
	fe.v[9] = (uint32_t(b[28]) >> 6) | (uint32_t(b[29]) << 2) | (uint32_t(b[30]) << 10) | (uint32_t(b[31] & 0x7F) << 18); // 25
}

// Reduce the coefficients to their nominal bit ranges. It may be > p.
inline void reduce (Fe32 &fe)
{
	uint32_t c;

	c = fe.v[0];    fe.v[0] = c & mask26;  c >>= 26;
	c += fe.v[1];   fe.v[1] = c & mask25;  c >>= 25;
	c += fe.v[2];   fe.v[2] = c & mask26;  c >>= 26;
	c += fe.v[3];   fe.v[3] = c & mask25;  c >>= 25;
	c += fe.v[4];   fe.v[4] = c & mask26;  c >>= 26;
	c += fe.v[5];   fe.v[5] = c & mask25;  c >>= 25;
	c += fe.v[6];   fe.v[6] = c & mask26;  c >>= 26;
	c += fe.v[7];   fe.v[7] = c & mask25;  c >>= 25;
	c += fe.v[8];   fe.v[8] = c & mask26;  c >>= 26;
	c += fe.v[9];   fe.v[9] = c & mask25;  c >>= 25;
	fe.v[0] += 19 * c;
}


inline void add_bits32 (uint8_t *b, uint32_t c)
{
	b[0] |= c & 0xFF;
	b[1] = (c >> 8) & 0xFF;
	b[2] = (c >> 16) & 0xFF;
	b[3] = (c >> 24);
}

void show_raw (const char *label, const Fe32 &fe)
{
	std::cout << label << ": " << std::hex << std::setfill('0');
	for (int i = 0; i < 10; ++i) {
		std::cout << "0x" << std::setw(7) << fe.v[i] << ", ";
	}
	std::cout << '\n' << std::setfill(' ') << std::dec;
}


void show_raw (const char *label, const Fe64 &fe)
{
	std::cout << label << ": " << std::hex << std::setfill('0');
	for (int i = 0; i < 5; ++i) {
		std::cout << "0x" << std::setw(7) << fe.v[i] << ", ";
	}
	std::cout << '\n' << std::setfill(' ') << std::dec;
}


// Fully reduce to mod p and store it in byte form.
void reduce_store (uint8_t b[32], Fe32 &fe)
{
	reduce (fe);
	reduce (fe);
	// Now we have fe between 0 and 2²⁵⁵ - 1.
   // Add 19 and reduce.
	fe.v[0] += 19;
	reduce (fe);
	// Now we have fe between 19 and 2²⁵⁵ - 1.
	// Substract 19. Do this by adding 2²⁵⁶ - 19 = 2²⁵⁶ - 1 - 18. This is the
	// same as having all bits 1 and substract 18. Then disregard all bits
	// beyond 255.
	uint32_t c;
	c = fe.v[0] + mask26 - 18;  fe.v[0] = c & mask26;   c >>= 26;
	c += fe.v[1] + mask25;      fe.v[1] = c & mask25;   c >>= 25;
	c += fe.v[2] + mask26;      fe.v[2] = c & mask26;   c >>= 26;
	c += fe.v[3] + mask25;      fe.v[3] = c & mask25;   c >>= 25;
	c += fe.v[4] + mask26;      fe.v[4] = c & mask26;   c >>= 26;
	c += fe.v[5] + mask25;      fe.v[5] = c & mask25;   c >>= 25;
	c += fe.v[6] + mask26;      fe.v[6] = c & mask26;   c >>= 26;
	c += fe.v[7] + mask25;      fe.v[7] = c & mask25;   c >>= 25;
	c += fe.v[8] + mask26;      fe.v[8] = c & mask26;   c >>= 26;
	c += fe.v[9] + mask25;      fe.v[9] = c & mask25;

	// Now pack it in bytes.
	b[0] = 0;
	add_bits32 (b +  0, fe.v[0]);
	add_bits32 (b +  3, fe.v[1] << 2);   // 26 - 24
	add_bits32 (b +  6, fe.v[2] << 3);   // 51 - 48
	add_bits32 (b +  9, fe.v[3] << 5);   // 77 - 72
	add_bits32 (b + 12, fe.v[4] << 6);   // 102 - 96
	b[16] = 0;
	add_bits32 (b + 16, fe.v[5]);        // 128 - 128
	add_bits32 (b + 19, fe.v[6] << 1);   // 153 - 152
	add_bits32 (b + 22, fe.v[7] << 3);   // 179 - 176
	add_bits32 (b + 25, fe.v[8] << 4);   // 204 - 190
	add_bits32 (b + 28, fe.v[9] << 6);   // 230 - 224
}

// Fully reduce to mod p
void reduce_full (Fe32 &fe)
{
	reduce (fe);
	reduce (fe);
	// Now we have fe between 0 and 2²⁵⁵ - 1.
	// Add 19 and reduce.
	fe.v[0] += 19;
	reduce (fe);
	// Now we have fe between 19 and 2²⁵⁵ - 1.
	// Substract 19. Do this by adding 2²⁵⁶ - 19 = 2²⁵⁶ - 1 - 18. This is the
	// same as having all bits 1 and substract 18. Then disregard all bits
	// beyond 255.
	uint32_t c;
	c = fe.v[0] + mask26 - 18;  fe.v[0] = c & mask26;   c >>= 26;
	c += fe.v[1] + mask25;      fe.v[1] = c & mask25;   c >>= 25;
	c += fe.v[2] + mask26;      fe.v[2] = c & mask26;   c >>= 26;
	c += fe.v[3] + mask25;      fe.v[3] = c & mask25;   c >>= 25;
	c += fe.v[4] + mask26;      fe.v[4] = c & mask26;   c >>= 26;
	c += fe.v[5] + mask25;      fe.v[5] = c & mask25;   c >>= 25;
	c += fe.v[6] + mask26;      fe.v[6] = c & mask26;   c >>= 26;
	c += fe.v[7] + mask25;      fe.v[7] = c & mask25;   c >>= 25;
	c += fe.v[8] + mask26;      fe.v[8] = c & mask26;   c >>= 26;
	c += fe.v[9] + mask25;      fe.v[9] = c & mask25;
}


static void show_fe (std::ostream &os, const uint32_t rhs[10], const char *label=0)
{
	Fe tmp;
	for (int i = 0; i < fecount; ++i) tmp.v[i] = rhs[i];

	uint8_t bytes[32];
	reduce_store (bytes, tmp);

	if (label) {
		os << label << ": ";
	}

	os << std::hex << std::setfill('0');
	int count = 0;
	for (int i = 0; i < 32; ++i) {
		std::cout << std::setw(2) << unsigned(bytes[i]);
		if (++count == 4 ) {
			std::cout << ' ';
			count = 0;
		}
	}
	os << std::dec;
	if (label) {
		os << '\n';
	}
}

std::ostream & operator<< (std::ostream &os, const Fe32 &rhs)
{
	show_fe (os, rhs.v);
	return os;
}



// Compute z11 = z¹¹ and res = z ^ (2²⁵² - 2²). Taken from the slides of
// "Scalar-multiplication algorithms" by Peter Schwabe.
static void raise_252_2 (Fe &res, Fe &z11, const Fe &z)
{
	Fe t;
	Fe z2;  // square of z
	Fe z9;  // z⁹
	// In the following z2_x_y means z^(2^x - 2^y)
	Fe z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0;
	// The comments show the exponent.
	square (z2, z);     // 2
	square (t, z2);     // 4
	square (t, t);      // 8
	mul (z9, t, z);     // 9
	mul (z11, z9, z2);  // 11
	square (t, z11);    // 22
	mul (z2_5_0, t, z9);   // 2⁵ - 2⁰
	square (t, z2_5_0);    // 2⁶ - 2¹
	for (int i = 0; i < 4; ++i) {
		square (t, t);
	}                       // 2¹⁰ - 2⁵
	mul (z2_10_0, t, z2_5_0);   // 2¹⁰ - 2⁰
	square (t, z2_10_0);        // 2¹¹ - 2¹
	for (int i = 0; i < 9; ++i) {
		square (t, t);
	}                           // 2²⁰ - 2¹⁰
	mul (z2_20_0, t, z2_10_0);  // 2²⁰ - 2⁰
	square (t, z2_20_0);        // 2²¹ - 2¹
	for (int i = 0; i < 19; ++i) {
		square (t, t);
	}                           // 2⁴⁰ - 2²⁰
	mul (t, t, z2_20_0);        // 2⁴⁰ - 2⁰
	square (t, t);              // 2⁴¹ - 2¹
	for (int i = 0; i < 9; ++i) {
		square (t, t);
	}                           // 2⁵⁰ - 2¹⁰
	mul (z2_50_0, t, z2_10_0);  // 2⁵⁰ - 2⁰
	square (t, z2_50_0);        // 2⁵¹ - 2¹
	for (int i = 0; i < 49; ++i) {
		square (t, t);
	}                           // 2¹⁰⁰ -2⁵⁰
	mul (z2_100_0, t, z2_50_0); // 2¹⁰⁰ - 2⁰
	square (t, z2_100_0);       // 2¹⁰¹ - 2¹
	for (int i = 0; i < 99; ++i) {
		square (t, t);
	}                           // 2²⁰⁰ - 2¹⁰⁰
	mul (t, t, z2_100_0);       // 2²⁰⁰ - 2⁰
	square (t, t);              // 2²⁰¹ - 2¹
	for (int i = 0; i < 49; ++i) {
		square (t, t);
	}                           // 2²⁵⁰ - 2⁵⁰
	mul (t, t, z2_50_0);        // 2²⁵⁰ - 2⁰
	square (t, t);              // 2²⁵¹ - 2¹
	square (res, t);            // 2²⁵² - 2²
}


// Raise to p-2 = 2²⁵⁵ - 21. This is the same as computing the inverse in
// this field.
void invert (Fe &res, const Fe &z)
{
	Fe z11, tmp;// z¹¹
	raise_252_2 (tmp, z11, z);    // 2²⁵² - 2²
	square (tmp, tmp);      // 2²⁵³ - 2³
	square (tmp, tmp);      // 2²⁵⁴ - 2⁴
	square (tmp, tmp);      // 2²⁵⁵ - 2⁵
	mul (res, tmp, z11);    // 2²⁵⁵ - 21
}


// Raise z to the 2²⁵² - 3 power. Similar to the above computation. Used for
// combined sqrt and division. From the Ed25519 paper: we need to compute the
// square root of a quotient.
/*
   β = sqrt(u/v) = (u/v)^[(p+3)/8], where p is 2²⁵⁵ - 19.
   β = (u/v)^[(p+3)/8] = u^[(p+3)/8] * v^[p-1-(p+3)/8], because x^(p-1) == 1
   β = u^[(p+3)/8] * v^[(7p-11)/8] = uv³(uv⁷)^[(p-5)/8]
*/

void raise_252_3 (Fe &res, const Fe &z)
{
	Fe z11, tmp;
	raise_252_2 (tmp, z11, z);    // 2²⁵² - 2²
	mul (res, tmp, z);        // 2²⁵² - 3
}


// Return 1 or 0. Constant time.
uint8_t not_zero (const uint8_t *b, size_t n)
{
	uint8_t res = 0;
	for (unsigned i = 0; i < n; ++i) {
		res |= b[i];
	}
	res |= res >> 4;
	res |= res >> 2;
	res |= res >> 1;
	return res & 1;
}


// res = sqrt(1/x). Constant time. Return 0 if it was a square. Return 1 if
// it was not an square.
/* β = sqrt(u/v) = (u/v)^[(p+3)/8], where p is 2²⁵⁵ - 19.
   β = (u/v)^[(p+3)/8] = u^[(p+3)/8] * v^[p-1-(p+3)/8], because x^(p-1) == 1
   β = u^[(p+3)/8] * v^[(7p-11)/8] = uv³(uv⁷)^[(p-5)/8]
   iff u == 1, sqrt(1/v) = v³(v⁷)^[(p-5)/8] = v³(v⁷)^(2²⁵² - 3)
*/

int invsqrt (Fe &res, const Fe &x)
{
	Fe x3, x7, r, r2, f1, rm1;
	square (x3, x);
	mul (x3, x3, x);
	square (x7, x3);
	mul (x7, x7, x);
	raise_252_3 (x7, x7);
	mul (r, x3, x7);

	// Check if we got the correct sign.
	square (r2, r);
	mul (f1, r2, x);
	uint8_t bytes[32];
	reduce_store (bytes, f1);

	// Multiply by sqrt(-1) if it is not 1.
	mul (rm1, r, root_minus_1);
	cswap (r, rm1, bytes[1] & 1);

	// Check that it is a square.
	square (r2, r);
	mul (f1, r2, x);
	reduce_store (bytes, f1);
	bytes[0]--;

	res = r;
	return not_zero (bytes, 32);
}


// res = sqrt(x) = x^((p+3)/8) = x^[(2²⁵⁵ - 16)/8] = x^(2²⁵² - 2)
// Return 0 if there is a root. 1 if no root exists.
int sqrt (Fe &res, const Fe &z)
{
	Fe r, z11;
	raise_252_2 (r, z11, z);  // r = z ^ (2²⁵² - 4)
	square (z11, z);
	mul (r, r, z11);

	// See if we need to multiply by sqrt(-1)
	square (z11, r);
	sub (z11, z11, z);
	uint8_t bytes[32];
	reduce_store (bytes, z11);

	Fe rm1;
	mul (rm1, r, root_minus_1);
	// If the result was not 0 then multiply by sqrt(-1)
	cswap (r, rm1, not_zero(bytes, 32));
	// Now r has the correct root, if a root exists.

	square (z11, r);
	sub (z11, z11, z);
	res = r;
	reduce_store (bytes, z11);
	return not_zero (bytes, 32);
}



// Compute res = sqrt(u/v) and return zero or res = sqrt(iu/v) and return
// 1. If u/v is not a square then iu/v is a square. i = sqrt(-1).
int sqrt_ratio_m1 (Fe &res, const Fe &u, const Fe &v)
{
	Fe v3, v7, r, check;
	square (v3, v);
	mul (v3, v3, v);
	square (v7, v3);
	mul (v7, v7, v);
	mul (r, u, v7);
	raise_252_3 (r, r);
	mul (r, r, v3);
	mul (r, r, u);
	square (check, r);
	mul (check, check, v);

	Fe tmp;
	sub (tmp, check, u);
	int correct_sign_sqrt = ct_is_zero (tmp);
	add (tmp, check, u);
	int flipped_sign_sqrt = ct_is_zero (tmp);
	mul (tmp, u, root_minus_1);
	add (tmp, tmp, check);
	int flipped_sign_sqrt_i = ct_is_zero (tmp);

	Fe r_prime;
	mul (r_prime, root_minus_1, r);
	select (r, r_prime, r, flipped_sign_sqrt | flipped_sign_sqrt_i);

	negate (tmp, r);
	uint8_t sc[32];
	reduce_store (sc, r);
	select (res, tmp, r, sc[0] & 1);

	return 1 ^ (correct_sign_sqrt | flipped_sign_sqrt);
}



void raise_253_5 (Fe &res, const Fe &z)
{
	Fe t1, t2;
	raise_252_2 (t1, t2, z);    // t1 = z^(2²⁵² - 4)
	mul (t1, t1, z);            // t1 = z^(2²⁵² - 3)
	square (t1, t1);            // t1 = z^(2²⁵³ - 6)
	mul (res, t1, z);           // t1 = z^(2²⁵³ - 5)
}

// Raise to 2²⁵⁴ - 10 Required for elligator 2.
void raise_254_10 (Fe &res, const Fe &z)
{
	Fe z6, tmp;
	raise_252_2 (tmp, z6, z);  // 2²⁵² - 2²
	square (tmp, tmp);         // 2²⁵³ - 2³
	square (tmp, tmp);         // 2²⁵⁴ - 2⁴ = 2²⁵⁴ - 16
	square (z6, z);
	mul (z6, z6, z);
	square (z6, z6);
	mul (res, tmp, z6);        // 2²⁵⁴ - 10
}



static const Fe fezero = { 0 };
static const Fe feone = { 1 };
enum { A = 486662 };

// Input x coordinate of point P and scalar. Output x2:z2 x coordinate of
// scalar*P and x3:z3 x coordinate of (scalar+1)*P. Works for any scalar.
static void montgomery_ladder (Fe &x2, Fe &z2, Fe &x3, Fe &z3, const Fe &x1, const uint8_t scalar[32], int startbit=255)
{
	x2 = feone;
	z2 = fezero;
	x3 = x1;
	z3 = feone;
	Fe t1, t2, t3, t4, t5, t6, t7, t8, t9;
	// Are 2 and 3 swapped?
	uint32_t swapped = 0;
	for (int i = startbit; i >= 0; --i) {
		uint32_t current = (scalar[i/8] >> (i & 7)) & 1;
		uint32_t flag = current ^ swapped;
		cswap (x2, x3, flag);
		cswap (z2, z3, flag);
		swapped = current;

		add_no_reduce (t1, x2, z2);
		sub (t2, x2, z2);
		add_no_reduce (t3, x3, z3);
		sub (t4, x3, z3);
		square (t6, t1);
		square (t7, t2);
		sub (t5, t6, t7);
		mul (t8, t4, t1);
		mul (t9, t3, t2);
		add_no_reduce (x3, t8, t9);
		square (x3, x3);
		sub (z3, t8, t9);
		square (z3, z3);
		mul (z3, z3, x1);
		mul (x2, t6, t7);
		mul_small (z2, t5, 121666);
		add_no_reduce (z2, z2, t7);
		mul (z2, z2, t5);
	}

	cswap (x2, x3, swapped);
	cswap (z2, z3, swapped);
}

// Normal montgomery ladder. Compute the X coordinate only. It ignores bit
// 255 and works with bits 0-254 of the scalar. X25519 requires that bit 254
// is always set and bits 0-2 are cleared. This routine works with anything
// and you must ensure that the scalar's bits have been properly masked.
void montgomery_ladder (Fe &res, const Fe &xp, const uint8_t scalar[32], int startbit)
{
	Fe x2, z2, x3, z3;
	montgomery_ladder (x2, z2, x3, z3, xp, scalar, startbit);
	invert (z2, z2);
	mul (res, x2, z2);
}

void montgomery_ladder (Fe &u, Fe &z, const Fe &xp, const uint8_t scalar[32], int startbit)
{
	Fe x3, z3;
	montgomery_ladder (u, z, x3, z3, xp, scalar, startbit);
}



// Montgomery ladder with recovery of projective X:Y:Z coordinates.
void montgomery_ladder_uv (Fe &resu, Fe &resv, Fe &resz,
            const Fe &xpu, const Fe &xpv, const uint8_t scalar[32], int startbit)
{
	Fe x2, z2, x3, z3;
	montgomery_ladder (x2, z2, x3, z3, xpu, scalar, startbit);

	// Algorithm 1 of Okeya and Sakurai, "Efficient Elliptic Curve
	// Cryptosystems from a Scalar multiplication algorithm with recovery of
	// the y-coordinate on a montgomery form elliptic curve".
	Fe t1, t2, t3, t4;
	mul (t1, xpu, z2);
	add (t2, x2, t1);
	sub (t3, x2, t1);
	square (t3, t3);
	mul (t3, t3, x3);
	mul_small (t1, z2, 2*A);
	add_no_reduce (t2, t2, t1);
	mul (t4, xpu, x2);
	add_no_reduce (t4, t4, z2);
	mul (t2, t2, t4);
	mul (t1, t1, z2);
	sub (t2, t2, t1);
	mul (t2, t2, z3);
	sub (resv, t2, t3);
	mul_small (t1, xpv, 2);
	mul (t1, t1, z2);
	mul (t1, t1, z3);
	mul (resu, t1, x2);
	mul (resz, t1, z2);
}

// Montgomery ladder with recovery of affine U and V coordinates.
void montgomery_ladder_uv (Fe &resu, Fe &resv, const Fe &xpu, const Fe &xpv, const uint8_t scalar[32], int startbit)
{
	Fe resz;
	montgomery_ladder_uv (resu, resv, resz, xpu, xpv, scalar, startbit);
	invert (resz, resz);
	mul (resu, resu, resz);
	mul (resv, resv, resz);
}

#if AMBER_LIMB_BITS == 32
// C = sqrt(-A-2)
static const Fe C = { 0x0ba81e7, 0x07ed540, 0x0afa672, 0x175a417, 0x0e978b0,
                      0x003b081, 0x27b91fe, 0x12885b0, 0x0b9f5ff, 0x1c36448 };
#elif AMBER_LIMB_BITS >= 64
static const Fe C = { 0x1fb5500ba81e7, 0x5d6905cafa672, 0xec204e978b0, 0x4a216c27b91fe,
                      0x70d9120b9f5ff };
#endif

// u = (1+y)/(1-y)  v = Cu/x
// u = (Z+Y)/(Z-Y) v = C(Z+Y)Z/(Z-Y)/X
void edwards_to_mont (Fe &u, Fe &v, const Edwards &p)
{
	Fe zmy, zmyx, inv;
	sub (zmy, p.z, p.y);
	mul (zmyx, zmy, p.x);
	invert (inv, zmyx);
	add (zmy, p.z, p.y);
	mul (zmy, zmy, inv);    // zmy = (Z+Y)/(Z-Y)/X
	mul (u, zmy, p.x);
	mul (v, zmy, p.z);
	mul (v, v, C);
}


void mont_to_edwards (Edwards &e, const Fe &u, const Fe &v, const Fe &z)
{
	// y = (U-Z)/(U+Z) x = CU/V
	// X = CU(U+Z) Y = (U-Z)V Z=(U+Z)V T=CU(U-Z)
	Fe t1, t2, cu;
	add_no_reduce (t1, u, z);
	sub (t2, u, z);
	mul (cu, C, u);
	mul (e.x, cu, t1);
	mul (e.y, t2, v);
	mul (e.z, t1, v);
	mul (e.t, cu, t2);
}

// Montgomery ladder with result as Edwards point.
void montgomery_ladder (Edwards &res, const Fe &xpu, const Fe &xpv, const uint8_t scalar[32], int startbit)
{
	Fe u, v, z;
	montgomery_ladder_uv (u, v, z, xpu, xpv, scalar, startbit);
	mont_to_edwards (res, u, v, z);
}

void montgomery_ladder (Edwards &res, const Edwards &p, const uint8_t scalar[32], int startbit)
{
	Fe u, v;
	edwards_to_mont (u, v, p);
	montgomery_ladder (res, u, v, scalar, startbit);
}

// Base point in Montgomery coordinates.
static const Fe bu = { 9 };

#if AMBER_LIMB_BITS == 32
static const Fe bv = { 0x2ced3d9, 0x071689f, 0x036453d, 0x1f36be3, 0x248f535,
                       0x148d14c, 0x36e963b, 0x0d69c03, 0x21b8a08, 0x082b866 };
#elif AMBER_LIMB_BITS >= 64
static const Fe bv = { 0x1c5a27eced3d9, 0x7cdaf8c36453d, 0x523453248f535,
                       0x35a700f6e963b, 0x20ae19a1b8a08 };
#endif

void montgomery_base (Fe &u, Fe &v, Fe &z, const uint8_t scalar[32], int startbit)
{
	montgomery_ladder_uv (u, v, z, bu, bv, scalar, startbit);
}

void montgomery_base (Fe &u, Fe &v, const uint8_t scalar[32], int startbit)
{
	montgomery_ladder_uv (u, v, bu, bv, scalar, startbit);
}

void montgomery_base (Edwards &e, const uint8_t scalar[32], int startbit)
{
	montgomery_ladder (e, bu, bv, scalar, startbit);
}

void montgomery_base (uint8_t mx[32], const uint8_t scalar[32], int startbit)
{
	Fe u, v, z;
	montgomery_ladder_uv (u, v, z, bu, bv, scalar, startbit);
	// x = Cu/v
	Fe t1, t2;
	mul (t1, v, z);
	invert (t1, t1);    // t1 = 1/(VZ)
	mul (t2, u, C);
	mul (t2, t2, t1);
	mul (t2, t2, z);
	reduce_store (mx, t2);
	uint8_t sign = mx[0] & 1;

	mul (t1, t1, v);
	mul (t1, t1, u);
	reduce_store (mx, t1);
	mx[31] |= sign << 7;
}



// X25519 requires that bit 254 is always set and bits 0-2 are cleared. This
// routine works with anything and you must ensure that the scalar's bits have
// been properly masked.

// DJB does not check for multiplication of small order points. There is a
// debate about whether this is needed or not. We can protect against Eve
// sending us a small order point. Eve could also fool some protocols by
// sending a point P + S, where S is a small order point. Multiplying by the
// cofactor clears S. A small order point means that a DH with it does not
// contribute to the final key in a protocol. The IETF wants to check for
// this case. Our check will reject small order points and points which are
// not on the curve.

int montgomery_ladder_checked (uint8_t res[32], const uint8_t pointx[32], const uint8_t scalar[32], int startbit)
{
	Fe fu, fz, fb;
	load (fb, pointx);
	montgomery_ladder (fu, fz, fb, scalar, startbit);

	// The final point is a multiple of two times the pointx. Therefore its u
	// coordinate must be a square. This rejects twist points and small order
	// points.
	Fe fres;
	mul (fres, fu, fz);
	int err = invsqrt (fres, fres);
	mul (fres, fres, fu);
	square (fres, fres);
	reduce_store (res, fres);
	return err;
}

void montgomery_ladder_unchecked (uint8_t res[32], const uint8_t pointx[32], const uint8_t scalar[32], int startbit)
{
	Fe fu, fz, fb;
	load (fb, pointx);
	montgomery_ladder (fu, fz, fb, scalar, startbit);
	invert (fz, fz);
	mul (fu, fu, fz);
	reduce_store (res, fu);
}


// Elligator 2

// See https://www.imperialviolet.org/2013/12/25/elligator.html


/* sqrt(-1)*sqrt(A+2). Any of the two following values will do.
sqrt(-1)sqrt(A+2): 067e45ff aa046ecc 821a7d4b d1d3a1c5 7e4ffc03 dc087bd2 bb06a060 f4ed260f
  limbs: 0x3457e06, 0x1812abf, 0x350598d, 0x08a5be8, 0x316874f, 0x1fc4f7e, 0x1846e01, 0x0d77a4f, 0x3460a00, 0x03c9bb7
sqrt(-1)sqrt(A+2): e781ba00 55fb9133 7de582b4 2e2c5e3a 81b003fc 23f7842d 44f95f9f 0b12d970
  limbs: 0x0ba81e7, 0x07ed540, 0x0afa672, 0x175a417, 0x0e978b0, 0x003b081, 0x27b91fe, 0x12885b0, 0x0b9f5ff, 0x1c36448
*/

#if AMBER_LIMB_BITS == 32
static const Fe sqrtmA2 = { 0x0ba81e7, 0x07ed540, 0x0afa672, 0x175a417, 0x0e978b0,
                            0x003b081, 0x27b91fe, 0x12885b0, 0x0b9f5ff, 0x1c36448 };
#elif AMBER_LIMB_BITS >= 64
static const Fe sqrtmA2 = { 0x1fb5500ba81e7, 0x5d6905cafa672, 0xec204e978b0,
                            0x4a216c27b91fe, 0x70d9120b9f5ff };
#endif

// (p-1)/2: 2²⁵⁴ - 10
static const uint8_t pm12[32] = {
	0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
};

// Return 1 if v > lim. Return 0 otherwise. Constant time.
uint32_t gt_than (const uint8_t v[32], const uint8_t lim[32])
{
	unsigned equal = 1;
	unsigned gt = 0;
	for (int i = 31; i >= 0; --i) {
		// This will be set if everything was equal until now and v[i]>lim[i].
		gt |= ((lim[i] - v[i]) >> 8) & equal;
		// Equal will be cleared when we encounter a difference.
		equal &= ((lim[i] ^ v[i]) - 1) >> 8;
	}
	return gt;
}

/* The formulas are :
	x, y: Edwards coordinates.
	u, v: Montgomery coordinates.
	1. Conversion from Edwards to Montgomery
	u = (1+y)/(1-y)
	v = sqrt(-1)*sqrt(A+2)*u/x

	2. Point to representative:
	if (v <= (p-1)/2) r = sqrt[u/(-2(u+A))]
	if (v > (p-1)/2)  r = sqrt[u/(-2u)]
	For this to work u != A and -2u(u+A) must be a square.
*/

int elligator2_p2r (Fe &r, const Fe &u, const Fe &v)
{
	Fe upa = u;
	upa.v[0] += 486662;
	Fe uua = u;
	mul (uua, upa, u);      // uua = u(u+A)
	add (uua, uua, uua);
	negate (uua, uua);      // uua = -2u(u+A)

	Fe riuua;
	if (invsqrt (riuua, uua) != 0) {   // riuua = 1/sqrt(-2u(u+A))
		// If -2u(u+A) is not a square then we cannot compute the
		// representative. Return -1 to signal an error.
		return -1;
	}

	Fe r1, r2;
	mul (r1, u, riuua);         // r1 = sqrt(-u/(2(u+A)))
	mul (r2, upa, riuua);       // r2 = sqrt(-(u+A)/(2u)))

	uint8_t bv[32];
	Fe tmpv = v;
	reduce_store (bv, tmpv);
	uint32_t swap = gt_than (bv, pm12);

	// Select r1 if bv < (q-1)/2 otherwise r2
	cswap (r1, r2, swap);

	reduce_store (bv, r1);
	negate (r2, r1);
	// Select r or -r. Both are valid as numbers, but we want to have the one
	// that fits in 253 bits. Select the smaller one.
	cswap (r1, r2, gt_than (bv, pm12));
	r = r1;

	// Now we have r as a number. When storing it as bits, bit 253 and 254
	// will be set to zero. Fill them with random bits before using the
	// representative.
	return 0;
}

int elligator2_p2r (Fe &r, Fe &u, const Edwards &p)
{
	// First compute u and v.
	Fe invxzy;
	sub (invxzy, p.z, p.y);
	mul (invxzy, invxzy, p.x);
	invert (invxzy, invxzy);  // invxzy = 1/(x(z-y))

	Fe zpy;
	add_no_reduce (zpy, p.z, p.y);    // zpy = z + y
	Fe v;
	mul (v, zpy, invxzy);   // (z+y)/(z-y)/x
	mul (u, v, p.x);        // (z+y)/(z-y)
	mul (v, v, p.z);        // (z+y)/(z-y)*(z/x)
	mul (v, v, sqrtmA2);    // sqrt(-1)*sqrt(A+2)*(z+y)/(z-y)*(z/x)

	return elligator2_p2r (r, u, v);
}


/* Map from r to u.
	d = -A/(1 + 2r²)
	ε = (d³ + Ad² + d)^(2²⁵⁴ - 5)
	ε is either -1 or 1.
	if ε == 1 then u = d
	if ε == -1 then u = -A - d
*/
void elligator2_r2u (Fe &u, const Fe &r)
{
	Fe d, d2, d3, e;
	enum { A = 486662 };

	square (d, r);
	add_no_reduce (d, d, d);
	d.v[0]++;
	invert (d, d);
	mul_small (d, d, A);
	negate (d, d);
	// d = -A/(1 + 2r²)

	square (d2, d);
	mul (d3, d2, d);
	add (e, d3, d);
	mul_small (d2, d2, A);
	add (e, e, d2);
	// e = d³ + Ad² + d

	raise_254_10 (e, e);
	// ε = (d³ + Ad² + d)^(2²⁵⁴ - 5)

	uint8_t re[32];
	reduce_store (re, e);

	// e is either 1 or -1.
	// if e == 1 then u = d
	// if e == -1 then u = -A - d

	// Select the correct result in constant time.
	uint32_t eisminus1 = e.v[1] & 1;
	Fe tmp;
	negate (tmp, d);
	cswap (tmp, d, eisminus1);   // Now d = e == -1 ? -d : d
	tmp = fezero;
	Fe av = fezero;
	av.v[0] = A;
	cswap (av, tmp, eisminus1);   // Now tmp = e == -1 ? A : 0

	sub (u, d, tmp);
}

void increment (uint8_t scalar[32], int delta)
{
	// Keep all increments a multiple of the cofactor.
	uint32_t carry = delta*8;
	// Do not touch the last byte.
	for (int i = 0; i < 31; ++i) {
		carry += scalar[i];
		scalar[i] = carry & 0xFF;
		carry >>= 8;
	}
}



// Load a byte string into the limb form.
void load (Fe64 &fe, const uint8_t b[32])
{
	// Loads 255 bits from b. Ignores the top most bit.

	/*             8          16     24     32    40     48     51
		 0- 50   b[0]        b[1]   b[2]   b[3]  b[4]   b[5]   b[6] & 0x7

				   5          13     21     29    37     45     51
		51-101   b[6] >> 3   b[7]   b[8]   b[9]  b[10]  b[11]  b[12] & 0x3F

				   2          10     18     26    34     42     50     51
	   102-152   b[12] >> 6  b[13]  b[14]  b[15] b[16]  b[17]  b[18]  b[19] & 0x1

				   7          15     23     31    39     47     51
	   153-203   b[19] >> 1  b[20]  b[21]  b[22] b[23]  b[24]  b[25] & 0xF

				   4          12     20     28    36     44     51
	   204-254   b[25] >> 4  b[26]  b[27]  b[28] b[29]  b[30]  b[31] & 0x7F
	*/
	fe.v[0] = uint64_t(b[0]) | (uint64_t(b[1]) << 8) | (uint64_t(b[2]) << 16) |
	          (uint64_t(b[3]) << 24) | (uint64_t(b[4]) << 32) | (uint64_t(b[5]) << 40) |
	          ((uint64_t(b[6]) & 0x7) << 48);
	fe.v[1] = (uint64_t(b[6]) >> 3)  | (uint64_t(b[7]) << 5) | (uint64_t(b[8]) << 13) |
	          (uint64_t(b[9]) << 21) | (uint64_t(b[10]) << 29) | (uint64_t(b[11]) << 37) |
	         ((uint64_t(b[12]) & 0x3F) << 45);
	fe.v[2] = (uint64_t(b[12]) >> 6)  | (uint64_t(b[13]) << 2) | (uint64_t(b[14]) << 10) |
	          (uint64_t(b[15]) << 18) | (uint64_t(b[16]) << 26) | (uint64_t(b[17]) << 34) |
	          (uint64_t(b[18]) << 42) | ((uint64_t(b[19]) & 0x1) << 50);
	fe.v[3] = (uint64_t(b[19]) >> 1)  | (uint64_t(b[20]) << 7) | (uint64_t(b[21]) << 15) |
	          (uint64_t(b[22]) << 23) | (uint64_t(b[23]) << 31) | (uint64_t(b[24]) << 39) |
	          ((uint64_t(b[25]) & 0xF) << 47);
	fe.v[4] = (uint64_t(b[25]) >> 4)  | (uint64_t(b[26]) << 4) | (uint64_t(b[27]) << 12) |
	          (uint64_t(b[28]) << 20) | (uint64_t(b[29]) << 28) | (uint64_t(b[30]) << 36) |
	          ((uint64_t(b[31]) & 0x7F) << 44);
}


// Reduce the coefficients to their nominal bit ranges. It may be > p.
inline void reduce (Fe64 &fe)
{
	uint64_t c;

	c = fe.v[0];    fe.v[0] = c & mask51;  c >>= 51;
	c += fe.v[1];   fe.v[1] = c & mask51;  c >>= 51;
	c += fe.v[2];   fe.v[2] = c & mask51;  c >>= 51;
	c += fe.v[3];   fe.v[3] = c & mask51;  c >>= 51;
	c += fe.v[4];   fe.v[4] = c & mask51;  c >>= 51;
	fe.v[0] += 19 * c;
}

inline void add_bits64 (uint8_t *b, uint64_t c)
{
	b[0] |= c & 0xFF;
	b[1] = (c >> 8) & 0xFF;
	b[2] = (c >> 16) & 0xFF;
	b[3] = (c >> 24) & 0xFF;
	b[4] = (c >> 32) & 0xFF;
	b[5] = (c >> 40) & 0xFF;
	b[6] = (c >> 48) & 0xFF;
	b[7] = (c >> 56) & 0xFF;
}


// Fully reduce to mod p and store it in byte form.
void reduce_store (uint8_t b[32], Fe64 &fe)
{
	reduce (fe);
	reduce (fe);
	// Now we have fe between 0 and 2²⁵⁵ - 1.
	// Add 19 and reduce.
	fe.v[0] += 19;
	reduce (fe);
	// Now we have fe between 19 and 2²⁵⁵ - 1.
	// Substract 19. Do this by adding 2²⁵⁶ - 19 = 2²⁵⁶ - 1 - 18. This is the
	// same as having all bits 1 and substract 18. Then disregard all bits
	// beyond 255.
	uint64_t c;
	c = fe.v[0] + mask51 - 18;  fe.v[0] = c & mask51;   c >>= 51;
	c += fe.v[1] + mask51;      fe.v[1] = c & mask51;   c >>= 51;
	c += fe.v[2] + mask51;      fe.v[2] = c & mask51;   c >>= 51;
	c += fe.v[3] + mask51;      fe.v[3] = c & mask51;   c >>= 51;
	c += fe.v[4] + mask51;      fe.v[4] = c & mask51;

	// Now pack it in bytes.
	b[0] = 0;
	add_bits64 (b +  0, fe.v[0]);        // 0-50
	add_bits64 (b +  6, fe.v[1] << 3);   // 51 - 101
	add_bits64 (b + 12, fe.v[2] << 6);   // 102 - 152
	add_bits64 (b + 19, fe.v[3] << 1);   // 153 - 203
	c = fe.v[4] << 4;
	b[25] |= c & 0xFF;  c >>= 8;
	b[26] = c & 0xFF;   c >>= 8;
	b[27] = c & 0xFF;   c >>= 8;
	b[28] = c & 0xFF;   c >>= 8;
	b[29] = c & 0xFF;   c >>= 8;
	b[30] = c & 0xFF;   c >>= 8;
	b[31] = c & 0xFF;
}

// Fully reduce to mod p
void reduce_full (Fe64 &fe)
{
	reduce (fe);
	reduce (fe);
	// Now we have fe between 0 and 2²⁵⁵ - 1.
	// Add 19 and reduce.
	fe.v[0] += 19;
	reduce (fe);
	// Now we have fe between 19 and 2²⁵⁵ - 1.
	// Substract 19. Do this by adding 2²⁵⁶ - 19 = 2²⁵⁶ - 1 - 18. This is the
	// same as having all bits 1 and substract 18. Then disregard all bits
	// beyond 255.
	uint64_t c;
	c = fe.v[0] + mask51 - 18;  fe.v[0] = c & mask51;   c >>= 51;
	c += fe.v[1] + mask51;      fe.v[1] = c & mask51;   c >>= 51;
	c += fe.v[2] + mask51;      fe.v[2] = c & mask51;   c >>= 51;
	c += fe.v[3] + mask51;      fe.v[3] = c & mask51;   c >>= 51;
	c += fe.v[4] + mask51;      fe.v[4] = c & mask51;
}


static void show_fe (std::ostream &os, const uint64_t rhs[5], const char *label=0)
{
	Fe64 tmp;
	for (int i = 0; i < 5; ++i) tmp.v[i] = rhs[i];

	uint8_t bytes[32];
	reduce_store (bytes, tmp);

	if (label) {
		os << label << ": ";
	}

	os << std::hex << std::setfill('0');
	int count = 0;
	for (int i = 0; i < 32; ++i) {
		std::cout << std::setw(2) << unsigned(bytes[i]);
		if (++count == 4 ) {
			std::cout << ' ';
			count = 0;
		}
	}
	os << std::dec;
	if (label) {
		os << '\n';
	}
}

std::ostream & operator<< (std::ostream &os, const Fe64 &rhs)
{
	show_fe (os, rhs.v);
	return os;
}


}}

