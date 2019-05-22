/*
 * Copyright (c) 2017-2019, P. Bernedo.
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

#include "tweetamber.hpp"
#include <stdexcept>
#include <string.h>
#include <vector>
#include <random>
#include <stdint.h>
#include <mutex>
#include <limits.h>

#if defined(__has_include)
	#if __has_include("pthread.h")
		#define USE_PTHREAD_ATFORK
	#endif
#endif

#if !defined(USE_PTHREAD_ATFORK) && defined(__unix__)
	#define USE_PTHREAD_ATFORK
#endif

#ifdef USE_PTHREAD_ATFORK
	#include <pthread.h>
#endif

namespace twamber {  namespace AMBER_SONAME {

// Hashing from the Blake2 reference implementation from RFC.

#ifndef ROTR64
#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

// Little-endian byte access.

#define B2B_GET64(p)                            \
	(((uint64_t) ((uint8_t *) (p))[0]) ^        \
	(((uint64_t) ((uint8_t *) (p))[1]) << 8) ^  \
	(((uint64_t) ((uint8_t *) (p))[2]) << 16) ^ \
	(((uint64_t) ((uint8_t *) (p))[3]) << 24) ^ \
	(((uint64_t) ((uint8_t *) (p))[4]) << 32) ^ \
	(((uint64_t) ((uint8_t *) (p))[5]) << 40) ^ \
	(((uint64_t) ((uint8_t *) (p))[6]) << 48) ^ \
	(((uint64_t) ((uint8_t *) (p))[7]) << 56))

// G Mixing function.

#define B2B_G(a, b, c, d, x, y) {   \
	v[a] = v[a] + v[b] + x;         \
	v[d] = ROTR64(v[d] ^ v[a], 32); \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR64(v[b] ^ v[c], 24); \
	v[a] = v[a] + v[b] + y;         \
	v[d] = ROTR64(v[d] ^ v[a], 16); \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR64(v[b] ^ v[c], 63); }

// Initialization Vector.

static const uint64_t blake2b_iv[8] = {
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// Compression function. "last" flag indicates last block.
static void blake2b_compress(blake2b_ctx *ctx, int last)
{
	const uint8_t sigma[12][16] = {
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
		{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
		{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
		{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
		{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
	};
	int i;
	uint64_t v[16], m[16];

	for (i = 0; i < 8; i++) {           // init work variables
		v[i] = ctx->h[i];
		v[i + 8] = blake2b_iv[i];
	}

	v[12] ^= ctx->t[0];                 // low 64 bits of offset
	v[13] ^= ctx->t[1];                 // high 64 bits
	if (last)                           // last block flag set ?
		v[14] = ~v[14];

	for (i = 0; i < 16; i++)            // get little-endian words
		m[i] = B2B_GET64(&ctx->b[8 * i]);

	for (i = 0; i < 12; i++) {          // twelve rounds
		B2B_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
		B2B_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
		B2B_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
		B2B_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
		B2B_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
		B2B_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
		B2B_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
		B2B_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
	}

	for( i = 0; i < 8; ++i )
		ctx->h[i] ^= v[i] ^ v[i + 8];
}

int blake2b_init (blake2b_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen)        // (keylen=0: no key)
{
	size_t i;

	if (outlen == 0) {
		throw std::runtime_error ("Blake2b cannot be used to output 0 bytes.");
	}
	if (outlen > 64) {
		throw std::runtime_error ("Blake2b cannot be output more than 64 bytes.");
	}
	if (keylen > 64) {
		throw std::runtime_error ("Blake2b cannot be use more than 64 bytes of key.");
	}

	for (i = 0; i < 8; i++)             // state, "param block"
		ctx->h[i] = blake2b_iv[i];
	ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

	ctx->t[0] = 0;                      // input count low word
	ctx->t[1] = 0;                      // input count high word
	ctx->c = 0;                         // pointer within buffer
	ctx->outlen = outlen;

	for (i = keylen; i < 128; i++)      // zero input block
		ctx->b[i] = 0;
	if (keylen > 0) {
		blake2b_update(ctx, key, keylen);
		ctx->c = 128;                   // at the end
	}

	return 0;
}

void blake2b_update (blake2b_ctx *ctx, const void *in, size_t inlen)
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		if (ctx->c == 128) {            // buffer full ?
			ctx->t[0] += ctx->c;        // add counters
			if (ctx->t[0] < ctx->c)     // carry overflow ?
				ctx->t[1]++;            // high word
			blake2b_compress(ctx, 0);   // compress (not last)
			ctx->c = 0;                 // counter to zero
		}
		ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
	}
}

void blake2b_final (blake2b_ctx *ctx, void *out)
{
	size_t i;

	ctx->t[0] += ctx->c;                // mark last block offset
	if (ctx->t[0] < ctx->c)             // carry overflow
		ctx->t[1]++;                    // high word

	while (ctx->c < 128)                // fill up with zeros
		ctx->b[ctx->c++] = 0;
	blake2b_compress(ctx, 1);           // final block flag = 1

	// little endian convert and store
	for (i = 0; i < ctx->outlen; i++) {
		((uint8_t *) out)[i] =
			(ctx->h[i >> 3] >> (8 * (i & 7))) & 0xFF;
	}
}

int blake2b (void *out, size_t outlen,
             const void *key, size_t keylen,
             const void *in, size_t inlen)
{
	blake2b_ctx ctx;

	if (blake2b_init(&ctx, outlen, key, keylen))
		return -1;
	blake2b_update(&ctx, in, inlen);
	blake2b_final(&ctx, out);

	return 0;
}

#ifndef ROTR32
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#endif

#define B2S_G(a, b, c, d, x, y) {   \
	v[a] = v[a] + v[b] + x;         \
	v[d] = ROTR32(v[d] ^ v[a], 16); \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR32(v[b] ^ v[c], 12); \
	v[a] = v[a] + v[b] + y;         \
	v[d] = ROTR32(v[d] ^ v[a], 8);  \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR32(v[b] ^ v[c], 7); }

// Initialization Vector.

static const uint32_t blake2s_iv[8] =
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Compression function. "last" flag indicates last block.
static void blake2s_compress(blake2s_ctx *ctx, int last)
{
	const uint8_t sigma[10][16] = {
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
		{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
		{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
		{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
		{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
	};
	int i;
	uint32_t v[16], m[16];

	for (i = 0; i < 8; i++) {           // init work variables
		v[i] = ctx->h[i];
		v[i + 8] = blake2s_iv[i];
	}

	v[12] ^= ctx->t[0];                 // low 32 bits of offset
	v[13] ^= ctx->t[1];                 // high 32 bits
	if (last)                           // last block flag set ?
		v[14] = ~v[14];

	for (i = 0; i < 16; i++)            // get little-endian words
		m[i] = leget32 (&ctx->b[4 * i]);

	for (i = 0; i < 10; i++) {          // ten rounds
		B2S_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
		B2S_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
		B2S_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
		B2S_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
		B2S_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
		B2S_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
		B2S_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
		B2S_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
	}

	for( i = 0; i < 8; ++i )
		ctx->h[i] ^= v[i] ^ v[i + 8];
}

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 32 gives the digest size in bytes.
//      Secret key (also <= 32 bytes) is optional (keylen = 0).

int blake2s_init (blake2s_ctx *ctx, size_t outlen,
    const void *key, size_t keylen)     // (keylen=0: no key)
{
	size_t i;

	if (outlen == 0 || outlen > 32 || keylen > 32)
		return -1;                      // illegal parameters

	for (i = 0; i < 8; i++)             // state, "param block"
		ctx->h[i] = blake2s_iv[i];
	ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

	ctx->t[0] = 0;                      // input count low word
	ctx->t[1] = 0;                      // input count high word
	ctx->c = 0;                         // pointer within buffer
	ctx->outlen = outlen;

	for (i = keylen; i < 64; i++)       // zero input block
		ctx->b[i] = 0;
	if (keylen > 0) {
		blake2s_update(ctx, key, keylen);
		ctx->c = 64;                    // at the end
	}

	return 0;
}

// Add "inlen" bytes from "in" into the hash.

void blake2s_update(blake2s_ctx *ctx,
    const void *in, size_t inlen)       // data bytes
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		if (ctx->c == 64) {             // buffer full ?
			ctx->t[0] += ctx->c;        // add counters
			if (ctx->t[0] < ctx->c)     // carry overflow ?
				ctx->t[1]++;            // high word
			blake2s_compress(ctx, 0);   // compress (not last)
			ctx->c = 0;                 // counter to zero
		}
		ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
	}
}

// Generate the message digest (size given in init).
//      Result placed in "out".

void blake2s_final(blake2s_ctx *ctx, void *out)
{
	size_t i;

	ctx->t[0] += ctx->c;                // mark last block offset
	if (ctx->t[0] < ctx->c)             // carry overflow
		ctx->t[1]++;                    // high word

	while (ctx->c < 64)                 // fill up with zeros
		ctx->b[ctx->c++] = 0;
	blake2s_compress(ctx, 1);           // final block flag = 1

	// little endian convert and store
	for (i = 0; i < ctx->outlen; i++) {
		((uint8_t *) out)[i] =
			(ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
	}
}


// Poly1305 donna implementation.

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
	unsigned long r[5];
	unsigned long h[5];
	unsigned long pad[4];
	size_t leftover;
	unsigned char buffer[poly1305_block_size];
	unsigned char final;
} poly1305_state_internal_t;


void poly1305_init(poly1305_context *ctx, const unsigned char key[32])
{
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = (leget32(&key[ 0])     ) & 0x3ffffff;
	st->r[1] = (leget32(&key[ 3]) >> 2) & 0x3ffff03;
	st->r[2] = (leget32(&key[ 6]) >> 4) & 0x3ffc0ff;
	st->r[3] = (leget32(&key[ 9]) >> 6) & 0x3f03fff;
	st->r[4] = (leget32(&key[12]) >> 8) & 0x00fffff;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;

	/* save pad for later */
	st->pad[0] = leget32(&key[16]);
	st->pad[1] = leget32(&key[20]);
	st->pad[2] = leget32(&key[24]);
	st->pad[3] = leget32(&key[28]);

	st->leftover = 0;
	st->final = 0;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
	const unsigned long hibit = (st->final) ? 0 : (1 << 24); /* 1 << 128 */
	unsigned long r0,r1,r2,r3,r4;
	unsigned long s1,s2,s3,s4;
	unsigned long h0,h1,h2,h3,h4;
	unsigned long long d0,d1,d2,d3,d4;
	unsigned long c;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (bytes >= poly1305_block_size) {
		/* h += m[i] */
		h0 += (leget32(m+ 0)     ) & 0x3ffffff;
		h1 += (leget32(m+ 3) >> 2) & 0x3ffffff;
		h2 += (leget32(m+ 6) >> 4) & 0x3ffffff;
		h3 += (leget32(m+ 9) >> 6) & 0x3ffffff;
		h4 += (leget32(m+12) >> 8) | hibit;

		/* h *= r */
		d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
		d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
		d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
		d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
		d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

		/* (partial) h %= p */
					  c = (unsigned long)(d0 >> 26); h0 = (unsigned long)d0 & 0x3ffffff;
		d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
		d2 += c;      c = (unsigned long)(d2 >> 26); h2 = (unsigned long)d2 & 0x3ffffff;
		d3 += c;      c = (unsigned long)(d3 >> 26); h3 = (unsigned long)d3 & 0x3ffffff;
		d4 += c;      c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
		h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
		h1 += c;

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

void poly1305_finish(poly1305_context *ctx, unsigned char mac[16])
{
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long h0,h1,h2,h3,h4,c;
	unsigned long g0,g1,g2,g3,g4;
	unsigned long long f;
	unsigned long mask;

	/* process the remaining block */
	if (st->leftover) {
		size_t i = st->leftover;
		st->buffer[i++] = 1;
		for (; i < poly1305_block_size; i++)
			st->buffer[i] = 0;
		st->final = 1;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

				 c = h1 >> 26; h1 = h1 & 0x3ffffff;
	h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
	h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
	h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
	h1 +=     c;

	/* compute h + -p */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1 << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

	/* mac = (h + pad) % (2^128) */
	f = (unsigned long long)h0 + st->pad[0]            ; h0 = (unsigned long)f;
	f = (unsigned long long)h1 + st->pad[1] + (f >> 32); h1 = (unsigned long)f;
	f = (unsigned long long)h2 + st->pad[2] + (f >> 32); h2 = (unsigned long)f;
	f = (unsigned long long)h3 + st->pad[3] + (f >> 32); h3 = (unsigned long)f;

	leput32(mac +  0, h0);
	leput32(mac +  4, h1);
	leput32(mac +  8, h2);
	leput32(mac + 12, h3);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->r[3] = 0;
	st->r[4] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;
	st->pad[2] = 0;
	st->pad[3] = 0;
}

void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes)
{
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	size_t i;

	/* handle leftover */
	if (st->leftover) {
		size_t want = (poly1305_block_size - st->leftover);
		if (want > bytes)
			want = bytes;
		for (i = 0; i < want; i++)
			st->buffer[st->leftover + i] = m[i];
		bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < poly1305_block_size)
			return;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= poly1305_block_size) {
		size_t want = (bytes & ~(poly1305_block_size - 1));
		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i = 0; i < bytes; i++)
			st->buffer[st->leftover + i] = m[i];
		st->leftover += bytes;
	}
}


// Support.


int crypto_equal (const void *vp1, const void *vp2, size_t n)
{
	const unsigned char *v1 = (const unsigned char*)vp1;
	const unsigned char *v2 = (const unsigned char*)vp2;
	unsigned diff = 0;
	size_t i;
	for (i = 0; i < n; ++i) {
		diff |= v1[i] ^ v2[i];
	}
	// Only the lower 8 bits may be non zero. diff-1 will have the high bit
	// set only and only if diff was zero.
	diff = (diff - 1) >> (sizeof(unsigned)*8 - 1);
	return diff & 1;
}

int crypto_neq (const void *vp1, const void *vp2, size_t n)
{
	const unsigned char *v1 = (const unsigned char*)vp1;
	const unsigned char *v2 = (const unsigned char*)vp2;
	unsigned diff = 0;
	size_t i;
	for (i = 0; i < n; ++i) {
		diff |= v1[i] ^ v2[i];
	}
	// Only the lower 8 bits may be non zero. diff-1 will have the high bit
	// set only and only if diff was zero.
	diff = (diff - 1) >> (sizeof(unsigned)*8 - 1);
	return diff ^ 1;
}

int is_zero(const void *vp1, size_t n)
{
	const unsigned char *v1 = (const unsigned char*)vp1;
	unsigned diff = 0;
	size_t i;
	for (i = 0; i < n; ++i) {
		diff |= v1[i];
	}

	diff = (diff - 1) >> (sizeof(unsigned)*CHAR_BIT - 1);
	return diff;
}


// Chacha.
inline uint32_t rotl32 (const uint32_t w, const unsigned c)
{
  return ( w << c ) | ( w >> ( 32 - c ) );
}
inline void chacha_quarterround (uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a += *b;  *d = rotl32 (*d ^ *a, 16);
	*c += *d;  *b = rotl32 (*b ^ *c, 12);
	*a += *b;  *d = rotl32 (*d ^ *a, 8);
	*c += *d;  *b = rotl32 (*b ^ *c, 7);
}
inline void chacha_doubleround (uint32_t x[16])
{
	chacha_quarterround (x + 0, x + 4, x + 8,  x + 12);
	chacha_quarterround (x + 1, x + 5, x + 9,  x + 13);
	chacha_quarterround (x + 2, x + 6, x + 10, x + 14);
	chacha_quarterround (x + 3, x + 7, x + 11, x + 15);

	chacha_quarterround (x + 0, x + 5, x + 10, x + 15);
	chacha_quarterround (x + 1, x + 6, x + 11, x + 12);
	chacha_quarterround (x + 2, x + 7, x +  8, x + 13);
	chacha_quarterround (x + 3, x + 4, x +  9, x + 14);
}


void chacha20 (uint8_t out[64], const uint32_t kn[12])
{
	int i;
	uint32_t x[16];
	x[0] = 0x61707865;
	x[1] = 0x3320646e;
	x[2] = 0x79622d32;
	x[3] = 0x6b206574;

	x[4] = kn[0];
	x[5] = kn[1];
	x[6] = kn[2];
	x[7] = kn[3];
	x[8] = kn[4];
	x[9] = kn[5];
	x[10] = kn[6];
	x[11] = kn[7];
	x[12] = kn[8];
	x[13] = kn[9];
	x[14] = kn[10];
	x[15] = kn[11];

	for (i = 0; i < 10; ++i) {
		chacha_doubleround(x);
	}

	leput32 (out + 0, x[0] + 0x61707865);
	leput32 (out + 4, x[1] + 0x3320646e);
	leput32 (out + 8, x[2] + 0x79622d32);
	leput32 (out + 12, x[3] + 0x6b206574);
	leput32 (out + 16, x[4] + kn[0]);
	leput32 (out + 20, x[5] + kn[1]);
	leput32 (out + 24, x[6] + kn[2]);
	leput32 (out + 28, x[7] + kn[3]);
	leput32 (out + 32, x[8] + kn[4]);
	leput32 (out + 36, x[9] + kn[5]);
	leput32 (out + 40, x[10] + kn[6]);
	leput32 (out + 44, x[11] + kn[7]);
	leput32 (out + 48, x[12] + kn[8]);
	leput32 (out + 52, x[13] + kn[9]);
	leput32 (out + 56, x[14] + kn[10]);
	leput32 (out + 60, x[15] + kn[11]);
}


void chacha20 (uint8_t out[64], const Chakey &key, uint64_t n64, uint64_t bn)
{
	int i;
	uint32_t x[16];
	x[0] = 0x61707865;
	x[1] = 0x3320646e;
	x[2] = 0x79622d32;
	x[3] = 0x6b206574;

	x[4] = key.kw[0];
	x[5] = key.kw[1];
	x[6] = key.kw[2];
	x[7] = key.kw[3];
	x[8] = key.kw[4];
	x[9] = key.kw[5];
	x[10] = key.kw[6];
	x[11] = key.kw[7];
	x[12] = bn & 0xFFFFFFFF;
	x[13] = bn >> 32;
	x[14] = n64 & 0xFFFFFFFF;
	x[15] = n64 >> 32;

	for (i = 0; i < 10; ++i) {
		chacha_doubleround(x);
	}

	leput32 (out + 0, x[0] + 0x61707865);
	leput32 (out + 4, x[1] + 0x3320646e);
	leput32 (out + 8, x[2] + 0x79622d32);
	leput32 (out + 12, x[3] + 0x6b206574);
	leput32 (out + 16, x[4] + key.kw[0]);
	leput32 (out + 20, x[5] + key.kw[1]);
	leput32 (out + 24, x[6] + key.kw[2]);
	leput32 (out + 28, x[7] + key.kw[3]);
	leput32 (out + 32, x[8] + key.kw[4]);
	leput32 (out + 36, x[9] + key.kw[5]);
	leput32 (out + 40, x[10] + key.kw[6]);
	leput32 (out + 44, x[11] + key.kw[7]);
	leput32 (out + 48, x[12] + (bn & 0xFFFFFFFF));
	leput32 (out + 52, x[13] + (bn >> 32));
	leput32 (out + 56, x[14] + (n64 & 0xFFFFFFFF));
	leput32 (out + 60, x[15] + (n64 >> 32));
}


void load (Chakey *kw, const uint8_t bytes[32])
{
	for (unsigned i = 0; i < 8; ++i) {
		kw->kw[i] = leget32 (bytes + i*4);
	}
}


static void chacha208 (uint32_t b[16])
{
	uint32_t x[16];
	unsigned i;
	memcpy(x, b, sizeof x);
	chacha_doubleround(x);
	chacha_doubleround(x);
	chacha_doubleround(x);
	chacha_doubleround(x);
	for (i = 0; i < 16; ++i) {
		b[i] += x[i];
	}
}

// See https://www.ietf.org/mail-archive/web/cfrg/current/msg04310.html for
// a discussion of the extension of the HSalsa20 proof to HChaCha20.

void hchacha20 (Chakey *out, const uint8_t key[32], const uint8_t n[16])
{
	int i;
	uint32_t x[16];
	x[0] = 0x61707865;
	x[1] = 0x3320646e;
	x[2] = 0x79622d32;
	x[3] = 0x6b206574;

	x[4] = leget32(key + 0);
	x[5] = leget32(key + 4);
	x[6] = leget32(key + 8);
	x[7] = leget32(key + 12);
	x[8] = leget32(key + 16);
	x[9] = leget32(key + 20);
	x[10] = leget32(key + 24);
	x[11] = leget32(key + 28);

	x[12] = leget32(n + 0);
	x[13] = leget32(n + 4);
	x[14] = leget32(n + 8);
	x[15] = leget32(n + 12);

	for (i = 0; i < 10; ++i) {
		chacha_doubleround(x);
	}

	out->kw[0] = x[0];
	out->kw[1] = x[1];
	out->kw[2] = x[2];
	out->kw[3] = x[3];
	out->kw[4] = x[12];
	out->kw[5] = x[13];
	out->kw[6] = x[14];
	out->kw[7] = x[15];
}


static void xor_stream (uint8_t *dst, const uint8_t *src, size_t len,
                        const Chakey &key, uint64_t n64)
{
	uint8_t stream[64];
	// We use block zero to generate authentication keys for Poly1305. We xor
	// starting with block one.
	uint64_t bn = 1;
	while (len >= 64) {
		chacha20 (stream, key, n64, bn++);
		for (unsigned i = 0; i < 64; ++i) {
			dst[i] = src[i] ^ stream[i];
		}
		dst += 64;
		src += 64;
		len -= 64;
	}
	if (len > 0) {
		chacha20 (stream, key, n64, bn);
		for (unsigned i = 0; i < len; ++i) {
			dst[i] = src[i] ^ stream[i];
		}
	}
}

inline void leput64 (unsigned char *x, uint64_t u)
{
	x[0] = u & 0xFF;
	x[1] = (u >> 8) & 0xFF;
	x[2] = (u >> 16) & 0xFF;
	x[3] = (u >> 24) & 0xFF;
	x[4] = (u >> 32) & 0xFF;
	x[5] = (u >> 40) & 0xFF;
	x[6] = (u >> 48) & 0xFF;
	x[7] = (u >> 56) & 0xFF;
}


// ChaChaPoly

void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
                    const uint8_t *ad, size_t alen, const Chakey &kw,
                    const Chakey *ka, size_t nka, uint64_t nonce64)
{
	uint8_t stream[64];

	xor_stream (cipher, m, mlen, kw, nonce64);

	static const uint8_t pad[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	size_t npad1 = alen % 16;
	if (npad1 != 0) {
		npad1 = 16 - npad1;
	}
	size_t npad2 = mlen % 16;
	if (npad2 != 0) {
		npad2 = 16 - npad2;
	}
	uint8_t alen_le[8], mlen_le[8];
	leput64 (alen_le, alen);
	leput64 (mlen_le, mlen);

	poly1305_context poc;
	// For each authentication key, compute the Poly1305 tag and append it to
	// the resulting ciphertext.
	uint64_t block_number = 0;
	// Create the poly key using the last blocks. We use a different block
	// for each key because keys could have been repeated and then the tags
	// would be identical. The first block is zero to be compatible with
	// existing implementations.
	for (unsigned i = 0; i < nka; ++i) {
		chacha20 (stream, ka[i], nonce64, block_number--);
		poly1305_init (&poc, stream);
		if (alen != 0) {
			poly1305_update (&poc, ad, alen);
			poly1305_update (&poc, pad, npad1);
		}
		poly1305_update (&poc, cipher, mlen);
		poly1305_update (&poc, pad, npad2);
		poly1305_update (&poc, alen_le, 8);
		poly1305_update (&poc, mlen_le, 8);
		poly1305_finish (&poc, cipher + mlen + i*16);
	}
}

int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen,
                   const uint8_t *ad, size_t alen, const Chakey &kw,
                   const Chakey &ka, size_t nka, size_t ika,
                   uint64_t nonce64)
{
	if (clen < nka*16) return -1;
	size_t mlen = clen - nka*16;

	uint8_t stream[64];

	uint64_t block_number = 0;
	block_number -= ika;
	chacha20 (stream, ka, nonce64, block_number);

	static const uint8_t pad[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	size_t npad1 = alen % 16;
	if (npad1 != 0) {
		npad1 = 16 - npad1;
	}
	size_t npad2 = mlen % 16;
	if (npad2 != 0) {
		npad2 = 16 - npad2;
	}
	uint8_t alen_le[8], mlen_le[8];
	leput64 (alen_le, alen);
	leput64 (mlen_le, mlen);

	poly1305_context poc;
	poly1305_init (&poc, stream);
	if (alen != 0) {
		poly1305_update (&poc, ad, alen);
		poly1305_update (&poc, pad, npad1);
	}
	poly1305_update (&poc, cipher, mlen);
	poly1305_update (&poc, pad, npad2);
	poly1305_update (&poc, alen_le, 8);
	poly1305_update (&poc, mlen_le, 8);

	uint8_t tag[16];
	poly1305_finish (&poc, tag);

	if (crypto_neq(tag, cipher + mlen + ika*16, 16)) return -1;
	xor_stream (m, cipher, mlen, kw, nonce64);
	return 0;
}


// Scrypt-Blake2b
static void pbkdf2_blake2b_f(const char *pass, size_t npass,
                             const uint8_t *salt, size_t nsalt,
                             unsigned count, uint8_t *t, int i)
{
	uint8_t be[4];
	be[0] = (i >> 24) & 0xFF;
	be[1] = (i >> 16) & 0xFF;
	be[2] = (i >> 8) & 0xFF;
	be[3] = i & 0xFF;

	// First round, as per RFC 2898. U_1 = PRF (P, S || INT (i))
	blake2b_ctx bs;
	if (0 != blake2b_init (&bs, 32, pass, npass)) {
		throw std::invalid_argument("blake2s_init_key failed, empty key?");
	}
	blake2b_update (&bs, salt, nsalt);
	blake2b_update (&bs, be, 4);
	uint8_t u[32];
	blake2b_final (&bs, u);
	memcpy(t, u, 32);

	unsigned j, k;
	for (j = 1; j < count; ++j) {
		if (0 != blake2b_init (&bs, 32, pass, npass)) {
			throw std::invalid_argument("blake2s_init_key failed, empty key?");
		}
		blake2b_update (&bs, u, sizeof u);
		blake2b_final (&bs, u);

		for (k = 0; k < 32; ++k) {
			t[k] ^= u[k];
		}
	}
}

// PBKDF2 using blake2b
static
void pbkdf2_blake2b (uint8_t *key, size_t nkey,
                     const char *pass, size_t npass,
                     const uint8_t *salt, size_t nsalt,
                     unsigned count)
{
	size_t pos = 0;
	int i = 1;

	while (nkey >= 32) {
		pbkdf2_blake2b_f(pass, npass, salt, nsalt, count, key + pos, i);
		pos += 32;
		++i;
		nkey -= 32;
	}

	if (nkey > 0) {
		uint8_t tmp[32];
		pbkdf2_blake2b_f(pass, npass, salt, nsalt, count, tmp, i);
		memcpy(key + pos, tmp, nkey);
	}
}

enum { blen = 16, b2len = 2*blen };  // 64 byte blocks.

// There are 2*r blocks of 64 bytes.
static void scrypt_block_mix(uint32_t *b, int r)
{
	uint32_t t[blen], x[blen];;
	int i, j;
	int last = 2 * r - 1;
	int blast = last * blen;
	std::vector<uint32_t> y(blen*2*r);

	for (j = 0; j < blen; ++j) {
		x[j] = b[blast + j];
	}

	for (i = 0; i <= last; ++i) {
		int bi = i * blen;
		for (j = 0; j < blen; ++j) {
			t[j] = x[j] ^ b[bi + j];
		}
		chacha208 (t);
		for (j = 0; j < blen; ++j) {
			y[i*blen + j] = x[j] = t[j];
		}
	}

	for (i = 0; i < r; ++i) {
		for (j = 0; j < blen; ++j) {
			b[i*blen + j] = y[2*i*blen + j];
			b[(r + i)*blen + j] = y[(2*i + 1)*blen + j];
		}
	}
}

inline void copy_full(uint32_t *dest, uint32_t *src, size_t n)
{
	size_t j;
	for (j = 0; j < n; ++j) {
		*dest++ = *src++;
	}
}

inline void xor_full(uint32_t *dest, const uint32_t *src, size_t n)
{
	size_t j;
	for (j = 0; j < n; ++j) {
		*dest++ ^= *src++;
	}
}

static void scrypt_romix(uint32_t *b, int r, int N)
{
	int i;
	size_t veclen = b2len * r;
	std::vector<uint32_t> x(veclen), v(veclen*N);

	copy_full (&x[0], b, veclen);

	for (i = 0; i < N; ++i) {
		copy_full (&v[veclen*i], &x[0], veclen);
		scrypt_block_mix(&x[0], r);
	}

	for (i = 0; i < N; ++i) {
		size_t pos = blen * (2*r - 1);
		uint64_t j = x[pos];
		j %= N;

		xor_full (&x[0], &v[j*veclen], veclen);
		scrypt_block_mix(&x[0], r);
	}

	copy_full (b, &x[0], veclen);
}

static void scrypt_romix2(unsigned char *b, int r, int N)
{
	unsigned i;
	size_t bwcount = b2len*r;
	std::vector<uint32_t> bw(bwcount);

	for (i = 0; i < bwcount; ++i) {
		bw[i] = leget32(b + i*4);
	}
	scrypt_romix(&bw[0], r, N);

	for (i = 0; i < bwcount; ++i) {
		leput32 (b + i*4, bw[i]);
	}
}


void scrypt_blake2b (uint8_t *dk, size_t dklen,
                     const char *pwd, size_t plen,
                     const uint8_t *salt, size_t slen,
                     int shifts, int r, int p)
{
	int i;
	int N = 1 << shifts;
	std::vector<uint8_t> b(128*r*p);

	try {
		pbkdf2_blake2b (&b[0], 128*r*p, pwd, plen, salt, slen, 1);

		for (i = 0; i < p; ++i) {
			scrypt_romix2(&b[128*r*i], r, N);
		}

		pbkdf2_blake2b (dk, dklen, pwd, plen, &b[0], 128*r*p, 1);
	} catch (...) {
		throw_with_nested (std::runtime_error("Scrypt-Blake2s has failed."));
	}
}

// Random generator.

static void cxx_random_device (void *vp, size_t n)
{
	static std::random_device rd;
	typedef std::random_device::result_type Re; // C++11 defines this to be unsigned int.

	// C++11 also defined rd.min() to be 0 and rd.max() to be UINT_MAX.
	uint8_t *dest = (uint8_t*) vp;
	Re v;
	while (n > sizeof(v)) {
		v = rd();
		memcpy (dest, &v, sizeof v);
		n -= sizeof v;
		dest += sizeof v;
	}
	if (n > 0) {
		v = rd();
		memcpy (dest, &v, n);
	}
}

struct Rng_state {
	uint32_t kn[12];
	int count;
	Rng_state() { refresh(); }
	void refresh();
};

void Rng_state::refresh()
{
	uint32_t v[12];
	cxx_random_device (&v, sizeof v);
	// XOR with the existing state. This adds entropy, but does not replace
	// it.
	for (unsigned i = 0; i < 12; ++i) {
		kn[i] ^= v[i];
	}
	count = 0;
}


static Rng_state rngstate;
static std::mutex rngmtx;

#ifdef USE_PTHREAD_ATFORK
class Install_fork_handler {
public:
	Install_fork_handler();
};

static void refresh_rngstate()
{
	std::lock_guard<std::mutex> lk(rngmtx);
	rngstate.refresh();
}

Install_fork_handler::Install_fork_handler()
{
	pthread_atfork (NULL, NULL, refresh_rngstate);
}

static Install_fork_handler fork_handler;
#endif

void randombytes_buf (void *buf, size_t n)
{
	// The state is globally shared among all threads. We must lock.
	std::lock_guard<std::mutex> lk(rngmtx);

	uint8_t *b8 = (uint8_t*)buf;
	rngstate.count += n;
	while (n >= 64) {
		chacha20 (b8, rngstate.kn);
		rngstate.kn[11]++;
		n -= 64;
		b8 += 64;
	}
	uint8_t b[64];
	if (n > 0) {
		chacha20 (b, rngstate.kn);
		memcpy (b8, b, n);
		rngstate.kn[11]++;
	}
	// Use DJB's recommendation of resetting the state of the RNG.
	chacha20 (b, rngstate.kn);
	memcpy (rngstate.kn, b, 12*4);

	// Every now and then refresh the state by adding more entropy from the
	// std::random_device.
	if (rngstate.count > 1000000) {
		rngstate.refresh();
	}
}

typedef Blake2s Blake;

// Noise protocol
void mix_hash (uint8_t h[32], const uint8_t *data, size_t n)
{
	Blake b (32, NULL, 0);
	b.update (h, 32);
	b.update (data, n);
	b.final (h);
}

void mix_hash_init (uint8_t ck[32], uint8_t h[32], const char *protocol,
                    const uint8_t *pro, size_t plen)
{
	size_t n = strlen (protocol);
	if (n <= 32) {
		memcpy (h, protocol, n);
		memset (h + n, 0, 32 - n);
	} else {
		Blake b (32, NULL, 0);
		b.update (protocol, n);
		b.final (h);
	}
	memcpy (ck, h, 32);
	mix_hash (h, pro, plen);
}


void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n)
{
	Hkdf<Blake> hk (ck, 32);
	hk.add_input (ikm, n);
	hk.switch_to_output();
	const uint8_t *bp = hk.output_block();
	memcpy (ck, bp, 32);
	if (hk.hashlen < 64) {
		bp = hk.output_block();
	} else {
		bp += 32;
	}
	memcpy (k, bp, 32);
}

void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n)
{
	Hkdf<Blake> hk (ck, 32);
	hk.add_input (ikm, n);
	hk.switch_to_output();
	const uint8_t *bp = hk.output_block();
	memcpy (ck, bp, 32);
}


void encrypt_uint32 (uint8_t enc[4], const Chakey &ke, uint64_t nonce, uint32_t val)
{
	uint8_t stream[64];
	chacha20 (stream, ke, nonce, 0);
	uint8_t b[4];
	leput32 (b, val);
	for (unsigned i = 0; i < 4; ++i) enc[i] = b[i] ^ stream[32 + i];
}

uint32_t decrypt_uint32 (const uint8_t enc[4], const Chakey &ke, uint64_t nonce)
{
	uint8_t stream[64];
	chacha20 (stream, ke, nonce, 0);
	for (int i = 0; i < 4; ++i) stream[32 + i] ^= enc[i];
	return leget32 (stream + 32);
}



// Curve25519

struct Fe {
	uint64_t v[5];
};

enum { fecount = 10 };
enum { mask25 = (1 << 25) - 1, mask26 = (1 << 26) - 1 };
enum { mask51 = 0x7FFFFFFFFFFFF };

// p = 2²⁵⁵ - 19. The lowest limb of p has the representation p0. All other
// limbs of p have either mask25 or mask26.
static const uint64_t p0      = 0x7FFFFFFFFFFED;

// Four times P.
static const uint64_t four_p0 = 4*p0;
static const uint64_t four_mask51 = 4 * mask51;


// p = 2²⁵⁵-19
static const Fe p = { p0, mask51, mask51, mask51, mask51 };

static const Fe fezero = { 0 };
static const Fe feone = { 1 };
enum { A = 486662 };

// d = -121665/121666
static const Fe edwards_d = {  0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029,
                               0x739c663a03cbb, 0x52036cee2b6ff };

static const Fe edwards_2d = { 0x69b9426b2f159, 0x35050762add7a, 0x3cf44c0038052,
                               0x6738cc7407977, 0x2406d9dc56dff };

// sqrt(-1) = 2^(2²⁵³ - 5)
static const Fe root_minus_1 = { 0x61b274a0ea0b0, 0xd5a5fc8f189d, 0x7ef5e9cbd0c60,
                                 0x78595a6804c9e, 0x2b8324804fc1d };


// C = sqrt(-1)*sqrt(A+2)
static const Fe C = { 0x1fb5500ba81e7, 0x5d6905cafa672, 0xec204e978b0, 0x4a216c27b91fe,
                      0x70d9120b9f5ff };


// Base point in Montgomery.
static const Fe bu = { 9 };
static const Fe bv = { 0x1c5a27eced3d9, 0x7cdaf8c36453d, 0x523453248f535,
                       0x35a700f6e963b, 0x20ae19a1b8a08 };


// Load a byte string into the limb form.

void load (Fe &fe, const uint8_t b[32])
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


inline void add_no_reduce (Fe &res, const Fe &a, const Fe &b)
{
	res.v[0] = a.v[0] + b.v[0];
	res.v[1] = a.v[1] + b.v[1];
	res.v[2] = a.v[2] + b.v[2];
	res.v[3] = a.v[3] + b.v[3];
	res.v[4] = a.v[4] + b.v[4];
}

inline void add (Fe &res, const Fe &a, const Fe &b)
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
inline void sub (Fe &res, const Fe &a, const Fe &b)
{
	uint64_t c;
	c = four_p0 + a.v[0] - b.v[0];          res.v[0] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[1] - b.v[1];     res.v[1] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[2] - b.v[2];     res.v[2] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[3] - b.v[3];     res.v[3] = c & mask51;  c >>= 51;
	c += four_mask51 + a.v[4] - b.v[4];     res.v[4] = c & mask51;  c >>= 51;
	res.v[0] += c * 19;
}

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

#if AMBER_LIMB_BITS == 128

// Use uint128_t for the result of multiplying two 64 bit limbs.

// Multiply the number by a small number that fits in 32 bits.
inline void mul_small (Fe &res, const Fe &a, uint32_t bs)
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

inline void mul (Fe &res, const Fe &f, const Fe &g)
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

inline void square (Fe &res, const Fe &f)
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

#else

// 64 bit result.
inline uint64_t mul (uint32_t a, uint32_t b)
{
	return uint64_t(a) * uint64_t(b);
}

inline void mul (Fe &res, const Fe &f, const Fe &g)
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

// Same as before but with fewer multiplications.
inline void square (Fe &res, const Fe &f)
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


// We multiply two 64 bit limbs by decomposing them into two sublimbs with 25
// and 26 bits each. This mimics the decomposition into 25/26 bit limbs for
// the uint32_t representation.

// Multiply the number by a small number that fits in 32 bits.
inline void mul_small (Fe &res, const Fe &a, uint32_t bs)
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



#endif

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

static void invert (Fe &res, const Fe &z)
{
	Fe z11, tmp;// z¹¹
	raise_252_2 (tmp, z11, z);    // 2²⁵² - 2²
	square (tmp, tmp);      // 2²⁵³ - 2³
	square (tmp, tmp);      // 2²⁵⁴ - 2⁴
	square (tmp, tmp);      // 2²⁵⁵ - 2⁵
	mul (res, tmp, z11);    // 2²⁵⁵ - 21
}


// Reduce the coefficients to their nominal bit ranges. It may be > p.
inline void reduce (Fe &fe)
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

void reduce_store (uint8_t b[32], Fe &fe)
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


static void raise_252_3 (Fe &res, const Fe &z)
{
	Fe z11, tmp;
	raise_252_2 (tmp, z11, z);    // 2²⁵² - 2²
	mul (res, tmp, z);        // 2²⁵² - 3
}

inline void cswap (Fe &a, Fe &b, uint64_t flag)
{
	flag = ~ (flag - 1);
	uint64_t c;
	c = (a.v[0] ^ b.v[0]) & flag;  a.v[0] ^= c;  b.v[0] ^= c;
	c = (a.v[1] ^ b.v[1]) & flag;  a.v[1] ^= c;  b.v[1] ^= c;
	c = (a.v[2] ^ b.v[2]) & flag;  a.v[2] ^= c;  b.v[2] ^= c;
	c = (a.v[3] ^ b.v[3]) & flag;  a.v[3] ^= c;  b.v[3] ^= c;
	c = (a.v[4] ^ b.v[4]) & flag;  a.v[4] ^= c;  b.v[4] ^= c;
}

// Return 1 or 0. Constant time.
static uint8_t not_zero (const uint8_t *b, size_t n)
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

// Perform 4P - a. Avoids underflow to negative numbers.
inline void negate (Fe &res, const Fe &a)
{
	uint64_t c;
	c = four_p0 - a.v[0];          res.v[0] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[1];     res.v[1] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[2];     res.v[2] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[3];     res.v[3] = c & mask51;  c >>= 51;
	c += four_mask51 - a.v[4];     res.v[4] = c & mask51;  c >>= 51;
	res.v[0] += c * 19;
}

static int invsqrt (Fe &res, const Fe &x)
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

static void montgomery_ladder (Fe &x2, Fe &z2, Fe &x3, Fe &z3,
                               const Fe &x1, const uint8_t scalar[32])
{
	x2 = feone;
	z2 = fezero;
	x3 = x1;
	z3 = feone;
	Fe t1, t2, t3, t4, t5, t6, t7, t8, t9;
	// Are 2 and 3 swapped?
	uint32_t swapped = 0;
	for (int i = 254; i >= 0; --i) {
		uint32_t current = (scalar[i/8] >> (i & 7)) & 1;
		uint32_t flag = current ^ swapped;
		cswap (x2, x3, flag);
		cswap (z2, z3, flag);
		swapped = current;

		add (t1, x2, z2);
		sub (t2, x2, z2);
		add (t3, x3, z3);
		sub (t4, x3, z3);
		square (t6, t1);
		square (t7, t2);
		sub (t5, t6, t7);
		mul (t8, t4, t1);
		mul (t9, t3, t2);
		add (x3, t8, t9);
		square (x3, x3);
		sub (z3, t8, t9);
		square (z3, z3);
		mul (z3, z3, x1);
		mul (x2, t6, t7);
		mul_small (z2, t5, 121666);
		add (z2, z2, t7);
		mul (z2, z2, t5);
	}

	cswap (x2, x3, swapped);
	cswap (z2, z3, swapped);
}

static void montgomery_ladder (Fe &res, const Fe &xp, const uint8_t scalar[32])
{
	Fe x2, z2, x3, z3;
	montgomery_ladder (x2, z2, x3, z3, xp, scalar);
	invert (z2, z2);
	mul (res, x2, z2);
}

static void montgomery_ladder (Fe &u, Fe &z, const Fe &xp, const uint8_t scalar[32])
{
	Fe x3, z3;
	montgomery_ladder (u, z, x3, z3, xp, scalar);
}

// Montgomery ladder with recovery of projective X:Y:Z coordinates.
static void montgomery_ladder_uv (Fe &resu, Fe &resv, Fe &resz,
            const Fe &xpu, const Fe &xpv, const uint8_t scalar[32])
{
	Fe x2, z2, x3, z3;
	montgomery_ladder (x2, z2, x3, z3, xpu, scalar);

	// Algorithm 1 of Okeya and Sakurai, "Efficient Elliptic Curve
	// Cryptosystems from a Scalar multiplication algorithm with recovery of
	// the y-coordinate on a montgomery form elliptic curve.
	Fe t1, t2, t3, t4;
	mul (t1, xpu, z2);
	add (t2, x2, t1);
	sub (t3, x2, t1);
	square (t3, t3);
	mul (t3, t3, x3);
	mul_small (t1, z2, 2*A);
	add (t2, t2, t1);
	mul (t4, xpu, x2);
	add (t4, t4, z2);
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


typedef int32_t Limbtype;

// This is the order of the field in packed form.
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

// Store in dst the Montgomery u coordinate with the sign bit of the Edwards
// y coordinate. u,v,z are the projective Montgomery coordinates.
static void store_mxs (uint8_t *dst, const Fe &u, const Fe &v, const Fe &z)
{
	// y = (U-Z)/(U+Z) x = CU/V
	Fe t1, t2;
	mul (t1, v, z);
	invert (t1, t1);  // t1 = 1/(vz)
	mul (t2, u, t1);  // t2 = U/V/Z
	mul (t2, t2, v);  // t2 = U/Z
	reduce_store (dst, t2);
	mul (t2, C, u);   // t2 = CU
	mul (t2, t2, t1); // t2 = CU/V/Z
	mul (t2, t2, z);  // t2 = CU/V
	uint8_t tmp[32];
	reduce_store (tmp, t2);
	dst[31] |= (tmp[0] & 1) << 7;
}


void sign_bmx (const char *prefix, const uint8_t *m, size_t mlen,
               const uint8_t A[32], const uint8_t scalar[32], uint8_t sig[64])
{
	uint8_t hr[64], r[32], hram[64], rhram[32];

	blake2b (hr, 32, scalar, 32, NULL, 0);

	blake2b_ctx bs;
	blake2b_init (&bs, 64, NULL, 0);
	size_t plen;
	if (prefix != NULL) {
		plen = strlen (prefix) + 1;
		blake2b_update (&bs, prefix, plen);
	}
	blake2b_update (&bs, hr, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hr);
	reduce (r, hr);

	// R = rB
	Fe fu, fv, fz;
	montgomery_ladder_uv (fu, fv, fz, bu, bv, r);
	store_mxs (sig, fu, fv, fz);

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
	sig[63] |= A[31] & 0x80;
}


// Order of the group.
static const uint8_t order[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

// Return 1 if v > lim. Return 0 otherwise.
static uint32_t gt_than (const uint8_t v[32], const uint8_t lim[32])
{
	unsigned equal = 1;
	unsigned gt = 0;
	for (int i = 31; i >= 0; --i) {
		gt |= ((lim[i] - v[i]) >> 8) & equal;
		equal &= ((lim[i] ^ v[i]) - 1) >> 8;
	}
	return gt;
}

int verify_bmx (const char *prefix, const uint8_t *m, size_t mlen,
                const uint8_t sig[64], const uint8_t mx[32])
{
	uint8_t s[32];
	memcpy (s, sig + 32, 32);
	s[31] &= 0x7F;
	if (!gt_than (order, s)) {
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
	uint8_t mxs[32];
	memcpy (mxs, mx, 32);
	mxs[31] |= sig[63] & 0x80;

	blake2b_update (&bs, sig, 32);
	blake2b_update (&bs, mxs, 32);
	blake2b_update (&bs, m, mlen);
	blake2b_final (&bs, hram);

	uint8_t rhram[32];
	reduce (rhram, hram);

	// R = SB - hA
	Fe fu1, fu2, fz2, fu3, fz3;
	Fe tmp, s1, s2, femx;
	static const Fe ubase = { 9 };
	montgomery_ladder (fu2, fz2, ubase, s);
	load (femx, mx);
	montgomery_ladder (fu3, fz3, femx, rhram);
	load (fu1, sig);

	// We have computed sB and hA, which are in fu2/fz2 and fu3/fz3. Check if
	// R == ±SB ± hA
	/*  Sum condition for u: 4(u1 + u2 + u3 + A)(u1u2u3) = (1 - u1u2 - u2u3 - u3u1)²
		In projective coordinates:
		4 (U1.Z2.Z3 + U2.Z1.Z3 + U3.Z1.Z2 + A.Z1.Z2.Z3) (U1.U2.U3) = (Z1.Z2.Z3 - U1.U2.Z3 - U2.U3.Z1 - U3.U1.Z2)²

		Given that Z1 == 1.
		4 (U1.Z2.Z3 + U2.Z3 + U3.Z2 + A.Z2.Z3) (U1.U2.U3) = (Z2.Z3 - U1.U2.Z3 - U2.U3 - U3.U1.Z2)²
	*/

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


static void increment (uint8_t scalar[32], int delta)
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


/* sqrt(-1)*sqrt(A+2). Any of the two following values will do.
sqrt(-1)sqrt(A+2): 067e45ff aa046ecc 821a7d4b d1d3a1c5 7e4ffc03 dc087bd2 bb06a060 f4ed260f
  limbs: 0x3457e06, 0x1812abf, 0x350598d, 0x08a5be8, 0x316874f, 0x1fc4f7e, 0x1846e01, 0x0d77a4f, 0x3460a00, 0x03c9bb7
sqrt(-1)sqrt(A+2): e781ba00 55fb9133 7de582b4 2e2c5e3a 81b003fc 23f7842d 44f95f9f 0b12d970
  limbs: 0x0ba81e7, 0x07ed540, 0x0afa672, 0x175a417, 0x0e978b0, 0x003b081, 0x27b91fe, 0x12885b0, 0x0b9f5ff, 0x1c36448
*/

static const Fe sqrtmA2 = { 0x1fb5500ba81e7, 0x5d6905cafa672, 0xec204e978b0,
                            0x4a216c27b91fe, 0x70d9120b9f5ff };


// (p-1)/2: 2²⁵⁴ - 10
static const uint8_t pm12[32] = {
	0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
};

static int elligator2_p2r (Fe &r, const Fe &u, const Fe &v)
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


// Pass as input xs, filled with random bytes. The function will adjust xs
// and will compute xp and the corresponding representative.

void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Mon *xp, Cu25519Ell *rep)
{
	mask_scalar (xs->b);
	Fe fr, fmx, u, v, z;
	xs->b[0] -= 8;;
	// Keep trying until we find a point which has a representative.
	do {
		increment (xs->b, 1);
		montgomery_ladder_uv (u, v, z, bu, bv, xs->b);
		invert (z, z);
		mul (fmx, u, z);
		mul (v, v, z);
	} while (elligator2_p2r (fr, fmx, v) != 0);

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

void elligator2_r2u (Fe &u, const Fe &r)
{
	Fe d, d2, d3, e;
	enum { A = 486662 };

	square (d, r);
	add (d, d, d);
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

void cu25519_elligator2_rev (Cu25519Mon *u, const Cu25519Ell & rep)
{
	Fe fr, fu;
	load (fr, rep.b);

	// Ignore the last bit of fr. Load already discards bit 254. We must also
	// discard bit 253 because r < (p-1)/2 and the top two bits had been
	// filled with random bits.
	fr.v[4] &= (1ULL << 50) - 1;

	elligator2_r2u (fu, fr);
	reduce_store (u->b, fu);
}



void cu25519_shared_secret (uint8_t sh[32], const Cu25519Mon &xp, const Cu25519Sec &xs)
{
	Fe b, r;
	load (b, xp.b);
	montgomery_ladder (r, b, xs.b);
	reduce_store (sh, r);
}

void cu25519_generate (Cu25519Sec *xs, Cu25519Mon *xp)
{
	mask_scalar (xs->b);
	Fe u, v, z, t1, t2;
	montgomery_ladder_uv (u, v, z, bu, bv, xs->b);
	// y = (U-Z)/(U+Z) x = CU/V
	mul (t1, v, z);
	invert (t1, t1);  // t1 = 1/(vz)
	mul (t2, u, t1);
	mul (t2, t2, v);
	reduce_store (xp->b, t2);
	mul (t2, C, u);
	mul (t2, t2, t1);
	mul (t2, t2, z);
	uint8_t tmp[32];
	reduce_store (tmp, t2);
	xp->b[31] |= (tmp[0] & 1) << 7;
}



void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen, const Cu25519Mon &xp,
                   const Cu25519Sec &xs, uint8_t sig[64])
{
	sign_bmx (prefix, m, mlen, xp.b, xs.b, sig);
}


int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen, const uint8_t sig[64],
                    const Cu25519Mon &xp)
{
	return verify_bmx (prefix, m, mlen, sig, xp.b);
}


}}

