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
EXPORTFN
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
EXPORTFN
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
EXPORTFN
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
EXPORTFN
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
EXPORTFN
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
EXPORTFN
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
EXPORTFN
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

EXPORTFN
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
EXPORTFN
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
EXPORTFN
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

EXPORTFN
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
EXPORTFN
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
EXPORTFN
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

EXPORTFN
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

EXPORTFN
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

EXPORTFN
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

EXPORTFN
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

	x[12] = leget32(n + 8);
	x[13] = leget32(n + 12);
	x[14] = leget32(n + 0);
	x[15] = leget32(n + 4);

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
                        const Chakey &key, uint64_t n64, uint32_t ietf_sender=0)
{
	uint8_t stream[64];
	// We use block zero to generate authentication keys for Poly1305. We xor
	// starting with block one.
	uint64_t bn = 1 | (uint64_t(ietf_sender) << 32);
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
                    const Chakey *ka, size_t nka, uint64_t nonce64,
                    uint32_t ietf_sender)
{
	uint8_t stream[64];

	xor_stream (cipher, m, mlen, kw, nonce64, ietf_sender);

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
	uint64_t block_number = uint64_t(ietf_sender) << 32;
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
				   uint64_t nonce64, uint32_t ietf_sender)
{
	if (clen < nka*16) return -1;
	size_t mlen = clen - nka*16;

	uint8_t stream[64];

	uint64_t block_number = uint64_t (ietf_sender) << 32;
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
	xor_stream (m, cipher, mlen, kw, nonce64, ietf_sender);
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

EXPORTFN
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

static void cxx_random_device(void *vp, size_t n)
{
	static std::random_device rd;
	typedef std::random_device::result_type Re;

	uint8_t *dest = (uint8_t*) vp;
	if (std::numeric_limits<Re>::max() == rd.max() &&
	    std::numeric_limits<Re>::min() == rd.min()) {
		// Sane case: we get a random value with uniform distribution between
		// 0 and UINT_MAX. Just copy it.
		while (n > 0) {
			Re v = rd();
			if (n > sizeof(v)) {
				memcpy(dest, &v, sizeof v);
				n -= sizeof v;
			} else {
				memcpy(dest, &v, n);
				n = 0;
			}
		}
	} else {
		uintmax_t range = rd.max() - rd.min() + 1;
		Re low = (range & 0xFF) + rd.min();
		// Discard values less than low. There are range - range%0x100
		// possible acceptable values. Each of them of equal probability.
		// If we mod them by 0x100, we will get bytes with uniform
		// probability.

		Re val;
		while (n > 0) {
			do {
				val = rd();
			} while (val < low);
			*dest++ = val & 0xFF;
			--n;
		}
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


// Noise protocol
void mix_hash (uint8_t h[32], const uint8_t *data, size_t n)
{
	blake2s_ctx b;
	blake2s_init (&b, 32, NULL, 0);
	blake2s_update (&b, h, 32);
	blake2s_update (&b, data, n);
	blake2s_final (&b, h);
}

void mix_hash_init (uint8_t ck[32], uint8_t h[32], const char *protocol,
                    const uint8_t *pro, size_t plen)
{
	size_t n = strlen (protocol);
	if (n <= 32) {
		memcpy (h, protocol, n);
		memset (h + n, 0, 32 - n);
	} else {
		blake2s_ctx b;
		blake2s_init (&b, 32, NULL, 0);
		blake2s_update (&b, protocol, n);
		blake2s_final (&b, h);
	}
	memcpy (ck, h, 32);
	mix_hash (h, pro, plen);
}


void Hmac::reset (const uint8_t k[32])
{
	memcpy (key, k, 32);
	memset (key + 32, 0, 32);
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
	}
	blake2s_init (&b, 32, NULL, 0);
	blake2s_update (&b, key, sizeof key);
}
void Hmac::final (uint8_t h[32])
{
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
		key[i] ^= 0x5c;
	}
	blake2s_final (&b, h);
	blake2s_init (&b, 32, NULL, 0);
	blake2s_update (&b, key, sizeof key);
	blake2s_update (&b, h, 32);
	blake2s_final (&b, h);
}

void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n)
{
	Hmac hmac (ck);
	hmac.update (ikm, n);
	uint8_t tmp[32];
	hmac.final (tmp);
	hmac.reset (tmp);
	uint8_t b = 1;
	hmac.update (&b, 1);
	hmac.final (ck);
	hmac.reset (tmp);
	hmac.update (ck, 32);
	b = 2;
	hmac.update (&b, 1);
	hmac.final (k);
}

void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n)
{
	Hmac hmac (ck);
	hmac.update (ikm, n);
	uint8_t tmp[32];
	hmac.final (tmp);
	hmac.reset (tmp);
	uint8_t b = 1;
	hmac.update (&b, 1);
	hmac.final (ck);
}



// Curve25519

struct Fe {
	uint32_t v[10];
};
struct Edwards {
	Fe x, y, z, t;
	// x/z and y/z are the real coordinates. t/z = (x/z)*(y/z)
};

enum { fecount = 10 };
enum { mask25 = (1 << 25) - 1, mask26 = (1 << 26) - 1 };
// p = 2²⁵⁵ - 19. The lowest limb of p has the representation p0. All other
// limbs of p have either mask25 or mask26.
static const uint32_t p0      = 0x3FFFFED;

// Four times P.
static const uint32_t four_p0 = 4*p0;
static const uint32_t four_mask25 = 4 * mask25;
static const uint32_t four_mask26 = 4 * mask26;


// p = 2²⁵⁵-19
static const Fe p = { 0x3FFFFED, mask25, mask26, mask25, mask26,
                     mask25, mask26, mask25, mask26, mask25 };

static const Fe fezero = { 0 };
static const Fe feone = { 1 };
static const Edwards edzero = { fezero, feone, feone, fezero };
enum { A = 486662 };

// d = -121665/121666
static const Fe edwards_d = {  0x35978a3, 0x0d37284, 0x3156ebd, 0x06a0a0e, 0x001c029,
                               0x179e898, 0x3a03cbb, 0x1ce7198, 0x2e2b6ff, 0x1480db3 };


static const Fe edwards_2d = { 0x2b2f159, 0x1a6e509, 0x22add7a, 0x0d4141d, 0x0038052,
                               0x0f3d130, 0x3407977, 0x19ce331, 0x1c56dff, 0x0901b67 };

// sqrt(-1) = 2^(2²⁵³ - 5)
static const Fe root_minus_1 = { 0x20ea0b0, 0x186c9d2, 0x08f189d, 0x035697f, 0x0bd0c60,
                                 0x1fbd7a7, 0x2804c9e, 0x1e16569, 0x004fc1d, 0x0ae0c92 };

// C = sqrt(-1)*sqrt(A+2)
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

// Base point in Montgomery.
static const Fe bu = { 9 };
static const Fe bv = { 0x2ced3d9, 0x071689f, 0x036453d, 0x1f36be3, 0x248f535,
                       0x148d14c, 0x36e963b, 0x0d69c03, 0x21b8a08, 0x082b866 };


// Load a byte string into the limb form.
static void load (Fe &fe, const uint8_t b[32])
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

inline void add_no_reduce (Fe &res, const Fe &a, const Fe &b)
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

inline void add (Fe &res, const Fe &a, const Fe &b)
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
inline void sub (Fe &res, const Fe &a, const Fe &b)
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
// 64 bit result.
inline uint64_t mul (uint32_t a, uint32_t b)
{
	return uint64_t(a) * uint64_t(b);
}

// Normal multiplication. Produce 64 bit values, which are then reduced.
inline void mul (Fe &res, const Fe &f, const Fe &g)
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
inline void square (Fe &res, const Fe &f)
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

inline void reduce (Fe &fe)
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

inline void add_bits (uint8_t *b, uint32_t c)
{
	b[0] |= c & 0xFF;
	b[1] = (c >> 8) & 0xFF;
	b[2] = (c >> 16) & 0xFF;
	b[3] = (c >> 24);
}


// Fully reduce to mod p and store it in byte form.
static void reduce_store (uint8_t b[32], Fe &fe)
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
	add_bits (b +  0, fe.v[0]);
	add_bits (b +  3, fe.v[1] << 2);   // 26 - 24
	add_bits (b +  6, fe.v[2] << 3);   // 51 - 48
	add_bits (b +  9, fe.v[3] << 5);   // 77 - 72
	add_bits (b + 12, fe.v[4] << 6);   // 102 - 96
	b[16] = 0;
	add_bits (b + 16, fe.v[5]);        // 128 - 128
	add_bits (b + 19, fe.v[6] << 1);   // 153 - 152
	add_bits (b + 22, fe.v[7] << 3);   // 179 - 176
	add_bits (b + 25, fe.v[8] << 4);   // 204 - 190
	add_bits (b + 28, fe.v[9] << 6);   // 230 - 224
}

inline void mul_small (Fe &res, const Fe &a, uint32_t bs)
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

static void raise_252_3 (Fe &res, const Fe &z)
{
	Fe z11, tmp;
	raise_252_2 (tmp, z11, z);    // 2²⁵² - 2²
	mul (res, tmp, z);        // 2²⁵² - 3
}

inline void cswap (Fe &a, Fe &b, uint32_t flag)
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

// Store the point as Edwards y with the sign bit in bit 255.
static void edwards_to_ey (uint8_t res[32], const Edwards &p)
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

static int mx_to_edwards (Edwards &res, const uint8_t mx[32], bool neg=true)
{
	Fe u, t1, t2, a, b, h, s;
	enum { A = 486662 };

	load (u, mx);
	square (t1, u);
	mul_small (t2, u, A);
	add (t1, t1, t2);
	add (t1, t1, feone);
	mul (a, t1, u);         // a = u(1 + Au + u²) = v²

	add (b, u, feone);      // b = u + 1
	mul (h, a, b);
	mul (h, h, b);          // h = ab²

	invsqrt (s, h);     // s = 1/sqrt(h);

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

static
void mont_to_edwards (Edwards &e, const Fe &u, const Fe &v, const Fe &z)
{
	// y = (U-Z)/(U+Z) x = CU/V
	// X = CU(U+Z) Y = (U-Z)V Z=(U+Z)V T=CU(U-Z)
	Fe t1, t2, cu;
	add (t1, u, z);
	sub (t2, u, z);
	mul (cu, C, u);
	mul (e.x, cu, t1);
	mul (e.y, t2, v);
	mul (e.z, t1, v);
	mul (e.t, cu, t2);
}

static
void montgomery_ladder (Edwards &res, const Fe &xpu, const Fe &xpv, const uint8_t scalar[32])
{
	Fe u, v, z;
	montgomery_ladder_uv (u, v, z, xpu, xpv, scalar);
	mont_to_edwards (res, u, v, z);
}

// Precomputed values that are stored with z.
struct Summand {
	// y + x, y - x, t*2*d, z*2
	Fe ypx, ymx, t2d, z2;
};

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

static
void sign_bmx (const char *prefix, const uint8_t *m, size_t mlen, const uint8_t A[32],
               const uint8_t scalar[32], uint8_t sig[64])
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
	Edwards R;
	montgomery_ladder (R, bu, bv, r);
	edwards_to_ey (sig, R);

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

static
void edwards_to_summand (Summand &s, const Edwards &e)
{
	add (s.ypx, e.y, e.x);
	sub (s.ymx, e.y, e.x);
	mul (s.t2d, e.t, edwards_2d);
	add (s.z2, e.z, e.z);
}

static void compute_naf_window (int8_t d[256], const uint8_t s[32], int w = 5)
{
	// First extract the bits so that they can be handled easily.
	for (int i = 0; i < 256; ++i) {
		d[i] = (s[i >> 3] >> (i & 7)) & 1;
	}

	int wm1 = 1 << (w-1);
	int wm2 = 1 << w;
	for (int i = 0; i < 256; ++i) {
		if (d[i]) {
			int collect = d[i];
			int j;
			for (j = 1; j < w && (i + j < 256); ++j) {
				if (d[i + j]) {
					collect += d[i + j] << j;
					d[i + j] = 0;
				}
			}
			if (collect >= wm1) {
				int k = i + j;
				while (k < 256) {
					if (d[k]) {
						d[k] = 0;
					} else {
						d[k] = 1;
						break;
					}
					++k;
				}
			  d[i] = collect - wm2;
			} else {
				d[i] = collect;
			}
			i += w - 1;
		}
	}
}


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


// Variable time res = s1*B + s2*P, where B is the base point.
static
void scalarmult_wnaf (Edwards &res, const uint8_t s1[32],
                      const Edwards &p, const uint8_t s2[32])
{
	int8_t d1[256], d2[256];
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
	for (int j = 255; j >= 0; --j) {
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

static
int verify_bmx (const char *prefix, const uint8_t *m, size_t mlen, const uint8_t sig[64],
                const uint8_t mx[32])
{
	if (!gt_than (order, sig + 32)) {
		return -1;
	}

	Edwards p;
	if (mx_to_edwards (p, mx) != 0) {
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

	Edwards newr;
	scalarmult_wnaf (newr, sig + 32, p, rhram);
	uint8_t newrp[32];
	edwards_to_ey (newrp, newr);
	return crypto_neq (sig, newrp, 32);
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

static const Fe sqrtmA2 = { 0x0ba81e7, 0x07ed540, 0x0afa672, 0x175a417, 0x0e978b0,
                            0x003b081, 0x27b91fe, 0x12885b0, 0x0b9f5ff, 0x1c36448 };


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
EXPORTFN
void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Pub *xp, Cu25519Rep *rep)
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

void cu25519_elligator2_rev (Cu25519Pub *u, const Cu25519Rep & rep)
{
	Fe fr, fu;
	load (fr, rep.b);

	// Ignore the last bit of fr. Load already discards bit 254. We must also
	// discard bit 253 because r < (p-1)/2 and the top two bits had been
	// filled with random bits.
	fr.v[9] &= (1 << 24) - 1;

	elligator2_r2u (fu, fr);
	reduce_store (u->b, fu);
}


EXPORTFN
void cu25519_shared_secret (uint8_t sh[32], const Cu25519Pub &xp, const Cu25519Sec &xs)
{
	Fe b, r;
	load (b, xp.b);
	montgomery_ladder (r, b, xs.b);
	reduce_store (sh, r);
}
EXPORTFN
void cu25519_generate (Cu25519Sec *xs, Cu25519Pub *xp)
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

EXPORTFN
void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen, const Cu25519Pub &xp,
                   const Cu25519Sec &xs, uint8_t sig[64])
{
	sign_bmx (prefix, m, mlen, xp.b, xs.b, sig);
}

EXPORTFN
int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen, const uint8_t sig[64],
                    const Cu25519Pub &xp)
{
	return verify_bmx (prefix, m, mlen, sig, xp.b);
}

}}

