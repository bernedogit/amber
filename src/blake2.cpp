#include "blake2.hpp"
#include "hasopt.hpp"
#include "misc.hpp"
#include <stdexcept>


namespace amber {  namespace AMBER_SONAME {

// A simple BLAKE2b Reference Implementation.
// Taken from RFC 7693


// Cyclic right rotation.

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

#define CPPSTR(X) CPPSTR1(X)
#define CPPSTR1(X) #X
#define CPPLOC __FILE__ ":" CPPSTR(__LINE__)

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
int blake2b_init (blake2b_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen)        // (keylen=0: no key)
{
	size_t i;

	if (outlen == 0) {
		throw_rte (_("Blake2b cannot be used to output 0 bytes. %s"), CPPLOC);
	}
	if (outlen > 64) {
		throw_rte (_("Blake2b cannot be output more than 64 bytes. %s"), CPPLOC);
	}
	if (keylen > 64) {
		throw_rte (_("Blake2b cannot be use more than 64 bytes of key. %s"), CPPLOC);
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



int blake2b_init (blake2b_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen, Blake2b_param *par)
{
	size_t i;

	if (outlen == 0) {
		throw_rte (_("Blake2b cannot be used to output 0 bytes. %s"), CPPLOC);
	}
	if (outlen > 64) {
		throw_rte (_("Blake2b cannot be output more than 64 bytes. %s"), CPPLOC);
	}
	if (keylen > 64) {
		throw_rte (_("Blake2b cannot be use more than 64 bytes of key. %s"), CPPLOC);
	}

	for (i = 0; i < 8; i++) {             // state, "param block"
		ctx->h[i] = blake2b_iv[i];
	}

	if (par) {
		par->key_length = keylen;
		par->digest_length = outlen;
		uint64_t x = par->digest_length | (uint64_t(par->key_length) << 8)
				| (uint64_t(par->fanout) << 16) | (uint64_t(par->depth) << 24)
				| (uint64_t(par->leaf_length) << 32);
		ctx->h[0] ^= x;
		ctx->h[1] ^= par->node_offset | (uint64_t(par->xof_digest_length) << 32);
		x = par->node_depth | (uint64_t(par->inner_length) << 8)
			| (uint64_t(par->reserved[0]) << 16)
			| (uint64_t(par->reserved[1]) << 24)
			| (uint64_t(leget32 (par->reserved + 2)) << 32);
		ctx->h[2] ^= x;
		ctx->h[3] ^= leget64 (par->reserved + 6);
		ctx->h[4] ^= leget64 (par->salt);
		ctx->h[5] ^= leget64 (par->salt + 8);
		ctx->h[6] ^= leget64 (par->personal);
		ctx->h[7] ^= leget64 (par->personal + 8);
	} else {
		ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
	}

	ctx->t[0] = 0;                      // input count low word
	ctx->t[1] = 0;                      // input count high word
	ctx->c = 0;                         // pointer within buffer
	ctx->outlen = outlen;

	for (i = keylen; i < 128; i++) {    // zero input block
		ctx->b[i] = 0;
	}
	if (keylen > 0) {
		blake2b_update(ctx, key, keylen);
		ctx->c = 128;                   // at the end
	}

	return 0;
}


void Blake2xb::reset (size_t outlen, const void *key, size_t keylen)
{
	Blake2b_param par;
	par.digest_length = 64;
	par.xof_digest_length = xof_digest_length = outlen;
	blake2b_init (&bl, 64, key, keylen, &par);
	expanding = false;
}

void Blake2xb::output_block (uint32_t bn, uint8_t block[64])
{
	if (!expanding) {
		blake2b_final (&bl, h0);
		expanding = true;
	}
	Blake2b_param par;
	par.key_length = 0;
	par.fanout = 0;
	par.depth = 0;
	par.leaf_length = 64;
	par.xof_digest_length = xof_digest_length;
	par.node_depth = 0;
	par.inner_length = 64;
	par.node_offset = bn;

	blake2b_ctx bl;
	blake2b_init (&bl, 64, NULL, 0, &par);
	blake2b_update (&bl, h0, 64);
	blake2b_final (&bl, block);
}

void Blake2xb::output (uint8_t *dest)
{
	size_t pending = xof_digest_length;
	uint32_t bn = 0;
	while (pending >= 64) {
		output_block (bn++, dest);
		dest += 64;
	}
	if (pending > 0) {
		uint8_t tmp[64];
		output_block (bn, tmp);
		memcpy (dest, tmp, pending);
	}
}



// Add "inlen" bytes from "in" into the hash.
void blake2b_update (blake2b_ctx *ctx,
                    const void *in, size_t inlen)       // data bytes
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

// Generate the message digest (size given in init).
//      Result placed in "out".
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

// Convenience function for all-in-one computation.
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


// Blake2s

// Cyclic right rotation.

#ifndef ROTR32
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#endif

// Little-endian byte access.

#define B2S_GET32(p)                            \
	(((uint32_t) ((uint8_t *) (p))[0]) ^        \
	(((uint32_t) ((uint8_t *) (p))[1]) << 8) ^  \
	(((uint32_t) ((uint8_t *) (p))[2]) << 16) ^ \
	(((uint32_t) ((uint8_t *) (p))[3]) << 24))

// Mixing function G.

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
		m[i] = B2S_GET32(&ctx->b[4 * i]);

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


int blake2s_init (blake2s_ctx *ctx, size_t outlen,
    const void *key, size_t keylen, Blake2s_param *par)     // (keylen=0: no key)
{
	size_t i;

	if (outlen == 0 || outlen > 32 || keylen > 32)
		return -1;                      // illegal parameters

	for (i = 0; i < 8; i++)             // state, "param block"
		ctx->h[i] = blake2s_iv[i];

	if (par) {
		par->key_length = keylen;
		par->digest_length = outlen;
		uint32_t x = par->digest_length | (uint32_t(par->key_length) << 8)
				| (uint32_t(par->fanout) << 16) | (uint32_t(par->depth) << 24);
		ctx->h[0] ^= x;
		ctx->h[1] ^= par->leaf_length;
		ctx->h[2] ^= par->node_offset;
		ctx->h[3] ^= par->xof_digest_length | (uint32_t(par->node_depth) << 16) | (uint32_t(par->inner_length) << 24);
		ctx->h[4] ^= leget32 (par->salt);
		ctx->h[5] ^= leget32 (par->salt + 4);
		ctx->h[6] ^= leget32 (par->personal);
		ctx->h[7] ^= leget32 (par->personal + 4);
	} else {
		ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
	}

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

// Convenience function for all-in-one computation.
int blake2s(void *out, size_t outlen,
    const void *key, size_t keylen,
    const void *in, size_t inlen)
{
	blake2s_ctx ctx;

	if (blake2s_init(&ctx, outlen, key, keylen))
		return -1;
	blake2s_update(&ctx, in, inlen);
	blake2s_final(&ctx, out);

	return 0;
}


void Blake2xs::reset (size_t outlen, const void *key, size_t keylen)
{
	Blake2s_param par;
	par.digest_length = 32;
	par.xof_digest_length = xof_digest_length = outlen;
	blake2s_init (&bl, 32, key, keylen, &par);
	expanding = false;
}

void Blake2xs::output_block (uint32_t bn, uint8_t block[32])
{
	if (!expanding) {
		blake2s_final (&bl, h0);
		expanding = true;
	}
	Blake2s_param par;
	par.key_length = 0;
	par.fanout = 0;
	par.depth = 0;
	par.leaf_length = 32;
	par.xof_digest_length = xof_digest_length;
	par.node_depth = 0;
	par.inner_length = 32;
	par.node_offset = bn;

	blake2s_ctx bl;
	blake2s_init (&bl, 32, NULL, 0, &par);
	blake2s_update (&bl, h0, 32);
	blake2s_final (&bl, block);
}

void Blake2xs::output (uint8_t *dest)
{
    size_t pending = xof_digest_length;
	uint32_t bn = 0;
	while (pending >= 32) {
		output_block (bn++, dest);
		dest += 32;
	}
	if (pending > 0) {
		uint8_t tmp[32];
		output_block (bn, tmp);
		memcpy (dest, tmp, pending);
	}
}



}}

