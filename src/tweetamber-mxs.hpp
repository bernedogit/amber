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

#ifndef TWEETAMBER_HPP
#define TWEETAMBER_HPP

#include "soname.hpp"
#include <stdexcept>
#include <vector>
#include <string.h>
#include <assert.h>


namespace twamber { inline namespace AMBER_SONAME {

// Hashing
typedef struct {
	uint8_t b[128];                     // input buffer
	uint64_t h[8];                      // chained state
	uint64_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2b_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
EXPORTFN
int  blake2b_init(blake2b_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen);
EXPORTFN
void blake2b_update (blake2b_ctx *ctx, const void *in, size_t inlen);

EXPORTFN void blake2b_final (blake2b_ctx *ctx, void *out);

EXPORTFN
int blake2b (void *out, size_t outlen, const void *key, size_t keylen,
             const void *in, size_t inlen);

inline void blake2b_update (blake2b_ctx *ctx, uint64_t u)
{
	uint8_t x[8];
	x[0] = u & 0xFF;
	x[1] = (u >> 8) & 0xFF;
	x[2] = (u >> 16) & 0xFF;
	x[3] = (u >> 24) & 0xFF;
	x[4] = (u >> 32) & 0xFF;
	x[5] = (u >> 40) & 0xFF;
	x[6] = (u >> 48) & 0xFF;
	x[7] = (u >> 56) & 0xFF;
	blake2b_update (ctx, x, 8);
}

class EXPORTFN Blake2b {
	blake2b_ctx ctx;
public:
	enum { blocklen = 128, hashlen = 64 };
	Blake2b (size_t outlen=hashlen, const void *key=0, size_t keylen=0) { blake2b_init (&ctx, outlen, key, keylen); }
	void reset (size_t outlen=hashlen, const void *key=0, size_t keylen=0) { blake2b_init (&ctx, outlen, key, keylen); }
	void update (const void *in, size_t inlen) { blake2b_update (&ctx, in, inlen); }
	void final (void *out) { blake2b_final (&ctx, out); }
};



typedef struct {
	uint8_t b[64];                      // input buffer
	uint32_t h[8];                      // chained state
	uint32_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2s_ctx;

EXPORTFN
int blake2s_init (blake2s_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen);
EXPORTFN
void blake2s_update (blake2s_ctx *ctx, const void *in, size_t inlen);

EXPORTFN void blake2s_final (blake2s_ctx *ctx, void *out);

class EXPORTFN Blake2s {
	blake2s_ctx ctx;
public:
	enum { blocklen = 64, hashlen = 32 };
	Blake2s (size_t outlen=hashlen, const void *key=0, size_t keylen=0) { blake2s_init (&ctx, outlen, key, keylen); }
	void reset (size_t outlen=hashlen, const void *key=0, size_t keylen=0) { blake2s_init (&ctx, outlen, key, keylen); }
	void update (const void *in, size_t inlen) { blake2s_update (&ctx, in, inlen); }
	void final (void *out) { blake2s_final (&ctx, out); }
};


// Poly1305 donna implementation.
typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

EXPORTFN
void poly1305_init (poly1305_context *ctx, const unsigned char key[32]);

EXPORTFN
void poly1305_finish (poly1305_context *ctx, unsigned char mac[16]);

EXPORTFN
void poly1305_update (poly1305_context *ctx, const unsigned char *m, size_t bytes);

// Return 1 if equal (not equal) or 0 otherwise. Constant time.
EXPORTFN
int crypto_equal (const unsigned char *mac1, const unsigned char *mac2, size_t n);

EXPORTFN
int crypto_neq (const void *v1, const void *v2, size_t n);

// Constant time check if v1[0..n[ is zero.
EXPORTFN int is_zero (const void *v1, size_t n);


// kn contains the state of chacha.
EXPORTFN void chacha20 (uint8_t out[64], const uint32_t kn[12]);

// A Chacha key as 32 bit words.
struct Chakey {
	uint32_t kw[8];
};

// Convert from bytes to words.
EXPORTFN void load (Chakey *kw, const uint8_t bytes[32]);

// HChaCha20. Take a key and a 16 byte nonce and generate a new key.
EXPORTFN
void hchacha20 (Chakey *out, const uint8_t key[32], const uint8_t n[16]);

// Generate a chunk based on the nonce and the block number.
EXPORTFN
void chacha20 (uint8_t out[64], const Chakey &key, uint64_t n64, uint64_t bn);


// Encrypt and decrypt using ChaChaPoly with multiple tags.
EXPORTFN
void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
                    const uint8_t *ad, size_t alen, const Chakey &kw,
                    const Chakey *ka, size_t nka, uint64_t nonce64);

EXPORTFN
int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen,
                   const uint8_t *ad, size_t alen, const Chakey &kw,
                   const Chakey &ka, size_t nka, size_t ika, uint64_t nonce64);

EXPORTFN
void scrypt_blake2b (uint8_t *dk, size_t dklen,
                     const char *pwd, size_t plen,
                     const uint8_t *salt, size_t slen,
                     int shifts, int r=8, int p=1);

EXPORTFN void randombytes_buf (void *buf, size_t n);


struct Cu25519Sec { uint8_t b[32]; };   // The scalar.
struct Cu25519Mon { uint8_t b[32]; };   // Point in Montgomery X format.
struct Cu25519Ell { uint8_t b[32]; };   // Elligator representative.

inline void mask_scalar (uint8_t scb[32])
{
	scb[0] &= 0xF8;    // Clear the lower 3 bits. Multiply by cofactor.
	scb[31] &= 0x7F;   // Clear the bit 255, not used.
	scb[31] |= 0x40;   // Set the most significant bit.
}

EXPORTFN void cu25519_generate (Cu25519Sec *xs, Cu25519Mon *xp);

// You must use mix_key() to convert the shared secret to a key. Best used
// with one of the Noise protocol patterns.
EXPORTFN
void cu25519_shared_secret (uint8_t sh[32], const Cu25519Mon &xp, const Cu25519Sec &xs);

EXPORTFN
void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
                   const Cu25519Mon &xp, const Cu25519Sec &xs,
                   uint8_t sig[64]);
EXPORTFN
int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen,
                    const uint8_t sig[64], const Cu25519Mon &xp);

EXPORTFN
void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Mon *xp, Cu25519Ell *rep);

EXPORTFN
void cu25519_elligator2_rev (Cu25519Mon *u, const Cu25519Ell & rep);



// Noise protocol support. Maintain the chaining key, the running hash and
// the encryption key.
EXPORTFN
void mix_hash_init (uint8_t ck[32], uint8_t h[32], const char *protocol,
                    const uint8_t *pro, size_t plen);

EXPORTFN
void mix_hash (uint8_t h[32], const uint8_t *data, size_t n);

template <class H>
class EXPORTFN Hmac {
	H blake;
	uint8_t key[H::blocklen];
public:
	enum { hashlen = H::hashlen };
	Hmac() {}
	Hmac(const uint8_t *k, size_t n) { reset (k, n); }
	void reset (const uint8_t *key, size_t n);
	void update (const uint8_t *data, size_t n) { blake.update (data, n); }
	void final (uint8_t *mac);
};

template <class H>
void Hmac<H>::reset (const uint8_t *k, size_t n)
{
	if (n > H::blocklen) {
		H tmph;
		tmph.update (k, n);
		tmph.final (key);
		memset (key + H::hashlen, 0, H::blocklen - H::hashlen);
	} else {
		memcpy (key, k, n);
		memset (key + n, 0, sizeof key - n);
	}
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
	}
	blake.reset (H::hashlen, NULL, 0);
	blake.update (key, sizeof key);
}
template <class H>
void Hmac<H>::final (uint8_t *mac)
{
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
		key[i] ^= 0x5c;
	}
	blake.final (mac);
	blake.reset (H::hashlen, NULL, 0);
	blake.update (key, sizeof key);
	blake.update (mac, H::hashlen);
	blake.final (mac);
}

template <class BLK>
class EXPORTFN Hkdf {
	Hmac<BLK> hmac;
	uint8_t prk[BLK::hashlen], last[BLK::hashlen];
	int last_size;
	unsigned char block_number;
	std::vector<uint8_t> infov;
public:
	enum { hashlen = BLK::hashlen };
	Hkdf (const uint8_t *salt, size_t nsalt) : hmac (salt, nsalt) {}
	void reset (const uint8_t *salt, size_t nsalt) { hmac.reset (salt, nsalt); }
	void add_input (const uint8_t *ikm, size_t n) { hmac.update (ikm, n); }
	void switch_to_output (const uint8_t *info=0, size_t ninfo=0);
	const uint8_t * output_block();
};
template <class BLK>
void Hkdf<BLK>::switch_to_output (const uint8_t *info, size_t ninfo)
{
	hmac.final (prk);
	last_size = 0;
	block_number = 1;
	infov.resize (ninfo);
	memcpy (&infov[0], info, ninfo);
}
template <class BLK>
const uint8_t * Hkdf<BLK>::output_block()
{
	hmac.reset (prk, hmac.hashlen);
	hmac.update (last, last_size);
	hmac.update (&infov[0], infov.size());
	hmac.update (&block_number, 1);
	hmac.final (last);
	last_size = hashlen;
	++block_number;
	return last;
}


EXPORTFN
void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n);
// To split call mix_key (ck, k, NULL, 0). ck is the initiator's key and k is
// the responder's key.

// Use this when you do not need the second key.
EXPORTFN void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n);


inline void leput32(unsigned char *p, const uint32_t v)
{
	p[0] = (unsigned char)(v      );
	p[1] = (unsigned char)(v >>  8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}
inline uint32_t leget32(const unsigned char *p)
{
	return
	(((uint32_t)(p[0])      ) |
	 ((uint32_t)(p[1]) <<  8) |
	 ((uint32_t)(p[2]) << 16) |
	 ((uint32_t)(p[3]) << 24));
}

void encrypt_uint32 (uint8_t enc[4], const Chakey &ke, uint64_t nonce, uint32_t val);
uint32_t decrypt_uint32 (const uint8_t enc[4], const Chakey &ke, uint64_t nonce);


}}


#endif

