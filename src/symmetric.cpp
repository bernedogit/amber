/* Copyright (c) 2015-2017, Pelayo Bernedo.
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




#include "symmetric.hpp"
#include "blake2.hpp"
#include "poly1305.hpp"
#include "hasopt.hpp"
#include <string.h>
#include <chrono>
#include <random>
#include <fstream>
#include <mutex>

// We need pthread_atfork to handle forking and the state of the random
// number generator.
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


//#include "misc.hpp"
namespace amber {    namespace AMBER_SONAME {


// Chacha. Implemented by P. Bernedo.


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

void chacha20 (uint32_t out[16], const uint32_t kn[12])
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

	out[0]  = x[0]  + 0x61707865;
	out[1]  = x[1]  + 0x3320646e;
	out[2]  = x[2]  + 0x79622d32;
	out[3]  = x[3]  + 0x6b206574;
	out[4]  = x[4]  + kn[0];
	out[5]  = x[5]  + kn[1];
	out[6]  = x[6]  + kn[2];
	out[7]  = x[7]  + kn[3];
	out[8]  = x[8]  + kn[4];
	out[9]  = x[9]  + kn[5];
	out[10] = x[10] + kn[6];
	out[11] = x[11] + kn[7];
	out[12] = x[12] + kn[8];
	out[13] = x[13] + kn[9];
	out[14] = x[14] + kn[10];
	out[15] = x[15] + kn[11];
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



void chacha20 (uint8_t out[64], const uint32_t key[8], uint64_t nonce, uint64_t bn)
{
	int i;
	uint32_t x[16];
	x[0] = 0x61707865;
	x[1] = 0x3320646e;
	x[2] = 0x79622d32;
	x[3] = 0x6b206574;

	x[4] = key[0];
	x[5] = key[1];
	x[6] = key[2];
	x[7] = key[3];
	x[8] = key[4];
	x[9] = key[5];
	x[10] = key[6];
	x[11] = key[7];
	x[12] = bn & 0xFFFFFFFF;
	x[13] = bn >> 32;
	x[14] = nonce & 0xFFFFFFFF;
	x[15] = nonce >> 32;

	for (i = 0; i < 10; ++i) {
		chacha_doubleround(x);
	}

	leput32 (out + 0, x[0] + 0x61707865);
	leput32 (out + 4, x[1] + 0x3320646e);
	leput32 (out + 8, x[2] + 0x79622d32);
	leput32 (out + 12, x[3] + 0x6b206574);
	leput32 (out + 16, x[4] + key[0]);
	leput32 (out + 20, x[5] + key[1]);
	leput32 (out + 24, x[6] + key[2]);
	leput32 (out + 28, x[7] + key[3]);
	leput32 (out + 32, x[8] + key[4]);
	leput32 (out + 36, x[9] + key[5]);
	leput32 (out + 40, x[10] + key[6]);
	leput32 (out + 44, x[11] + key[7]);
	leput32 (out + 48, x[12] + (bn & 0xFFFFFFFF));
	leput32 (out + 52, x[13] + (bn >> 32));
	leput32 (out + 56, x[14] + (nonce & 0xFFFFFFFF));
	leput32 (out + 60, x[15] + (nonce >> 32));
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



void hchacha20 (uint32_t out[8], const uint8_t key[32], const uint8_t n[16])
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

	out[0] = x[0];
	out[1] = x[1];
	out[2] = x[2];
	out[3] = x[3];
	out[4] = x[12];
	out[5] = x[13];
	out[6] = x[14];
	out[7] = x[15];
}



void hchacha20 (Chakey *out, const Chakey &key, const uint8_t n[16])
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



void load (Chakey *kw, const uint8_t bytes[32])
{
	for (unsigned i = 0; i < 8; ++i) {
		kw->kw[i] = leget32 (bytes + i*4);
	}
}



void Chacha::reset (const Chakey &key, uint64_t nonce, uint64_t pos)
{
	memcpy (state, key.kw, 32);
	// We start with block number one when xoring.
	pos += 64;
	uint64_t bn = pos >> 6;     // pos/64
	state[8] = bn & 0xFFFFFFFF;
	state[9] = bn >> 32;
	state[10] = nonce & 0xFFFFFFFF;
	state[11] = nonce >> 32;

	chacha20 (buf, state);
	if (++state[8] == 0) state[9]++;
	buf_next = pos & 0x3F;
}

void Chacha::reset (const uint8_t *keybytes, uint64_t nonce, uint64_t pos)
{
	for (int i = 0; i < 8; ++i) {
		state[i] = leget32 (keybytes + 4*i);
	}
	pos += 64;
	uint64_t bn = pos >> 6;     // pos/64
	state[8] = bn & 0xFFFFFFFF;
	state[9] = bn >> 32;
	state[10] = nonce & 0xFFFFFFFF;
	state[11] = nonce >> 32;

	chacha20 (buf, state);
	if (++state[8] == 0) state[9]++;
	buf_next = pos & 0x3F;
}




void Chacha::set_nonce (uint64_t nonce)
{
	state[8] = 1;
	state[9] = 0;
	state[10] = nonce & 0xFFFFFFFF;
	state[11] = nonce >> 32;

	chacha20 (buf, state);
	if (++state[8] == 0) state[9]++;
	buf_next = 0;
}

void Chacha::doxor (uint8_t *out, const uint8_t *in, size_t n)
{
	while (n > 0) {
		if (buf_next < 64) {
			while (buf_next < 64 && n > 0) {
				*out++ = *in++ ^ buf[buf_next++];
				--n;
			}
		}
		while (n > 64) {
			chacha20 (buf, state);
			if (++state[8] == 0) state[9]++;
			for (int i = 0; i < 64; ++i) {
				*out++ = *in++ ^ buf[i];
			}
			n -= 64;
		}
		if (buf_next == 64) {
			chacha20 (buf, state);
			if (++state[8] == 0) state[9]++;
			buf_next = 0;
		}
	}
}
void Chacha::copy (uint8_t *out, size_t n)
{
	while (n > 0) {
		if (buf_next < 64) {
			while (buf_next < 64 && n > 0) {
				*out++ = buf[buf_next++];
				--n;
			}
		}
		while (n > 64) {
			chacha20 (buf, state);
			if (++state[8] == 0) state[9]++;
			for (int i = 0; i < 64; ++i) {
				*out++ = buf[i];
			}
			n -= 64;
		}
		if (buf_next == 64) {
			chacha20 (buf, state);
			if (++state[8] == 0) state[9]++;
			buf_next = 0;
		}
	}
}


void Chacha::seek (uint64_t pos)
{
	pos += 64;
	uint64_t bn = pos >> 6;     // pos/64
	state[8] = bn & 0xFFFFFFFF;
	state[9] = bn >> 32;
	chacha20 (buf, state);
	if (++state[8] == 0) state[9]++;
	buf_next = pos & 0x3F;
}



// Encrypt the plaintext with ChaCha20. Xor_stream starts with block number 0
// and continues until the input has been completely processed. The
// authencation keys are used to generate a block with index 0. This block is
// then used as the key for Poly1305. This setup allows us to use the same
// key for encryption (kw) and for authentication (ka). The encryption will
// use the blocks starting with 1 until the input is processed. The
// authentication will use the block with index 0. We use the same scheme as
// RFC 7539 for the padding.

void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
                    const uint8_t *ad, size_t alen, const Chakey &kw,
                    const Chakey *ka, size_t nka, uint64_t nonce64,
                    uint32_t ietf_sender)
{
	uint8_t stream[64];
	Janitor jan(stream, sizeof stream);

	Chacha cha (kw, nonce64, uint64_t(ietf_sender) << 38);
	cha.doxor (cipher, m, mlen);

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
			poly1305_pad16 (&poc, alen);
		}
		poly1305_update (&poc, cipher, mlen);
		poly1305_pad16 (&poc, mlen);
		poly1305_update (&poc, alen);
		poly1305_update (&poc, mlen);
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
	Janitor jan(stream, sizeof stream);

	uint64_t block_number = uint64_t (ietf_sender) << 32;
	block_number -= ika;
	chacha20 (stream, ka, nonce64, block_number);

	poly1305_context poc;
	poly1305_init (&poc, stream);
	if (alen != 0) {
		poly1305_update (&poc, ad, alen);
		poly1305_pad16 (&poc, alen);
	}
	poly1305_update (&poc, cipher, mlen);
	poly1305_pad16 (&poc, mlen);
	poly1305_update (&poc, alen);
	poly1305_update (&poc, mlen);

	uint8_t tag[16];
	poly1305_finish (&poc, tag);

	if (crypto_neq(tag, cipher + mlen + ika*16, 16)) return -1;
	Chacha cha (kw, nonce64, uint64_t(ietf_sender) << 38);
	cha.doxor (m, cipher, mlen);
	return 0;
}


size_t encrypt_packet (uint8_t *ct, const uint8_t *m, size_t mlen,
                       uint64_t uval, size_t padlen,
                       const Chakey &ke, uint64_t nonce,
                       const Chakey *ka, size_t nka,
                       const uint8_t *ad, size_t alen)
{
	Chacha cha (ke, nonce, 0);
	uint8_t valbytes[10];
	int vlen = write_uleb (uval, valbytes);
	cha.doxor (ct, valbytes, vlen);
	cha.doxor (ct + vlen, m, mlen);
	cha.copy (ct + vlen + mlen, padlen);

	poly1305_context poc;
	// For each authentication key, compute the Poly1305 tag and append it to
	// the resulting ciphertext.
	uint64_t block_number = 0;
	// Create the poly key using the last blocks. We use a different block
	// for each key because keys could have been repeated and then the tags
	// would be identical. The first block is zero to be compatible with
	// existing implementations.
	size_t ctlen = vlen + mlen + padlen;
	for (unsigned i = 0; i < nka; ++i) {
		uint8_t stream[64];
		chacha20 (stream, ka[i], nonce, block_number--);
		poly1305_init (&poc, stream);
		if (alen != 0) {
			poly1305_update (&poc, ad, alen);
			poly1305_pad16 (&poc, alen);
		}
		poly1305_update (&poc, ct, ctlen);
		poly1305_pad16 (&poc, ctlen);
		poly1305_update (&poc, alen);
		poly1305_update (&poc, ctlen);
		poly1305_finish (&poc, ct + ctlen + i*16);
	}
	return ctlen + nka * 16;
}


int decrypt_packet (uint8_t *m, size_t *msglen, uint64_t *u,
                    const uint8_t *cipher, size_t clen, size_t padlen,
                    const Chakey &ke, uint64_t nonce,
                    const Chakey *ka, size_t nka, size_t ika,
                    const uint8_t *ad, size_t alen)
{
	if (clen < nka*16 + 1) return -1;
	size_t mlen = clen - nka*16;

	uint8_t stream[64];
	Janitor jan(stream, sizeof stream);

	uint64_t block_number = 0;
	block_number -= ika;
	chacha20 (stream, *ka, nonce, block_number);

	poly1305_context poc;
	poly1305_init (&poc, stream);
	if (alen != 0) {
		poly1305_update (&poc, ad, alen);
		poly1305_pad16 (&poc, alen);
	}
	poly1305_update (&poc, cipher, mlen);
	poly1305_pad16 (&poc, mlen);
	poly1305_update (&poc, alen);
	poly1305_update (&poc, mlen);

	uint8_t tag[16];
	poly1305_finish (&poc, tag);

	if (crypto_neq(tag, cipher + mlen + ika*16, 16)) return -1;

	Chacha cha (ke, nonce, 0);
	enum { prefix_bytes = 10 };
	uint8_t valbytes[prefix_bytes];
	cha.doxor (valbytes, cipher, prefix_bytes);
	int nvalbytes = read_uleb (u, valbytes);

	// Guard against overflows.

	if (padlen + nvalbytes > mlen) return -1;

	size_t rest = prefix_bytes - nvalbytes;
	size_t payload_len = mlen - padlen - nvalbytes;
	*msglen = payload_len;

	if (payload_len <= rest) {
		memcpy (m, valbytes + nvalbytes, payload_len);
	} else if (payload_len > rest) {
		memcpy (m, valbytes + nvalbytes, rest);
		cha.doxor (m + rest, cipher + prefix_bytes, payload_len - rest);
	}
	return 0;
}


int peek_head (uint64_t *uval, const uint8_t ct[10], const Chakey &ke, uint64_t nonce)
{
	uint8_t pt[10];
	Chacha cha (ke, nonce, 0);
	cha.doxor (pt, ct, 10);
	if (read_uleb (uval, pt) < 0) return -1;
	return 0;
}




// PBKDF2 using blake2s. Generation of 32 byte chunk of the key.
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
	Janitor jan(u, sizeof u);
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
	Janitor jan1(t, sizeof t), jan2(x, sizeof x);
	Janitor jan3(&y[0], y.size()*4);

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
	Janitor jan1(&x[0], x.size()*4), jan2(&v[0], v.size()*4);

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
	Janitor jan(&bw[0], bw.size()*4);

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
	try {
		int i;
		int N = 1 << shifts;
		std::vector<uint8_t> b(128*r*p);
		Janitor jan(&b[0], b.size());
	
		pbkdf2_blake2b (&b[0], 128*r*p, pwd, plen, salt, slen, 1);

		for (i = 0; i < p; ++i) {
			scrypt_romix2(&b[128*r*i], r, N);
		}

		pbkdf2_blake2b (dk, dklen, pwd, plen, &b[0], 128*r*p, 1);
	} catch (...) {
		throw_nrte (_("Scrypt-Blake2s has failed."));
	}
}



// Read random bytes from C++11's std::random_device. According to the C++11 standard it
// is intended for cryptographic purposes, but the standard does not actually require
// anything from it. It is up to you whether you want to trust the
// implementors of the C++11 compiler/library. If you do not trust them then
// you should generate the random bytes by reading from /dev/urandom on most
// systems, using RDRAND if you trust Intel, using arc4random_buf() or, under
// Windows, calling CryptGenRandom(), but then the program would not be
// strictly portable. Keep in mind that a corrupt random device is likely
// one of the weakest points of a cryptographic system. It is easy to
// corrupt but hard to detect (google the Dual_EC_DRBG fiasco).
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


// Get random bytes from /dev/urandom. Return 0 on success.
static int read_urandom(void *vp, size_t n)
{
	std::ifstream is;
	is.rdbuf()->pubsetbuf(0, 0);    // Make it non buffered.
	is.open("/dev/urandom", is.binary);
	if (!is) {
		return -1;
	}
	is.read((char*)vp, n);
	if (is.gcount() != std::streamsize(n)) {
		return -1;
	}
	return 0;
}

// Belt and suspenders strategy. We hash the given key, the current time and
// the output of the std::random_device. We use the resulting hash to seed
// our generator. If you provide a good key then it will add the entropy of
// the key to the resulting generator, possibly compensating weaknesses of
// the std::random_device. Assuming that the std::random_device is
// deterministic all the randomness comes from the key and the time is used
// as a nonce.
void Keyed_random::reset(const void *ikm, size_t n)
{
	blake2b_ctx bl;

	blake2b_init (&bl, 48, NULL, 0);
	blake2b_update (&bl, ikm, n);
	uint8_t buf[48 + 8 + 8];
	// The ChaCha state has 48 bytes. We take 48 bytes of entropy from the
	// system and combine them with the current time. All this is keyed with
	// the given key.
	if (read_urandom(buf, 48) != 0) {
		cxx_random_device(buf, 48);
	}
	leput64 (buf + 48, std::chrono::system_clock::now().time_since_epoch().count());
	leput64 (buf + 56, std::chrono::high_resolution_clock::now().time_since_epoch().count());
	blake2b_update (&bl, buf, sizeof buf);
	blake2b_final (&bl, buf);
	Chacha::reset (buf, leget64(buf + 32), leget64(buf + 40));
}

void Keyed_random::reset (const char *password)
{
	reset (password, strlen(password));
}



// The Keyed_random is not thread safe and does not know about forks. If you
// are sharing Keyed_randoms among threads you must provide your own locking.
// It is also up to you to handle forks properly. If forks happen and are not
// handled then the parent and child may be sharing the same state and
// generate the same sequence of random numbers. The following provides a
// centralized facility that is thread and fork safe.

// State of the random number generator.
struct Rng_state {
	uint32_t kn[12];    // ChaCha20 state.
	int count;          // Number of bytes generated since last refresh.
	Rng_state() { refresh(); }
	void refresh();     // Add entropy from the std::random_device.
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
// In case of fork we refresh the state of the CSPRNG of the child.

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

	uint8_t *b8 = (uint8_t*) buf;
	uint32_t b32[16];
	rngstate.count += n;
	while (n >= 64) {
		chacha20 (b32, rngstate.kn);
		memcpy (b8, b32, 64);
		rngstate.kn[11]++;
		n -= 64;
		b8 += 64;
	}
	if (n > 0) {
		chacha20 (b32, rngstate.kn);
		memcpy (b8, b32, n);
		rngstate.kn[11]++;
	}
	// Use DJB's recommendation of resetting the state of the RNG.
	chacha20 (b32, rngstate.kn);
	memcpy (rngstate.kn, b32, 12*4);

	// Every now and then refresh the state by adding more entropy from the
	// std::random_device.
	if (rngstate.count > 1000000) {
		rngstate.refresh();
	}
	// Remove any trace of the previous output.
	crypto_bzero (b32, 64);
}


}}


