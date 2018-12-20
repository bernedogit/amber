/*
 * Copyright (c) 2015-2018, Pelayo Bernedo
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

// Test of the amber lib.


#include "group25519.hpp"
#include "symmetric.hpp"
#include "blake2.hpp"
#include "misc.hpp"
#include "hasopt.hpp"
#include "siphash24.hpp"
#include "poly1305.hpp"
#include <iostream>
#include <vector>
#include <string.h>
#include <chrono>
#include <math.h>
#include <typeinfo>
#include <iomanip>
#include <fstream>
#include <random>

using namespace amber;

typedef std::chrono::duration<double, std::nano> Fns;


namespace std {

// This needs to be in the std namespace because both arguments are members
// of std. Therefore ADL will only look into std. On the other hand, C++ says
// that adding to std is undefined behaviour. However without putting this
// declaration in std, it will be available only as long as we are in the
// global namespace. If we are in amber (like the format function) then this
// definition is not visible.

template <class R, class P>
std::ostream & operator<< (std::ostream &os, const std::chrono::duration<R,P> &dur)
{
	static const int lim = 10;
	using namespace std::chrono;
	seconds sec(duration_cast<seconds>(dur));
	if (fabs(sec.count()) > lim) {
		os << sec.count() << " s";
	} else {
		milliseconds ms(duration_cast<milliseconds>(dur));
		if (fabs(ms.count()) > lim) {
			os << ms.count() << " ms";
		} else {
			microseconds us(duration_cast<microseconds>(dur));
			if (fabs(us.count()) > lim) {
				os << us.count() << " μs";
			} else {
				Fns ns(duration_cast<Fns>(dur));
				os << ns.count() << " ns";
			}
		}
	}
	return os;
}
}


typedef std::chrono::high_resolution_clock Clock;

typedef struct {
	uint32_t r[4];
	uint32_t h[5];
	uint32_t c[5];
	uint32_t pad[5];
	size_t   c_index;
} crypto_poly1305_ctx;


void poly_block (crypto_poly1305_ctx *ctx)
{
	// s = h + c, without carry propagation
	const uint64_t s0 = ctx->h[0] + (uint64_t)ctx->c[0]; // s0 <= 1_fffffffe
	const uint64_t s1 = ctx->h[1] + (uint64_t)ctx->c[1]; // s1 <= 1_fffffffe
	const uint64_t s2 = ctx->h[2] + (uint64_t)ctx->c[2]; // s2 <= 1_fffffffe
	const uint64_t s3 = ctx->h[3] + (uint64_t)ctx->c[3]; // s3 <= 1_fffffffe
	const uint64_t s4 = ctx->h[4] + (uint64_t)ctx->c[4]; // s4 <=   00000004

	// Local all the things!
	const uint32_t r0 = ctx->r[0];       // r0  <= 0fffffff
	const uint32_t r1 = ctx->r[1];       // r1  <= 0ffffffc
	const uint32_t r2 = ctx->r[2];       // r2  <= 0ffffffc
	const uint32_t r3 = ctx->r[3];       // r3  <= 0ffffffc
	const uint32_t rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
	const uint32_t rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // * 5 trick
	const uint32_t rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // * 5 trick
	const uint32_t rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // * 5 trick

	// (h + c) * r, without carry propagation
	const uint64_t x0 = s0*r0 + s1*rr3 + s2*rr2 + s3*rr1 + s4*rr0;//<=97ffffe007fffff8
	const uint64_t x1 = s0*r1 + s1*r0  + s2*rr3 + s3*rr2 + s4*rr1;//<=8fffffe20ffffff6
	const uint64_t x2 = s0*r2 + s1*r1  + s2*r0  + s3*rr3 + s4*rr2;//<=87ffffe417fffff4
	const uint64_t x3 = s0*r3 + s1*r2  + s2*r1  + s3*r0  + s4*rr3;//<=7fffffe61ffffff2
	const uint32_t x4 = s4 * (r0 & 3); // ...recover 2 bits       //<=0000000000000018

	// partial reduction modulo 2^130 - 5
	const uint32_t u5 = x4 + (x3 >> 32); // u5 <= 7ffffffe
	const uint64_t u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
	const uint64_t u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
	const uint64_t u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
	const uint64_t u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
	const uint64_t u4 = (u3 >> 32)     + (u5 & 3);

	// Update the hash
	ctx->h[0] = u0 & 0xffffffff; // u0 <= 1_9ffffffa
	ctx->h[1] = u1 & 0xffffffff; // u1 <= 1_97ffffe0
	ctx->h[2] = u2 & 0xffffffff; // u2 <= 1_8fffffe2
	ctx->h[3] = u3 & 0xffffffff; // u3 <= 1_87ffffe4
	ctx->h[4] = u4;              // u4 <=          4
}

// (re-)initializes the input counter and input buffer
void poly_clear_c(crypto_poly1305_ctx *ctx)
{
	for (int i = 0; i < 4; ++i) { ctx->c[i] = 0; }
	ctx->c_index = 0;
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32])
{
	// constant init
	for (int i = 0; i < 5; ++i) { ctx->h [i] = 0; } // initial hash: zero
	ctx->c  [4] = 1;                  // add 2^130 to every input block
	ctx->pad[4] = 0;                  // poly_add() compatibility
	poly_clear_c(ctx);
	// load r and pad (r has some of its bits cleared)
	/**/            ctx->r  [0] = leget32(key      ) & 0x0fffffff;
	for (int i = 1; i < 4; ++i) { ctx->r  [i] = leget32(key + i*4) & 0x0ffffffc; }
	for (int i = 0; i < 4; ++i) { ctx->pad[i] = leget32(key + i*4 + 16);         }
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *msg, size_t msg_size)
{
	for (unsigned i = 0; i < msg_size; ++i) {
		if (ctx->c_index == 16) {
			poly_block (ctx);
			poly_clear_c (ctx);
		}
		// feed the input buffer
		ctx->c[ctx->c_index / 4] |= msg[i] << ((ctx->c_index % 4) * 8);
		ctx->c_index++;
	}
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16])
{
	// Process the last block (if any)
	if (ctx->c_index != 0) {
		// move the final 1 according to remaining input length
		// (We may add less than 2^130 to the last input block)
		ctx->c[4] = 0;
		ctx->c[ctx->c_index / 4] |= 1 << ((ctx->c_index % 4) * 8);
		// one last hash update
		poly_block(ctx);
	}

	// check if we should subtract 2^130-5 by performing the
	// corresponding carry propagation.
	uint64_t u = 5;
	u += ctx->h[0];  u >>= 32;
	u += ctx->h[1];  u >>= 32;
	u += ctx->h[2];  u >>= 32;
	u += ctx->h[3];  u >>= 32;
	u += ctx->h[4];  u >>=  2;
	// now u indicates how many times we should subtract 2^130-5 (0 or 1)

	// store h + pad, minus 2^130-5 if u tells us to.
	u *= 5;
	u += (int64_t)(ctx->h[0]) + ctx->pad[0];  leput32(mac     , u);  u >>= 32;
	u += (int64_t)(ctx->h[1]) + ctx->pad[1];  leput32(mac +  4, u);  u >>= 32;
	u += (int64_t)(ctx->h[2]) + ctx->pad[2];  leput32(mac +  8, u);  u >>= 32;
	u += (int64_t)(ctx->h[3]) + ctx->pad[3];  leput32(mac + 12, u);
}


template <class T>
void dummy1 (std::ostream &os, const T &t)
{
	os << t;
}

template <class T>
inline void dummy2 (std::ostream &os, const T &t) {
	os << t;
}


void measure_encryption (size_t n)
{
	std::cout << "\nMeasuring encryption and decryption speed.\n";
	std::vector<uint8_t> plain(n), cipher, plain2(n);
	uint8_t ad[100];
	Clock::time_point t1, t2;
	uint8_t nonce[28], key[32];

	randombytes_buf(&plain[0], n);
	memset(nonce, 42, sizeof nonce);
	memset(key, 43, sizeof key);
	memset(ad, 5, sizeof ad);

	enum { rounds = 100000 };

	Chakey new_key;
	uint64_t nonce64;
	xchacha (&new_key, &nonce64, key, nonce);

	cipher.resize(n + 16);
	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		encrypt_one(&cipher[0], &plain[0], plain.size(), ad, sizeof ad,
		            new_key, nonce64++);
	}
	t2 = Clock::now();
	format (std::cout, _("encrypt_one with n=%d takes %s (%s per byte)\n"), n,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds/n);

	int res;
	--nonce64;
	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		res = decrypt_one(&plain2[0], &cipher[0], cipher.size(), ad, sizeof ad,
		                  new_key, nonce64);
	}
	t2 = Clock::now();
	format (std::cout, _("decrypt_one with n=%d takes %d, res=%d  (%d per byte)\n"), n,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds, res,
	        std::chrono::duration_cast<Fns>(t1 - t1)/rounds/n);

	format (std::cout, "memcmp()=%d\n", amber::crypto_neq (&plain[0], &plain2[0], plain.size()));

	size_t jlim = n/64 + 1;
	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		for (unsigned j = 0; j < jlim; ++j) {
			chacha20(&cipher[0], new_key, nonce64, i + j);
		}
	}
	t2 = Clock::now();
	format (std::cout, _("chacha20 takes %d (%d per byte)\n"),
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds/n);

	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		poly1305_auth(&cipher[0], &plain[0], plain.size(), &plain[0]);
	}
	t2 = Clock::now();
	format (std::cout, _("poly1305 takes %d (%d per byte)\n"),
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds/n);

	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		crypto_poly1305_ctx pc;
		crypto_poly1305_init (&pc, &cipher[0]);
		crypto_poly1305_update (&pc, &plain[0], plain.size());
		crypto_poly1305_final (&pc, &plain[0]);
	}
	t2 = Clock::now();
	format (std::cout, _("monocipher poly1305 takes %d (%d per byte)\n"),
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds/n);

	// AEAD without AD
	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		encrypt_one(&cipher[0], &plain[0], plain.size(), NULL, 0,
		            new_key, nonce64++);
	}
	t2 = Clock::now();
	format (std::cout, _("encrypt_one with n=%d (no AD) takes %d (%d per byte)\n"), n,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds/n);

	--nonce64;
	t1 = Clock::now();
	for (int i = 0; i < rounds; ++i) {
		res = decrypt_one(&plain2[0], &cipher[0], plain.size() + 16, NULL, 0,
		                  new_key, nonce64);
	}
	t2 = Clock::now();
	format (std::cout, _("decrypt_one with n=%d (no AD) takes %d (%d per byte)\n"), n,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds,
	        std::chrono::duration_cast<Fns>(t2 - t1)/rounds/n);

	format (std::cout, "memcmp()=%d\n", amber::crypto_neq(&plain[0], &plain2[0], plain.size()));
}

void measure_x25519 (int n)
{
	std::cout << "\nMeasuring speed of X25519\n";

	Clock::time_point t1, t2;
	unsigned char shs1[32], shs2[32];
	Cu25519Sec cus1, cus2;
	Cu25519Pub cup1, cup2;

	randombytes_buf(cus1.b, sizeof cus1.b);
	randombytes_buf(cus2.b, sizeof cus2.b);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate(&cus1, &cup1);
		cu25519_generate(&cus2, &cup2);
	}
	t2 = Clock::now();
	format (std::cout, "X25519 key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret(shs1, cup1, cus2);
		cu25519_shared_secret(shs2, cup2, cus1);
	}
	t2 = Clock::now();
	std::cout << "X25519 shared secret: " << (t2 - t1)/n/2 << '\n';
	if (amber::crypto_neq(shs1, shs2, 32)) {
		std::cout << "error in x25519_shared_secret\n";
	}
}


void measure_ed25519 (int n)
{
	std::cout << "\nMeasuring speed of Ed25519\n";
	Clock::time_point t1, t2;
	Cu25519Pair ed1, ed2;

	memset (ed1.xs.b, 51, sizeof ed1.xs.b);
	memset (ed2.xs.b, 52, sizeof ed2.xs.b);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&ed1.xs, &ed1.xp);
		cu25519_generate (&ed2.xs, &ed2.xp);
	}
	t2 = Clock::now();
	std::cout << "cu25519 key generation: " << (t2 - t1)/n/2 << '\n';


	unsigned char sig[64];
	static const int text_lengths[] = { 64, 20000 };
	for (unsigned i = 0; i < sizeof(text_lengths)/sizeof(text_lengths[0]); ++i) {
		std::vector<unsigned char> item(text_lengths[i]);
		std::cout << "Signing and verifying with text length: " << item.size() << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			cu25519_sign(&item[0], item.size(), ed1, sig);
		}
		t2 = Clock::now();
		std::cout << "cu25519 sign: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (cu25519_verify(&item[0], item.size(), sig, ed1.xp) != 0) {
				std::cout << "error in verify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "cu25519 verify: " << (t2 - t1)/n << '\n';
	}
}



void measure_hash(int n)
{
	Clock::time_point t1, t2;
	std::vector<unsigned char> tmp(100000);
	unsigned char hash[64];

	t1 = Clock::now();
	blake2b_ctx bc;
	blake2b_init (&bc, 64, NULL, 0);
	for (int i = 0; i < n; ++i) {
		blake2b_update (&bc, &tmp[0], tmp.size());
	}
	blake2b_final (&bc, hash);
	t2 = Clock::now();
	std::cout << "blake2b: " << std::chrono::duration_cast<Fns>(t2 - t1)/n/tmp.size() << " per byte\n";

	t1 = Clock::now();
	uint64_t value = 0;
	uint64_t sipkey[2] = { 42, 43 };
	for (int i = 0; i < n; ++i) {
		value += siphash24 (&tmp[0], tmp.size(), sipkey[0], sipkey[1]);
	}
	t2 = Clock::now();
	std::cout << "siphash24: " << std::chrono::duration_cast<Fns>(t2 - t1)/n/tmp.size() << " per byte\n";

	enum { vbsize = 100000 };
	std::vector<uint8_t> rb;

	for (size_t vsz = 4; vsz <= vbsize; vsz += vbsize - 4) {
		rb.resize (vsz);
		std::cout << "Random test with size=" << vsz << '\n';
		Keyed_random kr;
		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			kr.get_bytes (&rb[0], rb.size());
		}
		t2 = Clock::now();
		std::cout << "Keyed random: " << std::chrono::duration_cast<Fns>(t2 - t1)/n/rb.size() << " per byte\n";

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			randombytes_buf (&rb[0], rb.size());
		}
		t2 = Clock::now();
		std::cout << "randombytes_buf: " << std::chrono::duration_cast<Fns>(t2 - t1)/n/rb.size() << " per byte\n";
	}

	std::mt19937 mt;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		size_t count = rb.size();
		uint8_t *pb = (uint8_t*) &rb[0];
		while (count > 4) {
			uint32_t mtv = mt();
			memcpy (pb, &mtv, 4);
			pb += 4;
			count -= 4;
		}
		if (count > 0) {
			uint32_t v = mt();
			memcpy (pb, &v, count);
		}
	}
	t2 = Clock::now();
	std::cout << "Mersenne twister: " << std::chrono::duration_cast<Fns>(t2 - t1)/n/rb.size() << " per byte\n";

	for (int shifts = 5; shifts < 16; ++shifts) {
		enum { niter = 5 };
		t1 = Clock::now();
		for (int i = 0; i < niter; ++i) {
			scrypt_blake2b(hash, 32, (const char*)&tmp[0], 16, &tmp[16], 32, shifts);
		}
		t2 = Clock::now();
		std::cout << "scrypt_blake2b with " << shifts << " shifts: "
				<< std::chrono::duration_cast<Fns>(t2 - t1)/niter
				<< " memory: " << (1 << shifts)/1024 << " MiB\n";
	}

	for (int r = 8; r < 25; r+=4) {
		enum { niter = 5 };
		t1 = Clock::now();
		for (int i = 0; i < niter; ++i) {
			scrypt_blake2b(hash, 32, (const char*)&tmp[0], 16, &tmp[16], 32, 10, r);
		}
		t2 = Clock::now();
		std::cout << "scrypt_blake2b with 10 shifts and r=" << r << ": "
			<< std::chrono::duration_cast<Fns>(t2 - t1)/niter
			<< " memory: " << (1 << 14)*r*128/1024/1024 << " MiB\n";
	}

}



void verify_encdec()
{
	using namespace amber;
	enum { sz = 1000, chunk = 50 };
	std::vector<unsigned char> s1(sz), s2;

	randombytes_buf(&s1[0], s1.size());
	Base64_encoder enc;
	std::string b64;
	for (int i = 0; i <= sz/chunk; ++i) {
		size_t tail = s1.size() - chunk * i;
		enc.encode_append(&s1[chunk * i], tail > chunk ? chunk : tail, &b64);
	}
	enc.flush_append(&b64);

	Base64_decoder dec;
	dec.decode_append(b64.c_str(), b64.size(), &s2);
	dec.flush_append(&s2);

	if (s1.size() != s2.size()) {
		std::cout << "error in different sizes in Base 64\n";
		return;
	}
	if (amber::crypto_neq(&s1[0], &s2[0], s1.size())) {
		std::cout << "error in Base 64\n";
	}
//    std::cout << "b64:\n" << b64 << '\n';

	base32enc(&s1[0], 32, b64, false, true);
//    std::cout << "b32: " << b64 << "  (" << b64.size() << " bytes)\n";

	base64enc(&s1[0], 32, b64, false, false);
	base64dec(b64.c_str(), s2, b64.size());
	if (s2.size() != 32 || memcmp(&s1[0], &s2[0], s2.size())) {
		std::cout << "error base64dec withouth =\n";
	}
//    std::cout << "b64-32: " << b64 << "  (" << b64.size() << " bytes)\n";

	base64enc(&s1[0], 31, b64, false, false);
	base64dec(b64.c_str(), s2, b64.size());
	if (31 != s2.size() || memcmp(&s1[0], &s2[0], s2.size())) {
		std::cout << "error base64dec withouth =\n";
	}
	std::cout << "base 64 tested\n";
}

void test_chacha(size_t n)
{
	using namespace amber;
	uint8_t nonce[28], key[32], ad[64];
	std::vector<uint8_t> plain(n), cipher(n + 16), dec(n);

	randombytes_buf(nonce, 28);
	randombytes_buf(key, 32);
	randombytes_buf(&plain[0], n);
	randombytes_buf(ad, sizeof ad);

	Chakey kn;
	uint64_t nonce64;
	xchacha (&kn, &nonce64, key, nonce);
	encrypt_one(&cipher[0], &plain[0], n, ad, sizeof ad, kn, nonce64);
	int res = decrypt_one(&dec[0], &cipher[0], n + 16, ad, sizeof ad, kn, nonce64);
	if (res == 0) {
		format (std::cout, _("chacha ok with n=%d\n"), n);
	} else {
		format (std::cerr, _("Error in chacha with n=%d\n"), n);
	}

	enum { nrx = 5 };
	Chakey ka[nrx];
	randombytes_buf((uint8_t*)&ka[0], sizeof(ka));
	cipher.resize(n + 16 * nrx);
	enum { adlen = 100 };
	uint8_t a[adlen];
	randombytes_buf(a, adlen);

	for (int i = 1; i < nrx; ++i) {
		encrypt_multi(&cipher[0], &plain[0], n, a, adlen, kn, &ka[0], i, nonce64);
		for (int j = 0; j < i; ++j) {
			res = decrypt_multi(&dec[0], &cipher[0], n + 16*i, a, adlen,
			                 kn, ka[j], i, j, nonce64);
			if (res != 0) {
				format (std::cerr, _("Error in encrypt_multi with i=%d  j=%d\n"), i, j);
			}
		}
	}
	std::cout << "encrypt_multi()/decrypt_multi() tested\n";
}



int main()
{
	enum { niter = 6000 };

	try {
		std::cout << "Start...\n";
		measure_hash (niter);
		measure_encryption (niter);
		measure_x25519 (niter);
		measure_ed25519 (niter);
		test_chacha(1000);
		test_chacha(2134);
		verify_encdec();
	} catch (std::exception &e) {
		format (std::cout, _("Exception of type %s was caught with what: %s\n"), typeid(e).name(), e.what());
	} catch (...) {
		std::cout << "some exception was thrown\n";
	}
}

