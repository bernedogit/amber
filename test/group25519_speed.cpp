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

#include "group25519.hpp"
#include "misc.hpp"
#include "symmetric.hpp"
#include "hasopt.hpp"
#include <iostream>
#include <chrono>
#include <math.h>
#include <string.h>
#include <fstream>
#include "tweetamber.hpp"

using namespace amber;

typedef std::chrono::duration<double, std::nano> Fns;

namespace std {
template <class R, class P>
std::ostream & operator<<(std::ostream &os, const std::chrono::duration<R,P> &dur)
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



void measure(int n)
{
	Clock::time_point t1, t2;
	unsigned char shs1[32], shs2[32];
	Cu25519Pair x1, x2, x3;
	Cu25519Rep ell;

	randombytes_buf (x1.xs.b, 32);
	randombytes_buf (x2.xs.b, 32);
	randombytes_buf (x3.xs.b, 32);

	twamber::Cu25519Sec txs1, txs2, txs3;
	twamber::Cu25519Pub txp1, txp2, txp3;
	twamber::Cu25519Rep tell;
	memcpy (txs1.b, x1.xs.b, 32);
	memcpy (txs2.b, x2.xs.b, 32);
	memcpy (txs3.b, x3.xs.b, 32);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&x1.xs, &x1.xp);
		cu25519_generate (&x2.xs, &x2.xp);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519 key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&txs1, &txp1);
		cu25519_generate (&txs2, &txp2);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519 key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_base (x1.xp.b, x1.xs.b);
	}
	t2 = Clock::now();
	format(std::cout, "ladder key generation: %d\n", (t2 - t1)/n);

	Cu25519Sec xs_saved = x3.xs;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		x3.xs = xs_saved;
		cu25519_elligator2_gen (&x3.xs, &x3.xp, &ell);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519_elligator2_gen(): %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_elligator2_rev (&x3.xp, ell);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519_elligator2_rev(): %d\n", (t2 - t1)/n);

	twamber::Cu25519Sec txs_saved = txs3;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		txs3 = txs_saved;
		cu25519_elligator2_gen (&txs3, &txp3, &tell);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519_elligator2_gen(): %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_elligator2_rev (&txp3, tell);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519_elligator2_rev(): %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret(shs1, x1.xp, x2.xs);
		cu25519_shared_secret(shs2, x2.xp, x1.xs);
	}
	t2 = Clock::now();
	std::cout << "cu25519 shared secret: " << (t2 - t1)/n/2 << '\n';
	if (amber::crypto_neq(shs1, shs2, 32)) {
		std::cout << "error in cu25519_shared_secret\n";
	}

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret (shs1, txp1, txs2);
		cu25519_shared_secret (shs2, txp2, txs1);
	}
	t2 = Clock::now();
	std::cout << "twamber::cu25519 shared key: " << (t2 - t1)/n/2 << '\n';
	if (amber::crypto_neq(shs1, shs2, 32)) {
		std::cout << "error in cu25519_shared_secret\n";
	}

	uint8_t mx[32], ey[32];
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		amber::mx_to_ey (ey, x1.xp.b);
	}
	t2 = Clock::now();
	std::cout << "conversion mx to ey: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		amber::ey_to_mx (mx, ey);
	}
	t2 = Clock::now();
	std::cout << "conversion ey to mx: " << (t2 - t1)/n << '\n';

	amber::Edwards e1, e2;
	scalarbase (e1, x1.xs.b);
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarmult (e2, e1, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "scalarmult: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarmult_wnaf (e2, e1, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "scalarmult_nafw: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarmult_fw (e2, e1, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "scalarmult_fw: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarbase (e2, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "scalarbase: " << (t2 - t1)/n << '\n';

	Fe ru, rv, rz;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_base (ru, rv, rz, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "montgomery_base: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_base (e2, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "montgomery_base ed output: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_ladder (e2, edwards_base_point, x2.xs.b);
	}
	t2 = Clock::now();
	std::cout << "montgomery ladder ed input and output: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_ladder (e2, edwards_base_point, x2.xs.b);
		edwards_to_mx (mx, e2);
	}
	t2 = Clock::now();
	std::cout << "Edwards shared secret: " << (t2 - t1)/n << '\n';


	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		edwards_to_mx (mx, e1);
	}
	t2 = Clock::now();
	std::cout << "edwards_to_mx: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		mx_to_edwards (e1, mx);
	}
	t2 = Clock::now();
	std::cout << "mx_to_edwards: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		edwards_to_ey (ey, e1);
	}
	t2 = Clock::now();
	std::cout << "edwards_to_ey: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		ey_to_edwards (e1, ey);
	}
	t2 = Clock::now();
	std::cout << "ey_to_edwards: " << (t2 - t1)/n << '\n';

	cu25519_generate (&x1.xs, &x1.xp);
	mx_to_ey (ey, x1.xp.b);
	memcpy (mx, x1.xp.b, 32);

	uint8_t ns[32], ey0[32];
	memcpy (ey0, ey, 32);
	if (ey0[31] & 0x80) {
		negate_scalar (ns, x1.xs.b);
		ey0[31] &= 0x7F;
	} else {
		memcpy (ns, x1.xs.b, 32);
	}

	memcpy (txs1.b, x1.xs.b, 32);
	memcpy (txp1.b, x1.xp.b, 32);

	unsigned char sig[64], sig2[64];
	static const int text_lengths[] = { 64, 20000 };
	for (unsigned i = 0; i < sizeof(text_lengths)/sizeof(text_lengths[0]); ++i) {
		std::vector<unsigned char> item(text_lengths[i]);
		std::cout << "Signing and verifying with text length: " << item.size() << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			cu25519_sign (&item[0], item.size(), x1, sig);
		}
		t2 = Clock::now();
		std::cout << "cu25519 sign: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (cu25519_verify(&item[0], item.size(), sig, x1.xp) != 0) {
				std::cout << "error in verify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "cu25519 verify: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			cu25519_sign (NULL, &item[0], item.size(), txp1, txs1, sig);
		}
		t2 = Clock::now();
		std::cout << "twamber::cu25519 sign: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (cu25519_verify (NULL, &item[0], item.size(), sig, txp1) != 0) {
				std::cout << "error in verify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "twamber::cu25519 verify: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			sign_sha (&item[0], item.size(), ey0, ns, sig);
		}
		t2 = Clock::now();
		std::cout << "sign_sha, cached: " << (t2 - t1)/n << '\n';
		if (verify_sey (&item[0], item.size(), sig, ey0, true) != 0) {
			std::cout << "error in verify_sey, ey0\n";
		}

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			sign_conv (&item[0], item.size(), ey, x1.xs.b, sig2);
		}
		t2 = Clock::now();
		std::cout << "sign_conv: " << (t2 - t1)/n << '\n';
		if (crypto_neq (sig, sig2, 64)) {
			std::cout << "error in sign_sha/sign_conv\n";
		}

		if (verify_sey (&item[0], item.size(), sig, ey0, true) != 0) {
			std::cout << "error in verify_sey, ey0\n";
		}

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			uint8_t cy[32];
			mx_to_ey (cy, x1.xs.b);
			sign_sha (&item[0], item.size(), cy, x1.xs.b, sig2);
		}
		t2 = Clock::now();
		std::cout << "mx->ey, sign_sha: " << (t2 - t1)/n << '\n';

		uint8_t mx0[32];
		memcpy (mx0, mx, 32);
		mx0[31] &= 0x7F;
		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (verify_sey (&item[0], item.size(), sig, mx0, false) != 0) {
				std::cout << "error in verify_sey, mx0\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "verify_sey took " << (t2 - t1)/n << '\n';
	}
}


bool is_masked (const uint8_t b[32])
{
	return (b[0] & 0x7) == 0 && (b[31] & 0x40) == 0x40;
}


void test_bad_keys()
{
	Cu25519Sec xs;
	Cu25519Pub xp, xp0;
	uint8_t sh[32];
	// -1
	Cu25519Pub xpm1 = { { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
					  } };
	Cu25519Pub xp1 = { { 1 } };
	Cu25519Pub xp2 = { { 2 } };

	randombytes_buf(xs.b, 32);
	cu25519_generate (&xs, &xp);
	memset(xp0.b, 0, 32);
	try {
		cu25519_shared_secret (sh, xp0, xs);
	} catch (...) {}  // We just want to show the result!
	show_block(std::cout, "DH with 0 ", sh, 32);
	try {
		cu25519_shared_secret (sh, xpm1, xs);
	} catch (...) {}
	show_block(std::cout, "DH with -1", sh, 32);
	try {
		cu25519_shared_secret(sh, xp1, xs);
	} catch (...) {}
	show_block(std::cout, "DH with 1 ", sh, 32);
	cu25519_shared_secret (sh, xp2, xs);
	show_block(std::cout, "DH with 2 ", sh, 32);

	Edwards e;
	memset (&e, 1, sizeof e);
	int err = mx_to_edwards (e, xp0.b, false);
	std::cout << "MX=0, err=" << err << "  e=" << e << '\n';
	err = mx_to_edwards (e, xpm1.b, false);
	std::cout << "MX=-1, err=" << err << "  e=" << e << '\n';
	err = mx_to_edwards (e, xp1.b, false);
	std::cout << "MX=1, err=" << err << "  e=" << e << '\n';

	static uint8_t b[32] = {
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
	};
	show_block (std::cout, "b", b, 32);
	Edwards ed;
	scalarbase (ed, b);
	std::cout << "base times p = " << ed << '\n';

	static uint8_t order[32] = {
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0,    0,    0,    0,    0,    0,    0,    0,
		0,    0,    0,    0,    0,    0,    0,    0x10
	};
	scalarbase (ed, order);
	std::cout << "base times order = " << ed << '\n';
}


void test_sig()
{
	uint8_t ey[32], s[32];
	amber::randombytes_buf (s, 32);
	amber::mask_scalar (s);
	amber::Edwards e;
	scalarbase (e, s);
	edwards_to_ey (ey, e);

	uint8_t mx2[32], ey2[32];
	edwards_to_ey_mx (ey2, mx2, e);
	uint8_t mx3[32];
	edwards_to_mx (mx3, e);
	if (amber::crypto_neq (ey2, ey, 32)) {
		std::cout << "error in edwards_to_ey_mx, ey\n";
	}
	if (amber::crypto_neq (mx2, mx3, 32)) {
		std::cout << "error in edwards_to_ey_mx, mx\n";
	}

	uint8_t sig[64];
	amber::sign_sha (s, 32, ey, s, sig);
	std::cout << "verify_sey1: " << amber::verify_sey (s, 32, sig, ey) << '\n';

	uint8_t ey0[32], ns[32];
	memcpy (ey0, ey, 32);
	memcpy (ns, s, 32);

	if (ey0[31] & 0x80) {
		negate_scalar (ns, s);
		ey0[31] &= 0x7F;
	}
	amber::sign_sha (s, 32, ey0, ns, sig);
	std::cout << "verify_sey2: " << amber::verify_sey (s, 32, sig, ey0) << '\n';

	uint8_t mx0[32];
	amber::ey_to_mx (mx0, ey0);
	std::cout << "verify_sey3: " << amber::verify_sey (s, 32, sig, mx0, false) << '\n';

	show_block (std::cout, "scalar    ", s, 32);
	show_block (std::cout, "neg scalar", ns, 32);
	show_block (std::cout, "ey ", ey, 32);
	show_block (std::cout, "ney", ey0, 32);
}



void real_main()
{
	measure(2000);
	test_bad_keys();
	test_sig();
}

int main()
{
	return run_main(real_main);
}


