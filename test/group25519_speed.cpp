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


typedef std::chrono::steady_clock Clock;


bool point_equal (const Edwards &p1, const Edwards &p2)
{
	Fe z1, z2;
	invert (z1, p1.z);
	invert (z2, p2.z);
	Fe x1, y1, x2, y2;
	mul (x1, p1.x, z1);
	mul (x2, p2.x, z2);
	mul (y1, p1.y, z1);
	mul (y2, p2.y, z2);
	sub (x1, x1, x2);
	sub (y1, y1, y2);
	return ct_is_zero (x1) && ct_is_zero (y1);
}


void measure(int n)
{
	Clock::time_point t1, t2;
	unsigned char shs1[32], shs2[32];
	Cu25519Sec x1s, x2s, x3s;
	Cu25519Mon x1m, x2m, x3m;
	Cu25519Ris x1r, x2r;
	Cu25519Ell ell;

	randombytes_buf (x1s.b, 32);
	randombytes_buf (x2s.b, 32);
	randombytes_buf (x3s.b, 32);

	twamber::Cu25519Sec txs1, txs2, txs3;
	twamber::Cu25519Ris txp1, txp2;
	twamber::Cu25519Ell tell;
	memcpy (txs1.b, x1s.b, 32);
	memcpy (txs2.b, x2s.b, 32);
	memcpy (txs3.b, x3s.b, 32);

	// This first loop may be much slower due to caches being empty! We
	// repeat it later.
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&x1s, &x1m);
		cu25519_generate (&x2s, &x2m);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519 Montgomery key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&x1s, &x1r);
		cu25519_generate (&x2s, &x2r);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519 Ristretto key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&x1s, &x1m);
		cu25519_generate (&x2s, &x2m);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519 Montgomery key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate (&txs1, &txp1);
		cu25519_generate (&txs2, &txp2);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519 key generation: %d\n", (t2 - t1)/n/2);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		twamber::cu25519_shared_secret (shs1, txp1, txs2);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519_shared_secret: %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_base (x1m.b, x1s.b);
	}
	t2 = Clock::now();
	format(std::cout, "ladder key generation: %d\n", (t2 - t1)/n);

	Cu25519Sec xes, xs_saved = x3s;
	Cu25519Mon xem;

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		xes = xs_saved;
		cu25519_elligator2_gen (&xes, &xem, &ell);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519_elligator2_gen(): %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_elligator2_rev (&x3m, ell);
	}
	t2 = Clock::now();
	format(std::cout, "cu25519_elligator2_rev(): %d\n", (t2 - t1)/n);

	twamber::Cu25519Sec txs_saved = txs3;
	twamber::Cu25519Mon txm3;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		txs3 = txs_saved;
		cu25519_elligator2_gen (&txs3, &txm3, &tell);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519_elligator2_gen(): %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_elligator2_rev (&txm3, tell);
	}
	t2 = Clock::now();
	format(std::cout, "twamber::cu25519_elligator2_rev(): %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret(shs1, x1m, x2s);
		cu25519_shared_secret(shs2, x2m, x1s);
	}
	t2 = Clock::now();
	std::cout << "cu25519 shared secret (Montgomery): " << (t2 - t1)/n/2 << '\n';
	if (amber::crypto_neq(shs1, shs2, 32)) {
		std::cout << "error in cu25519_shared_secret\n";
	}

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret_unchecked (shs1, x1m, x2s);
		cu25519_shared_secret_unchecked (shs2, x2m, x1s);
	}
	t2 = Clock::now();
	std::cout << "cu25519 shared secret unchecked (Montgomery): " << (t2 - t1)/n/2 << '\n';
	if (amber::crypto_neq(shs1, shs2, 32)) {
		std::cout << "error in cu25519_shared_secret_unchecked\n";
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
		amber::mxs_to_eys (ey, x1m.b);
	}
	t2 = Clock::now();
	std::cout << "conversion mx to ey: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		amber::eys_to_mxs (mx, ey);
	}
	t2 = Clock::now();
	std::cout << "conversion ey to mx: " << (t2 - t1)/n << '\n';

	amber::Edwards e1, e2;
	scalarbase (e1, x1s.b);
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarmult (e2, e1, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "scalarmult: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarmult_wnaf (e2, e1, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "scalarmult_nafw: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarmult_fw (e2, e1, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "scalarmult_fw: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		scalarbase (e2, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "scalarbase: " << (t2 - t1)/n << '\n';

	Fe ru, rv, rz;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_base (ru, rv, rz, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "montgomery_base: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_base (e2, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "montgomery_base ed output: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_ladder (e2, edwards_base_point, x2s.b);
	}
	t2 = Clock::now();
	std::cout << "montgomery ladder ed input and output: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		montgomery_ladder (e2, edwards_base_point, x2s.b);
		edwards_to_mxs (mx, e2);
	}
	t2 = Clock::now();
	std::cout << "Edwards shared secret: " << (t2 - t1)/n << '\n';


	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		edwards_to_mxs (mx, e1);
	}
	t2 = Clock::now();
	std::cout << "edwards_to_mxs: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		mxs_to_edwards (e1, mx, false);
	}
	t2 = Clock::now();
	std::cout << "mxs_to_edwards: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		edwards_to_eys (ey, e1);
	}
	t2 = Clock::now();
	std::cout << "edwards_to_eys: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		eys_to_edwards (e1, ey, false);
	}
	t2 = Clock::now();
	std::cout << "eys_to_edwards: " << (t2 - t1)/n << '\n';

	uint8_t rs[32];
	Edwards rsdec;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		edwards_to_ristretto (rs, e1);
	}
	t2 = Clock::now();
	std::cout << "edwards_to_ristretto: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		ristretto_to_edwards (rsdec, rs);
	}
	t2 = Clock::now();
	std::cout << "ristretto_to_edwards: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		ristretto_to_mont (rsdec, ru, rv, rs);
	}
	t2 = Clock::now();
	std::cout << "ristretto_to_mont: " << (t2 - t1)/n << '\n';

	Edwards sm1, sm2;
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		ristretto_to_mont (rsdec, ru, rv, rs);
		montgomery_ladder (sm1, ru, rv, rs);
	}
	t2 = Clock::now();
	std::cout << "ristretto_to_mont, ladder: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		ristretto_to_edwards (rsdec, rs);
		scalarmult_fw (sm2, rsdec, rs);
	}
	t2 = Clock::now();
	std::cout << "ristretto_to_edwards, fw: " << (t2 - t1)/n << '\n';

	if (!point_equal (sm1, sm2)) {
		format (std::cout, "rsmont, ladder and rsed, fw differ\n");
	}

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		ristretto_to_edwards (rsdec, rs);
		scalarmult_wnaf (sm2, rsdec, rs);
	}
	t2 = Clock::now();
	std::cout << "ristretto_to_edwards, wnaf: " << (t2 - t1)/n << '\n';

	if (!point_equal (sm1, sm2)) {
		format (std::cout, "rsmont, ladder and rsed, wnaf differ\n");
	}


	Cu25519Sec rsc;
	Cu25519Ris ris;
	randombytes_buf (rsc.b, 32);
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_generate_no_mask (rsc, &ris);
	}
	t2 = Clock::now();
	std::cout << "ristretto_generate: " << (t2 - t1)/n << '\n';

	uint8_t rsmul[32];
	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret (rsmul, ris, x1s);
	}
	t2 = Clock::now();
	std::cout << "Ristretto ladder: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret_cof (rsmul, ris, x1s);
	}
	t2 = Clock::now();
	std::cout << "Ristretto ladder_cof: " << (t2 - t1)/n << '\n';

	t1 = Clock::now();
	for (int i = 0; i < n; ++i) {
		cu25519_shared_secret_unchecked (rsmul, ris, x1s);
	}
	t2 = Clock::now();
	std::cout << "Ristretto ladder unchecked: " << (t2 - t1)/n << '\n';

	Fe fe1, fe2;
	uint8_t scr[32];
	randombytes_buf (scr, 32);
	load (fe1, scr);
	fe2 = fe1;
	int fen = n * 10;

	std::cout << "Loops enlarged 10 times\n";

	t1 = Clock::now();
	for (int i = 0; i < fen; ++i) {
		invert (fe2, fe1);
	}
	t2 = Clock::now();
	format (std::cout, "invert() took %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < fen; ++i) {
		sqrt (fe1, fe1);
	}
	t2 = Clock::now();
	format (std::cout, "sqrt() took %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < fen; ++i) {
		invsqrt (fe1, fe1);
	}
	t2 = Clock::now();
	format (std::cout, "invsqrt() took %d\n", (t2 - t1)/n);

	t1 = Clock::now();
	for (int i = 0; i < fen; ++i) {
		sqrt_ratio_m1 (fe1, fe1, fe2);
	}
	t2 = Clock::now();
	format (std::cout, "sqrt_ratio_m1() took %d\n", (t2 - t1)/n);

	cu25519_generate (&x1s, &x1m);
	mxs_to_eys (ey, x1m.b);
	memcpy (mx, x1m.b, 32);

	uint8_t ns[32], ey0[32];
	memcpy (ey0, ey, 32);
	if (ey0[31] & 0x80) {
		negate_scalar (ns, x1s.b);
		ey0[31] &= 0x7F;
	} else {
		memcpy (ns, x1s.b, 32);
	}

	memcpy (txs1.b, x1s.b, 32);
	twamber::cu25519_generate (&txs1, &txp1);
	unsigned char sig[64], sig2[64];
	static const int text_lengths[] = { 64, 20000 };
	for (unsigned i = 0; i < sizeof(text_lengths)/sizeof(text_lengths[0]); ++i) {
		std::vector<unsigned char> item(text_lengths[i]);
		std::cout << "Signing and verifying with text length: " << item.size() << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			sign_bmx ("foo", &item[0], item.size(), x1m.b, x1s.b, sig);
		}
		t2 = Clock::now();
		std::cout << "sign_bmx: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (verify_bmx ("foo", &item[0], item.size(), sig, x1m.b) != 0) {
				std::cout << "error in verify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "verify_bmx: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			twamber::cu25519_sign (NULL, &item[0], item.size(), txp1, txs1, sig);
		}
		t2 = Clock::now();
		std::cout << "twamber::cu25519 sign: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (twamber::cu25519_verify (NULL, &item[0], item.size(), sig, txp1) != 0) {
				std::cout << "error in twamber::verify\n";
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
		std::cout << "sign_sha: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		if (verify_sey (&item[0], item.size(), sig, ey0) != 0) {
			std::cout << "error in verify_sey, ey0\n";
		}
		t2 = Clock::now();
		std::cout << "verify_sey: " << (t2 - t1)/n << '\n';


		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			uint8_t cy[32];
			mxs_to_eys (cy, x1s.b);
			sign_sha (&item[0], item.size(), cy, x1s.b, sig2);
		}
		t2 = Clock::now();
		std::cout << "mx->ey, sign_sha: " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			curvesig ("Amber sig", &item[0], item.size(), x1m.b, x1s.b, sig);
		}
		t2 = Clock::now();
		format (std::cout, "curvesig took %d\n", (t2 - t1)/n);

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (curverify ("Amber sig", &item[0], item.size(), sig, x1m.b) != 0) {
				std::cout << "error in curverify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "curverify took " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (curverify_mont ("Amber sig", &item[0], item.size(), sig, x1m.b) != 0) {
				std::cout << "error in curverify_mont\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "curverify_mont took " << (t2 - t1)/n << '\n';


		uint8_t rissig[64];
		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			cu25519_sign ("ristretto", &item[0], item.size(), ris, rsc, rissig);
		}
		t2 = Clock::now();
		std::cout << "cu25519_sign (ris): " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (cu25519_verify ("ristretto", &item[0], item.size(), rissig, ris) != 0) {
				std::cout << "error in cu25519_verify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "cu25519_verify (ris): " << (t2 - t1)/n << '\n';

		t1 = Clock::now();
		for (int i = 0; i < n; ++i) {
			if (ristretto_qdsa_verify ("ristretto", &item[0], item.size(), rissig, ris) != 0) {
				std::cout << "error in ristretto_qdsa_verify\n";
				break;
			}
		}
		t2 = Clock::now();
		std::cout << "ristretto_qdsa_verify: " << (t2 - t1)/n << '\n';
	}
}


bool is_masked (const uint8_t b[32])
{
	return (b[0] & 0x7) == 0 && (b[31] & 0x40) == 0x40;
}


void test_bad_keys()
{
	Cu25519Sec xs;
	Cu25519Mon xp, xp0;
	uint8_t sh[32];
	// -1
	Cu25519Mon xpm1 = { { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
					  } };
	Cu25519Mon xp1 = { { 1 } };
	Cu25519Mon xp2 = { { 2 } };

	randombytes_buf(xs.b, 32);
	cu25519_generate (&xs, &xp);
	memset(xp0.b, 0, 32);
	cu25519_shared_secret_unchecked (sh, xp0, xs);
	show_block(std::cout, "DH with 0 ", sh, 32);
	cu25519_shared_secret_unchecked (sh, xpm1, xs);
	show_block(std::cout, "DH with -1", sh, 32);
	cu25519_shared_secret_unchecked (sh, xp1, xs);
	show_block(std::cout, "DH with 1 ", sh, 32);
	cu25519_shared_secret_unchecked (sh, xp2, xs);
	show_block(std::cout, "DH with 2 ", sh, 32);

	Edwards e;
	memset (&e, 1, sizeof e);
	int err = mxs_to_edwards (e, xp0.b, false);
	std::cout << "MX=0, err=" << err << "  e=" << e << '\n';
	err = mxs_to_edwards (e, xpm1.b, false);
	std::cout << "MX=-1, err=" << err << "  e=" << e << '\n';
	err = mxs_to_edwards (e, xp1.b, false);
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
	edwards_to_eys (ey, e);

	uint8_t mx2[32], ey2[32];
	edwards_to_eys_mxs (ey2, mx2, e);
	uint8_t mx3[32];
	edwards_to_mxs (mx3, e);
	if (amber::crypto_neq (ey2, ey, 32)) {
		std::cout << "error in edwards_to_eys_mxs, ey\n";
	}
	if (amber::crypto_neq (mx2, mx3, 32)) {
		std::cout << "error in edwards_to_eys_mxs, mx\n";
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
}



void real_main()
{
	measure (1000);
	test_bad_keys();
	test_sig();
}

int main()
{
	return run_main(real_main);
}


