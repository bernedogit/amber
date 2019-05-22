/*
 * Copyright (c) 2015-2018, Pelayo Bernedo.
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
#include "group25519.hpp"
#include "misc.hpp"
#include <string.h>

void test()
{
	twamber::Cu25519Sec txs1, txs2;
	twamber::Cu25519Mon txp1, txp2;
	amber::Cu25519Sec axs1, axs2;
	amber::Cu25519Mon axp1, axp2;

	twamber::randombytes_buf (txs1.b, 32);
	cu25519_generate (&txs1, &txp1);

	memcpy (axs1.b, txs1.b, 32);
	cu25519_generate (&axs1, &axp1);

	if (memcmp(axp1.b, txp1.b, 32) != 0) {
		std::cout << "error in cu25519_generate.\n";
	}

	twamber::randombytes_buf (txs2.b, 32);
	cu25519_generate (&txs2, &txp2);

	memcpy (axs2.b, txs2.b, 32);
	cu25519_generate (&axs2, &axp2);

	if (memcmp(axp2.b, txp2.b, 32) != 0) {
		std::cout << "error in cu25519_generate.\n";
	}

	amber::Chakey k1, k2;
	twamber::Chakey k3, k4;
	cu25519_shared_key (&k1, axp1, axs2);
	cu25519_shared_key (&k2, axp2, axs1);
	cu25519_shared_key (&k3, txp1, txs2);
	cu25519_shared_key (&k4, txp2, txs1);

	if (memcmp (k1.kw, k2.kw, 32) != 0) {
		std::cout << "error in cu25519_shared_key 1.\n";
	}
	if (memcmp (k3.kw, k4.kw, 32) != 0) {
		std::cout << "error in cu25519_shared_key 2.\n";
	}
	if (memcmp (k1.kw, k3.kw, 32) != 0) {
		std::cout << "error in cu25519_shared_key 3.\n";
	}

	uint8_t sig1[64], sig2[64];
	cu25519_sign (NULL, (uint8_t*)&k1.kw, 32, txp1, txs1, sig1);
	cu25519_sign (NULL, (uint8_t*)&k1.kw, 32, axp1, axs1, sig2);
	if (memcmp (sig1, sig2, 64) != 0) {
		std::cout << "error in cu25519_sign\n";
	}

	if (cu25519_verify (NULL, (uint8_t*)k1.kw, 32, sig1, txp1) != 0) {
		std::cout << "error in cu25519_verify.\n";
	}
	if (cu25519_verify (NULL, (uint8_t*)k1.kw, 32, sig1, axp1) != 0) {
		std::cout << "error in cu25519_verify.\n";
	}

	amber::Cu25519Ell ar;
	twamber::Cu25519Ell tr;
	cu25519_elligator2_gen (&axs1, &axp1, &ar);
	cu25519_elligator2_gen (&txs1, &txp1, &tr);
	if (memcmp (axs1.b, txs1.b, 32) != 0) {
		std::cout << "error in elligator_gen xs\n";
	}
	if (memcmp (axp1.b, txp1.b, 32) != 0) {
		std::cout << "error in elligator_gen xp\n";
	}
	tr.b[31] &= 0x3F;
	ar.b[31] &= 0x3F;
	if (memcmp (ar.b, tr.b, 32) != 0) {
		std::cout << "error in elligator_gen r\n";
	}

	amber::Cu25519Mon aru;
	twamber::Cu25519Mon tru;
	cu25519_elligator2_rev (&aru, ar);
	cu25519_elligator2_rev (&tru, tr);

	if (memcmp (aru.b, axp1.b, 32) != 0) {
		std::cout << "error in elligator_rev a\n";
	}
	if (memcmp (tru.b, txp1.b, 32) != 0) {
		std::cout << "error in elligator_rev t\n";
	}

	std::cout << "all checks done\n";
}


int main()
{
	test();
}

