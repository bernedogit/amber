/*
 * Copyright (c) 2012-2018, Pelayo Bernedo.
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
#include "misc.hpp"
#include "hasopt.hpp"
#include <iostream>
#include <string>
#include <random>

using namespace amber;


int main()
{
	uint8_t x[16];
	randombytes_buf(x, sizeof x);
	std::string s;
	base32enc(x, sizeof x, s, true, false, true);
	format(std::cout, _("Randomly generated, case independent password.\n"));
	format(std::cout, _("Four groups of four digits (80 bits of entropy) should be enough.\n"));
	format(std::cout, _("Entropy bits:      20   40   60   80  100  120\n"));
	format(std::cout, _("Caseless, ascii: %s\n"), s);
	show_block (std::cout, "Hex", x, 16);
	base58enc(x, sizeof x, s);
	format(std::cout, _("Base58 together: %s\n"), s);
	format(std::cout, _("Entropy bits:  23   47   70   94  117\n"));
	format(std::cout, _("Base 58:      %s %s %s %s %s\n"), s.substr(0,4), s.substr(4,4),
	        s.substr(8,4), s.substr(12,4), s.substr(16,4));

	std::random_device rd;
	uintmax_t range = rd.max() - rd.min() + 1;
	std::random_device::result_type val, low = (range % 6) + rd.min();
	// Discard values less than low. There are range - range%6 possible
	// acceptable values. Each of them of equal probability. If we mod them
	// by 6, we will get bytes with uniform probability.
	format(std::cout, _("Entropy:            13     26     39     52     65     77     90    103    116    129\n"));
	std::cout << _("Diceware indexes: ");
	for (int i = 0; i < 10; ++i) {
		for (int j = 0; j < 5; ++j) {
			do {
				val = rd();
			} while (val < low);
			std::cout << val%6 + 1;
		}
		std::cout << "  ";
	}
	std::cout << '\n';
}


