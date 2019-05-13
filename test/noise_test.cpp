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

#include "noise.hpp"
#include "hasopt.hpp"
#include <assert.h>

using namespace amber;

void test_one (Handshake::Predef ht, bool sknown, bool rsknown, bool elligated)
{
	Handshake ini, res;

	ini.initialize (ht, NULL, 0, elligated);
	res.initialize (ht, NULL, 0, elligated);

	Cu25519Pair inikey, reskey;
	randombytes_buf (inikey.xs.b, 32);
	randombytes_buf (reskey.xs.b, 32);
	cu25519_generate (&inikey.xs, &inikey.xp);
	cu25519_generate (&reskey.xs, &reskey.xp);
	ini.set_s (inikey, sknown);
	res.set_s (reskey, rsknown);

	if (sknown) {
		res.set_known_rs (inikey.xp);
	}
	if (rsknown) {
		ini.set_known_rs (reskey.xp);
	}
	format (std::cout, "Testing handshake %s, elligated: %s\n",
	        Handshake::name (ht), elligated);

	char pay1[] = "First message";
	char pay2[] = "Second message";
	char pay3[] = "Third message";
	std::vector<uint8_t> msg, pay;

	ini.write_message ((uint8_t*)pay1, sizeof pay1, msg);
	if (res.read_message (&msg[0], msg.size(), pay) != 0) {
		std::cout << "failed reading first message.\n";
		return;
	}
	if (pay.size() != sizeof (pay1) || crypto_neq (&pay[0], pay1, pay.size())) {
		std::cout << "first payload: " << &pay[0] << '\n';
	}

	if (!ini.finished()) {
		res.write_message ((uint8_t*)pay2, sizeof pay2, msg);
		if (ini.read_message (&msg[0], msg.size(), pay) != 0) {
		  std::cout << "failed reading second message.\n";
			return;
		}
		if (pay.size() != sizeof(pay2) || crypto_neq (&pay[0], pay2, pay.size())) {
			std::cout << "second payload: " << &pay[0] << '\n';
		}

		if (!ini.finished()) {
			ini.write_message ((uint8_t*)pay3, sizeof pay3, msg);
			if (res.read_message (&msg[0], msg.size(), pay) != 0) {
				std::cout << "failed reading third message.\n";
				return;
			}
			if (pay.size() != sizeof(pay3) || crypto_neq (&pay[0], pay3, pay.size())) {
				std::cout << "third payload: " << &pay[0] << '\n';
			}
		}
	}

	if (!ini.finished()) {
		std::cout << "ini is not finished\n";
	}
	if (!res.finished()) {
		std::cout << "res is not finished\n";
	}
	Cipher itx, irx, rtx, rrx;
	ini.split (&itx, &irx);
	res.split (&rtx, &rrx);

	if (crypto_neq (itx.get_key(), rrx.get_key(), 32)) {
		std::cout << "error in itx/rrx\n";
	}
	if (crypto_neq (irx.get_key(), rtx.get_key(), 32)) {
		std::cout << "error in irx/rtx\n";
	}
}

void read_all (const char *src, std::vector<uint8_t> &dest)
{
	const char *last;
	read_block (src, &last, dest);
	if (*last != 0) {
		std::cout << "error reading from " << src << '\n';
	}
}


struct First_case {
	Handshake::Predef htype;
	bool s_known;
	const char *prologue, *eseed, *sseed, *irs, *payload, *ciphertext;
};

static First_case fc[] = {
	{
		Handshake::N, false,
		"50726f6c6f677565313233",
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
		"",
		"31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
		"4c756477696720766f6e204d69736573",
		"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79441b168ed8bbe8220b52bbbde6593d109d0590dcd71f942224efaa932b5e4a052b"
	},
	{
		Handshake::X, false,
		"50726f6c6f677565313233",
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
		"e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
		"31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
		"4c756477696720766f6e204d69736573",
		"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79448bc3b729d16d3944f1bfae9fa98e0d306234bfadc44880f99a69c6e55b6c14581df5d4b8a62016a6d7881bcf1d53df2a830ae461a4479228789a38085be55b139727221a332addc1b622bf1570b60675"
	},
	{
		Handshake::K, true,
		"50726f6c6f677565313233",
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
		"e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
		"31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
		"4c756477696720766f6e204d69736573",
		"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79443ab57eb07c96791ebddff95c2ed2ccfec49affc5ecdc8895ba9f796df4659870"
	}
};

// Test the first message.
void test_first (const First_case &fc)
{
	std::vector<uint8_t> ipro, ieph, ista, irs, pay, ct;

	read_all (fc.prologue, ipro);
	read_all (fc.eseed, ieph);
	read_all (fc.sseed, ista);
	read_all (fc.irs, irs);
	read_all (fc.payload, pay);
	read_all (fc.ciphertext, ct);

	Cu25519Pair ie, is;
	Cu25519Mon rsp;

	assert (ieph.size() == 32);
	memcpy (ie.xs.b, &ieph[0], 32);
	cu25519_generate (&ie.xs, &ie.xp);
	ie.xp.b[31] &= 0x7f;

	if (ista.size() != 0) {
		assert (ista.size() == 32);
		memcpy (is.xs.b, &ista[0], 32);
		cu25519_generate (&is.xs, &is.xp);
		is.xp.b[31] &= 0x7f;
	}

	assert (irs.size() == 32);
	memcpy (rsp.b, &irs[0], 32);

	std::vector<uint8_t> out;
	Handshake hk;
	hk.initialize (fc.htype, &ipro[0], ipro.size(), false);
	hk.set_known_rs (rsp);
	hk.set_e_sec (&ieph[0]);
	if (!ista.empty()) {
		hk.set_s (is, fc.s_known);
	}
	hk.write_message (&pay[0], pay.size(), out);
	if (out.size() != ct.size() || crypto_neq (&out[0], &ct[0], ct.size())) {
		show_block (std::cout, "out", &out[0], out.size());
		show_block (std::cout, "exp", &ct[0], ct.size());
	}
}


void real_main()
{
	for (int i = 0; i < 2; ++i) {
		test_one (Handshake::N, false, true, i);
		test_one (Handshake::K, true, true, i);
		test_one (Handshake::X, false, true, i);

		test_one (Handshake::NN, false, false, i);
		test_one (Handshake::NK, false, true, i);
		test_one (Handshake::NX, false, false, i);

		test_one (Handshake::KN, true, false, i);
		test_one (Handshake::KK, true, true, i);
		test_one (Handshake::KX, true, false, i);

		test_one (Handshake::XN, false, false, i);
		test_one (Handshake::XK, false, true, i);
		test_one (Handshake::XX, false, false, i);

		test_one (Handshake::IN, false, false, i);
		test_one (Handshake::IK, false, true, i);
		test_one (Handshake::IX, false, false, i);
	}
	std::cout << "Round trip tests done.\n";

	test_first (fc[0]);
	test_first (fc[1]);
	test_first (fc[2]);
	std::cout << "One way tests vectors done.\n";
}

int main()
{
	return run_main (real_main);
}





