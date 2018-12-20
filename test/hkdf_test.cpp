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

#include "hkdf.hpp"
#include "misc.hpp"
#include "sha2.hpp"
#include <iostream>
#include <string.h>

using namespace amber;

void read_all (const char *src, std::vector<uint8_t> &dest)
{
	const char *last;
	read_block (src, &last, dest);
	if (*last != 0) {
		std::cout << "error reading from " << src << '\n';
	}
}

struct Case_hmac {
	const char *key, *data, *hash256, *hash512;
};

void test (const Case_hmac &tc)
{
	std::vector<uint8_t> key, data, expected256, expected512, res;

	read_all (tc.key, key);
	read_all (tc.data, data);
	read_all (tc.hash256, expected256);
	read_all (tc.hash512, expected512);

	Hmac<Sha256> hmac2 (&key[0], key.size());
	hmac2.update (&data[0], data.size());
	res.resize (hmac2.hashlen);
	hmac2.final (&res[0], res.size());
	if (expected256.size() != res.size()) {
		std::cout << "error reading expected256\n";
		return;
	}
	if (memcmp (&res[0], &expected256[0], res.size()) != 0) {
		std::cout << "error in hmac256\n";
	}

	Hmac<Sha512> hmac5 (&key[0], key.size());
	hmac5.update (&data[0], data.size());
	res.resize (hmac5.hashlen);
	hmac5.final (&res[0], res.size());
	if (expected512.size() != res.size()) {
		std::cout << "error reading expected512\n";
		return;
	}
	if (memcmp (&res[0], &expected512[0], res.size()) != 0) {
		std::cout << "error in hmac512\n";
	}
}

struct Test_case {
	const char *ikm;
	const char *salt;
	const char *info;
	unsigned L;
	const char *okm;
};



void test (const Test_case &tc)
{
	std::vector<uint8_t> ikm, salt, info, okm;
	read_all (tc.ikm, ikm);
	read_all (tc.salt, salt);
	read_all (tc.info, info);
	read_all (tc.okm, okm);

	Hkdf<Hmac<Sha256>> hk (&salt[0], salt.size());
	hk.update (&ikm[0], ikm.size());
	std::vector<uint8_t> res (tc.L);
	hk.final (&res[0], res.size(), &info[0], info.size());

	if (tc.L != okm.size()) {
		std::cout << "error reading okm\n";
		return;
	}
	if (memcmp (&okm[0], &res[0], tc.L) != 0) {
		std::cout << "error\n";
		show_block (std::cout, "expected", &okm[0], okm.size());
		show_block (std::cout, "result  ", &res[0], res.size());
		show_block (std::cout, "salt    ", &salt[0], salt.size());
		show_block (std::cout, "ikm     ", &ikm[0], ikm.size());
	}
}

int main()
{
	// RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005
	static const Case_hmac hm[] = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
			"daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
		},
		{
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
			"9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
			"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
			"bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
		},
		{
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
			"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
			"a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
			"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
			"6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
			"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
			"b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
		}
	};
	for (unsigned i = 0; i < sizeof(hm)/sizeof(hm[0]); ++i) {
		test (hm[i]);
	}
	std::cout << "HMAC tests finished\n";

	static const Test_case tc[] = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"000102030405060708090a0b0c",
			"f0f1f2f3f4f5f6f7f8f9",
			42,
			"3cb25f25faacd57a90434f64d0362f2a"
			"2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
			"34007208d5b887185865"
		},
		{
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
			"404142434445464748494a4b4c4d4e4f",
			"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
			"d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			82,
			"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
			"59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
			"cc30c58179ec3e87c14c01d5c1f3434f1d87"
		},
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"",
			"",
			42,
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
			"9d201395faa4b61a96c8"
		}
	};

	for (unsigned i = 0; i < sizeof(tc)/sizeof(tc[0]); ++i) {
		test (tc[i]);
	}
	std::cout << "HKDF tests finished.\n";
}

