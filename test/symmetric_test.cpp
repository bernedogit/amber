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

#include "symmetric.hpp"
#include "misc.hpp"
#include <iostream>
#include <string.h>
#include "hasopt.hpp"

// Verification with the ChaCha20 vectors available from
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00

// We do not test Poly1305 because we took it as it is from donna.

using namespace amber;

struct Chacha_vector {
	const char *key, *nonce, *stream;
};


void test_chacha20_case(const Chacha_vector &cv)
{
	std::vector<uint8_t> vk, vn, vs;
	const char *next;

	read_block(cv.key, &next, vk);
	read_block(cv.nonce, &next, vn);
	read_block(cv.stream, &next, vs);

	if (vk.size() != 32) {
		std::cout << "Wrong size in test vector key, expected 32, got " << vk.size() << '\n';
		return;
	}
	if (vn.size() != 8) {
		std::cout << "Wrong size in test vector nonce, expected 8, got " << vn.size() << '\n';
		return;
	}

	uint32_t kn[12];
	for (unsigned i = 0; i < 8; ++i) {
		kn[i] = leget32 (&vk[i*4]);
	}
	kn[8] = kn[9] = 0;
	kn[10] = leget32 (&vn[0]);
	kn[11] = leget32 (&vn[4]);

	std::vector<uint8_t> dest(vs.size());

	for (size_t i = 0; i < dest.size(); ++i) {
		dest[i] = 0;
	}

	size_t pos = 0;
	size_t lim = dest.size();
	while (pos + 64 <= lim) {
		chacha20(&dest[pos], kn);
		kn[8]++;
		pos += 64;
	}
	if (pos < lim) {
		uint8_t tmp[64];
		chacha20(tmp, kn);
		memcpy(&dest[pos], tmp, lim - pos);
	}


	if (memcmp(&dest[0], &vs[0], dest.size()) != 0) {
		std::cout << "Error in test vector\n";
		show_block(std::cout, "key     ", &vk[0], vk.size());
		show_block(std::cout, "nonce   ", &vn[0], vn.size());
		show_block(std::cout, "stream  ", &vs[0], vs.size());
		show_block(std::cout, "computed", &dest[0], dest.size());
		return;
	}
}

// Test vectors from
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00

static const Chacha_vector chv[] = {
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000",
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc"
		"8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c"
		"c387b669"
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000",
		"4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952"
		"ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea81"
		"7e9ad275"
	},
	{
		"00000000000000000000000000000000000000000000000000000000"
		"00000000",
		"0000000000000001",
		"de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df1"
		"37821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e"
		"445f41e3"
	},
	{
		"00000000000000000000000000000000000000000000000000000000"
		"00000000",
		"0100000000000000",
		"ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd1"
		"38e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d"
		"6bbdb004"
	},
	{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
		"1c1d1e1f",
		"0001020304050607",
		"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56"
		"f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1"
		"5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526"
		"4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e"
		"09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750"
		"32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5"
		"07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7"
		"6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2"
		"ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb"
	}
};

// RFC 7539 Test vector.
struct Chachapoly_case {
	const char *pt, *aad, *key, *iv, *ct;
};

static const Chachapoly_case ccc[] = {
	{
		"4c616469657320616e642047656e746c"
		"65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73"
		"73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63"
		"6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f"
		"6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20"
		"74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73"
		"63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69"
		"74 2e",
		"50 51 52 53 c0 c1 c2 c3 c4 c5 c6c7",
		"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
		"90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
		"40 41 42 43 44 45 46 47",
		"d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
		"a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
		"3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
		"1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
		"92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
		"fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
		"3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
		"61 16"
		"1ae10b594f09e26a7e902ecbd0600691"
	}
};


void read_all (const char *s, std::vector<uint8_t> &out)
{
	const char *next;
	read_block (s, &next, out);
	if (*next != 0) {
		std::cout << "Did not read all.\n";
	}
}

void test (const Chachapoly_case &tc)
{
	std::vector<uint8_t> pt, aad, key, iv, ct;
	read_all (tc.pt, pt);
	read_all (tc.aad, aad);
	read_all (tc.key, key);
	read_all (tc.iv, iv);
	read_all (tc.ct, ct);

	Chakey kw;
	load (&kw, &key[0]);

	uint64_t n = leget64 (&iv[0]);
	uint32_t sender = 7;
	std::vector<uint8_t> cv (pt.size() + 16);
	encrypt_one (&cv[0], &pt[0], pt.size(), &aad[0], aad.size(), kw, n, sender);
	if (cv.size() != ct.size() || memcmp (&cv[0], &ct[0], cv.size()) != 0) {
		show_block (std::cout, "cv", &cv[0], cv.size());
		show_block (std::cout, "ct", &ct[0], cv.size());
	}
}


void test_hchacha ()
{
	// Test case from
	// https://tools.ietf.org/html/draft-arciszewski-xchacha-03
	uint8_t key1[32];
	for (int i = 0; i < 32; ++i) key1[i] = i;
	uint8_t nonce[] = {
		0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27
	};
	uint32_t k2[8];
	uint32_t expected[8] = { 0x423b4182, 0xfe7bb227, 0x50420ed3, 0x737d878a,
	                         0xd5e4f9a0, 0x53a8748a, 0x13c42ec1, 0xdcecd326 };
	hchacha20 (k2, key1, nonce);
	for (int i = 0; i < 8; ++i) {
		if (expected[i] != k2[i]) {
			format (std::cout, "error in hchacha[%d], expected = 0x%08X  computed = 0x%08X\n",
			        i, expected[i], k2[i]);
		}
	}
	format (std::cout, "HChaCha20 tested\n");
}


void test_packets()
{
	enum { msglen = 3 };

	uint8_t pt[msglen], ct[msglen + 300], dec[msglen * 2];
	int vals[] = { 0, 1, 63, 64, 127, 128, 0xFFFFFFF };
	Chakey key;

	for (unsigned i = 0; i < msglen; ++i) pt[i] = i;
	load (&key, pt);

	for (unsigned i = 0; i < sizeof(vals)/sizeof(vals[0]); ++i) {
		size_t n = encrypt_packet (ct, pt, msglen, vals[i], 50, key, i);
		uint64_t uval;
		int err = peek_head (&uval, ct, key, i);
		if (err != 0) {
			std::cout << "Error decrypting the uval\n";
		}
		if (uval != (uint64_t)vals[i]) {
			std::cout << "encrypted val=" << vals[i] << " but decrypted " << uval << '\n';
		}
		size_t decmlen;
		err = decrypt_packet (dec, &decmlen, &uval, ct, n, 50, key, i);
		if (err != 0) {
			std::cout << "could not decrypt the packet\n";
		} else {
			if (decmlen != msglen) {
				std::cout << "error in decrypt_packet, decmlen=" << decmlen << "  msglen=" << msglen << '\n';
			}
			if (uval != (uint64_t)vals[i]) {
				std::cout << "error in decrypt_packet, uval=" << uval << "  expected=" << vals[i] << '\n';
			}
			if (memcmp (dec, pt, msglen) != 0) {
				std::cout << "Wrong message decoded\n";
			}
		}
	}
}


int main()
{
	enum { num_vecs = sizeof(chv)/sizeof(chv[0]) };
	for (size_t i = 0; i < num_vecs; ++i) {
		test_chacha20_case(chv[i]);
	}
	std::cout << num_vecs << " ChaCha20 test vectors checked\n";

	test (ccc[0]);
	test_hchacha();
	test_packets();
}


