/*
 * Copyright (c) 2017-2018, Pelayo Bernedo
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

#ifndef AMBER_HKDF_HPP
#define AMBER_HKDF_HPP

#include "soname.hpp"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include "blake2.hpp"


namespace amber {  inline namespace AMBER_SONAME {


void mix_hash (uint8_t h[32], const uint8_t *data, size_t n)
{
	blake2s_ctx b;
	blake2s_init (&b, 32, NULL, 0);
	blake2s_update (&b, h, 32);
	blake2s_update (&b, data, n);
	blake2s_final (&b, h);
}

void mix_hash_init (uint8_t ck[32], uint8_t h[32], const char *protocol,
                    const uint8_t *pro, size_t plen)
{
	size_t n = strlen (protocol);
	if (n <= 32) {
		memcpy (h, protocol, n);
		memset (h + n, 0, 32 - n);
	} else {
		blake2s_ctx b;
		blake2s_init (&b, 32, NULL, 0);
		blake2s_update (&b, protocol, n);
		blake2s_final (&b, h);
	}
	memcpy (ck, h, 32);
	mix_hash (h, pro, plen);
}

class Hmac2s {
	blake2s_ctx b;
	uint8_t key[64];
public:
	Hmac2s() {}
	Hmac2s (const uint8_t k[32]) { reset (k); }
	void reset (const uint8_t k[32]);
	void update (const uint8_t *data, size_t n) { blake2s_update (&b, data, n); }
	void final (uint8_t h[32]);
};

void Hmac2s::reset (const uint8_t k[32])
{
	memcpy (key, k, 32);
	memset (key + 32, 0, 32);
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
	}
	blake2s_init (&b, 32, NULL, 0);
	blake2s_update (&b, key, sizeof key);
}
void Hmac2s::final (uint8_t h[32])
{
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
		key[i] ^= 0x5c;
	}
	blake2s_final (&b, h);
	blake2s_init (&b, 32, NULL, 0);
	blake2s_update (&b, key, sizeof key);
	blake2s_update (&b, h, 32);
	blake2s_final (&b, h);
}


void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n)
{
	Hmac2s hmac (ck);
	hmac.update (ikm, n);
	uint8_t tmp[32];
	hmac.final (tmp);
	hmac.reset (tmp);
	uint8_t b = 1;
	hmac.update (&b, 1);
	hmac.final (ck);
	hmac.reset (tmp);
	hmac.update (ck, 32);
	b = 2;
	hmac.update (&b, 1);
	hmac.final (k);
}

void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n)
{
	Hmac2s hmac (ck);
	hmac.update (ikm, n);
	uint8_t tmp[32];
	hmac.final (tmp);
	hmac.reset (tmp);
	uint8_t b = 1;
	hmac.update (&b, 1);
	hmac.final (ck);
}



}}
#endif


