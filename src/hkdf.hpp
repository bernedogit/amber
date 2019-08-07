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


namespace amber {  inline namespace AMBER_SONAME {

// RFC 2104

template <class Hash>
class Hmac {
	uint8_t key[Hash::blocklen];
	Hash h;
public:
	enum { blocklen = Hash::blocklen, hashlen = Hash::hashlen };
	Hmac (const void *key, size_t n) { reset (key, n); }
	void reset (const void *key, size_t n);
	void update (const void *data, size_t n) { h.update (data, n); }
	void final (uint8_t *mac, size_t n);
};

template <class Hash>
void Hmac<Hash>::reset (const void *keyb, size_t nbytes)
{
	h.reset ();

	if (nbytes > Hash::blocklen) {
		Hash tmph;
		tmph.update (keyb, nbytes);
		tmph.final (key);
		memset (key + hashlen, 0, blocklen - hashlen);
	} else {
		memcpy (key, keyb, nbytes);
		memset (key + nbytes, 0, sizeof key - nbytes);
	}

	uint8_t k2[Hash::blocklen];
	for (size_t i = 0; i < sizeof key; ++i) {
		k2[i] = key[i] ^ 0x36;
	}
	h.update (k2, sizeof k2);
}

template <class Hash>
void Hmac<Hash>::final (uint8_t *mac, size_t n)
{
	uint8_t k2[Hash::blocklen];
	for (size_t i = 0; i < sizeof key; ++i) {
		k2[i] = key[i] ^ 0x5c;
	}
	uint8_t tag[Hash::hashlen];
	h.final (tag);
	h.reset();
	h.update (k2, sizeof k2);
	h.update (tag, sizeof tag);
	if (n == Hash::hashlen) {
		h.final (mac);
	} else {
		h.final (tag);
		memcpy (mac, tag, n > (unsigned)Hash::hashlen ? (unsigned)Hash::hashlen : n);
	}
}

// RFC 5869

template <class Hmac>
class Hkdf {
	Hmac hmac;
public:
	Hkdf (const void *salt=0, size_t slen=0) : hmac (salt, slen) {}
	void reset (const void *salt=0, size_t slen=0) { hmac.reset (salt, slen); }
	void update (const void *ikm, size_t n) { hmac.update (ikm, n); }
	void final (void *dest, size_t n, const void *info=0, size_t ilen=0);
};

template <class Hmac>
void Hkdf<Hmac>::final (void *dest, size_t n, const void *info, size_t ilen)
{
	uint8_t prk[Hmac::hashlen], tag[Hmac::hashlen];
	hmac.final (prk, sizeof prk);
	uint8_t bcount = 1;
	unsigned tsize = 0;
	uint8_t *bdest = (uint8_t*) dest;

	while (n > 0) {
		hmac.reset (prk, sizeof prk);
		hmac.update (tag, tsize);
		hmac.update (info, ilen);
		hmac.update (&bcount, 1);
		hmac.final (tag, sizeof tag);
		tsize = sizeof tag;
		++bcount;
		if (n > sizeof tag) {
			memcpy (bdest, tag, sizeof tag);
			n -= sizeof tag;
			bdest += sizeof tag;
		} else {
			memcpy (bdest, tag, n);
			bdest += n;
			n = 0;
		}
	}
}

// Helpers for Noise using Blake2s. Keep ck, k and h updated. ck is the
// chaining key: it contains the state of the keying material. k is the key
// used to encrypt the next messages of the protocol. h is the hash of all
// the previous premessages and any traffic exchanged.

// Init the chaining key and the running hash of noise.
EXPORTFN
void mix_hash_init (uint8_t ck[32], uint8_t h[32], const char *protocol,
                    const uint8_t *prologue, size_t prologue_len);

// Update the running hash. Update it with any premessage and with any
// transfer of data.
EXPORTFN void mix_hash (uint8_t h[32], const uint8_t *data, size_t n);

// Update the chaining key and the encryption key with input key material,
// ikm[0..n-1].
EXPORTFN
void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n);

// To split call mix_key with ikm=NULL, n=0. ck is the first key and k is the
// second key.

// Version of mix_key with just the chaining key if we do not use the
// encryption key k.
EXPORTFN void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n);


}}
#endif


