#ifndef AMBER_HKDF_HPP
#define AMBER_HKDF_HPP

#include "soname.hpp"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
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

EXPORTFN
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


