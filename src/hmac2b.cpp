class Hmac2b {
	uint8_t key[128];
	blake2b_ctx bl;
public:
	Hmac2b (const void *key, size_t n) { reset (key, n); }
	void reset (const void *key, size_t n);
	void update (const void *data, size_t n) { blake2b_update (&bl, data, n); }
	void final (uint8_t *mac, size_t n);
};

void Hmac2b::reset (const void *keyb, size_t nbytes)
{
	blak2b_init (&b, 64, NULL, 0);

	if (nbytes > 128) {
		blake2b (key, 64, keyb, nbytes, NULL, 0);
		memset (key + 64, 0, 64);
	} else {
		memcpy (key, keyb, nbytes);
		memset (key + nbytes, 0, sizeof key - nbytes);
	}

	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
	}
	blake2b_update (&bl, key, sizeof key);
}

void Hmac2b::final (uint8_t *mac, size_t n)
{
	for (size_t i = 0; i < sizeof key; ++i) {
		key[i] ^= 0x36;
		key[i] ^= 0x5c;
	}
	uint8_t tag[64];
	blake2b_final (&bl, tag);
	blake2b_init (&bl, 64, NULL, 0);
	blake2b_update (&bl, key, sizeof key);
	blake2b_update (&bl, tag, sizeof tag);
	blake2b_final (&bl, tag);
	memcpy (mac, tag, n > 64 ? 64 : n);
}

void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n)
{
	Hmac2b hmac (ck);
	hmac.update (ikm, n);
	uint8_t tmp[64];
	hmac.final (tmp);
	hmac.reset (tmp);
	uint8_t b = 1;
	hmac.update (&b, 1);
	hmac.final (tmp);
	memcpy (ck, tmp, 32);
	memcpy (k, tmp + 32, 32);
}

void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n)
{
	Hmac2b hmac (ck);
	hmac.update (ikm, n);
	uint8_t tmp[64];
	hmac.final (tmp);
	hmac.reset (tmp);
	uint8_t b = 1;
	hmac.update (&b, 1);
	hmac.final (tmp);
	memcpy (ck, tmp, 32);
}


