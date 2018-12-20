#include "siphash24.hpp"
#include "misc.hpp"
#include "symmetric.hpp"


namespace amber {   namespace AMBER_SONAME {


// Siphash24 portable implementation written by Gregory Petrosyan
// <gregory.petrosyan@gmail.com> taken from
// https://github.com/flyingmutant/siphash and licensed with the MIT license.


inline uint64_t sip_srotl64 (uint64_t u, int s)
{
	return (u << s) | (u >> (64 - s));
}

inline uint8_t sip_get8 (void const* data, size_t ix)
{
	return *((uint8_t const*)data + ix);
}



inline void sip_round(uint64_t* v0, uint64_t* v1, uint64_t* v2, uint64_t* v3)
{
	*v0 += *v1;
	*v1 = sip_srotl64(*v1, 13);
	*v1 ^= *v0;
	*v0 = sip_srotl64(*v0, 32);

	*v2 += *v3;
	*v3 = sip_srotl64(*v3, 16);
	*v3 ^= *v2;

	*v2 += *v1;
	*v1 = sip_srotl64(*v1, 17);
	*v1 ^= *v2;
	*v2 = sip_srotl64(*v2, 32);

	*v0 += *v3;
	*v3 = sip_srotl64(*v3, 21);
	*v3 ^= *v0;
}


inline void sip_compress2(uint64_t* v0, uint64_t* v1, uint64_t* v2, uint64_t* v3, uint64_t m)
{
	*v3 ^= m;

	sip_round(v0, v1, v2, v3);
	sip_round(v0, v1, v2, v3);

	*v0 ^= m;
}


inline uint64_t sip_last(const uint8_t *u8, size_t size)
{
	uint64_t v = 0;

	// The purpose of the fall through comments below is to keep the compiler
	// happy and prevent it from issuing wrong warnings.
	switch (size % 8) {
	case 7:  v |= uint64_t(u8[6]) << 48;    // fall through
	case 6:  v |= uint64_t(u8[5]) << 40;    // fall through
	case 5:  v |= uint64_t(u8[4]) << 32;    // fall through
	case 4:  v |= uint64_t(u8[3]) << 24;    // fall through
	case 3:  v |= uint64_t(u8[2]) << 16;    // fall through
	case 2:  v |= uint64_t(u8[1]) << 8;     // fall through
	case 1:  v |= uint64_t(u8[0]);
	}
	v |= uint64_t(size & 0xFF) << 56;
	return v;
}



uint64_t siphash24 (void const *data, size_t size, uint64_t k1, uint64_t k2)
{
	uint64_t v0 = k1 ^ 0x736f6d6570736575ull;
	uint64_t v1 = k2 ^ 0x646f72616e646f6dull;
	uint64_t v2 = k1 ^ 0x6c7967656e657261ull;
	uint64_t v3 = k2 ^ 0x7465646279746573ull;

	size_t len = size;
	const uint8_t *u8m = (const uint8_t*)data;
	while (len >= 8) {
		sip_compress2(&v0, &v1, &v2, &v3, leget64(u8m));
		u8m += 8;
		len -= 8;
	}
	sip_compress2(&v0, &v1, &v2, &v3, sip_last(u8m, size));

	v2 ^= 0xff;

	sip_round(&v0, &v1, &v2, &v3);
	sip_round(&v0, &v1, &v2, &v3);
	sip_round(&v0, &v1, &v2, &v3);
	sip_round(&v0, &v1, &v2, &v3);

	return v0 ^ v1 ^ v2 ^ v3;
}



void Siphash24::reset (uint64_t k1, uint64_t k2)
{
	v0 = k1 ^ 0x736f6d6570736575ull;
	v1 = k2 ^ 0x646f72616e646f6dull;
	v2 = k1 ^ 0x6c7967656e657261ull;
	v3 = k2 ^ 0x7465646279746573ull;
	pending = 0;
	npending = 0;
	total = 0;
}

void Siphash24::update (const void *p, size_t n)
{
	const uint8_t *u8m = (const uint8_t*)p;
	if (npending != 0) {
		while (npending < 8 && n > 0) {
			pending |= uint64_t(*u8m) << (npending * 8);
			++npending;
			++u8m;
			--n;
		}
		if (npending == 8) {
			sip_compress2(&v0, &v1, &v2, &v3, pending);
			npending = 0;
			pending = 0;
			total += 8;
		}
	}

	while (n >= 8) {
		sip_compress2(&v0, &v1, &v2, &v3, leget64(u8m));
		u8m += 8;
		n -= 8;
		total += 8;
	}

	while (n > 0) {
		pending |= uint64_t(*u8m) << (npending * 8);
		++npending;
		++u8m;
		--n;
	}
}


uint64_t Siphash24::final()
{
	pending |= (uint64_t(total + npending) & 0xFF) << 56;
	sip_compress2(&v0, &v1, &v2, &v3, pending);

	v2 ^= 0xff;

	sip_round(&v0, &v1, &v2, &v3);
	sip_round(&v0, &v1, &v2, &v3);
	sip_round(&v0, &v1, &v2, &v3);
	sip_round(&v0, &v1, &v2, &v3);

	return v0 ^ v1 ^ v2 ^ v3;
}


struct Two_longs {
	uint64_t sk[2];
	Two_longs();
};
Two_longs::Two_longs()
{
	randombytes_buf (sk, sizeof sk);
}

const uint64_t * get_static_key()
{
	static Two_longs ska;
	return ska.sk;
}


uint64_t siphash24 (void const *data, size_t size)
{
	static const uint64_t *k = get_static_key();
	return siphash24(data, size, k[0], k[1]);
}

void Siphash24::reset()
{
	static const uint64_t *k = get_static_key();
	reset (k[0], k[1]);
}



}}


