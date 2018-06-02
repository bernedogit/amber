#ifndef AMBER_SIPHASH24_HPP
#define AMBER_SIPHASH24_HPP

#include "soname.hpp"
#include <stdint.h>
#include <stddef.h>

// Siphash24 portable implementation written by Gregory Petrosyan
// <gregory.petrosyan@gmail.com> taken from
// https://github.com/flyingmutant/siphash and licensed with the MIT license.

namespace amber {    namespace AMBER_SONAME {

// Keyed hashing. This is cryptographically safe. Using other hash
// functions an attacker may arrange the inputs in such a way that all
// entries of a hash table hash into the same bucket. This would slow
// the application and provide an opportunity for a denial of service.

// Siphash24 has been designed to make such an attack impractical. To use
// this set the key to random bytes when the hash table is constructed.
EXPORTFN uint64_t siphash24 (void const* data, size_t size, uint64_t k1, uint64_t k2);

// Use random keys. The keys are computed when the program starts and may be
// different for each run.
EXPORTFN uint64_t siphash24 (void const *data, size_t size);


// Incremental interface.
class EXPORTFN Siphash24 {
	uint64_t v0, v1, v2, v3;
	uint64_t pending;
	size_t total;
	int npending;
public:
	// Use default random key. This key is generated each time that the program
	// is run.
	Siphash24 () { reset(); }
	// Use explicit key.
	Siphash24 (uint64_t k1, uint64_t k2) { reset (k1, k2); }
	// Use default random key.
	void reset();
	// Use explicit key.
	void reset (uint64_t k1, uint64_t k2);
	// Add input.
	void update (const void *p, size_t n);
	// Get the hash value.
	uint64_t final();
};


}}

#endif


