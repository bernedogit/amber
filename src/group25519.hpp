#ifndef AMBER_GROUP25519_HPP
#define AMBER_GROUP25519_HPP

/*
 * Copyright (c) 2017, Pelayo Bernedo.
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


#include "field25519.hpp"
#include "symmetric.hpp"
#include <string.h>


namespace amber {  inline namespace AMBER_SONAME {

// Mask the scalar according to X25519: make it a multiple of 8 and set the
// most significant bit (mod p)
inline void mask_scalar (uint8_t scb[32])
{
	scb[0] &= 0xF8;    // Clear the lower 3 bits. Multiply by cofactor.
	scb[31] &= 0x7F;   // Clear the bit 255, not used.
	scb[31] |= 0x40;   // Set the most significant bit.
}



// The sign bit is the least significant bit of the Edwards X coordinate.

// Store the point as Montgomery x with the sign bit in bit 255.
EXPORTFN
void edwards_to_mx (uint8_t res[32], const Edwards &p);

// Store the point as Edwards y with the sign bit in bit 255.
EXPORTFN
void edwards_to_ey (uint8_t res[32], const Edwards &p);

// Store in both formats. More efficient than separate calls.
EXPORTFN
void edwards_to_ey_mx (uint8_t ey[32], uint8_t mx[32], const Edwards &p);


// Load from compressed Edwards Y plus sign bit to full Edwards extended
// coordinates. Return 0 if ok, -1 on errors. If neg is true then it will
// select the negative value of the point.
EXPORTFN
int ey_to_edwards (Edwards &res, const uint8_t ey[32], bool neg=true);

// Load from compressed Montgomery X plus sign bit to full Edwards
// extended coordinates. Return 0 on success. If will fail if the point is
// not on the curve or mx == 0 or mx == -1. If neg is true then it will
// select the negative value of the point.
EXPORTFN
int mx_to_edwards (Edwards &res, const uint8_t mx[32], bool neg=true);

// In both cases above the sign bit is the least significant bit of
// the Edwards X coordinate of the point. It is stored in the most
// significant bit of the compressed coordinate. The expansion from Edwards Y
// is the one specified in Ed25519 to verify signatures using compressed
// Edwards coordinates. The expansion from Montgomery X is required to
// verify signatures using compressed Montgomery coordinates. Both functions
// take the same amount of time, which is dominated by the single
// exponentiation. See
// https://moderncrypto.org/mail-archive/curves/2015/000376.html



// Convert compressed Edwards y to compressed Montgomery x, with sign bits.
EXPORTFN
void ey_to_mx (uint8_t mx[32], const uint8_t ey[32]);

// Convert compressed Montgomery x to compressed Edwards y, with sign bits.
EXPORTFN
void mx_to_ey (uint8_t ey[32], const uint8_t mx[32]);

// Output the result of edwards_to_ey.
EXPORTFN
std::ostream & operator<< (std::ostream &os, const Edwards &rhs);


// Compute sB using precomputed multiples of B (the base point). Constant
// time.
EXPORTFN
void scalarbase (Edwards &res, const uint8_t scalar[32]);

// General scalar multiplication with variable base. Constant time.
EXPORTFN
void scalarmult (Edwards &res, const Edwards &p, const uint8_t s[32]);

// General scalar multiplication with variable base using a fixed window.
// Constant time. Faster.
EXPORTFN
void scalarmult_fw (Edwards &res, const Edwards &p, const uint8_t s[32]);


// The base point in Edwards coordinates.
extern const Edwards edwards_base_point;



// Ed25519-Blake2b signatures using the Montgomery X with sign format and the
// Blake2b hash function. (b)lake with (m)ontgomery (x)

// Sign the given message, m[0..mlen[ with the secret scalar. Mx is the
// public Montgomery X. This function uses Blake2b as hash. The prefix
// (including the terminating null) is prepended to the message.
EXPORTFN
void sign_bmx (const char *prefix, const uint8_t *m, size_t mlen,
               const uint8_t mx[32], const uint8_t scalar[32], uint8_t sig[64]);

// Check the signature sig[0..63] for the message m[0..mlen[ using mx as A
// for the hashing in H(RAM) and decompressing mx to the public point of
// the signer. Return 0 if the signature is valid. Uses Blake2b as hash. The
// prefix is prepended to the message.
EXPORTFN
int verify_bmx (const char *prefix, const uint8_t *m, size_t mlen,
                const uint8_t sig[64], const uint8_t mx[32]);


// Variable time res = s*P
EXPORTFN
void scalarmult_wnaf (Edwards &res, const Edwards &p, const uint8_t s[32]);

// Variable time res = s1*B + s2*P, where B is the base point.
EXPORTFN
void scalarmult_wnaf (Edwards &res, const uint8_t s1[32],
                      const Edwards &p, const uint8_t s2[32]);

// Point arithmetic.
EXPORTFN void add (Edwards &res, const Edwards &a, const Edwards &b);
EXPORTFN void negate (Edwards &res, const Edwards &p);

// Write the table of multiples required by scalarbase.
EXPORTFN void write_base_multiples (const char *name);

// Write the table of multiples required by the wNAF multiplication of the
// base.
EXPORTFN void write_summands (const char *name);


// Reduce mod L, where L=order of curve.
EXPORTFN void reduce (uint8_t *dst, const uint8_t src[64]);
typedef int32_t Limbtype;
EXPORTFN void modL (uint8_t r[32], Limbtype x[64]);


/////////////////////////////////////////

// Ed25519-SHA512 using the Edwards Y format and the SHA-512 hash function.
// (S)ha512 with (e)dwards (y). Prefer the use of the sign_bmx/verify_bmx if
// you do not need compatibility with existing signatures. BMX signatures
// only use the Montgomery X plus sign for signing and verifying. There is no
// need to keep Ed25519 keys around if you use the bmx variants.

// Compute the scalar corresponding to a seed. The scalar is the
// corresponding private scalar in X25519. The seed is what Ed25519 calls the
// private key.
EXPORTFN void ed25519_seed_to_scalar (uint8_t scalar[32], const uint8_t seed[32]);

// Same as sign_bmx but using the SHA-512 hash function. A is the public key
// used to compute H(R,A,M). It is otherwise not used for signing. It should
// be the Ed25519 public key in the context of Ed25519.
EXPORTFN void sign_sha (const uint8_t *m, size_t mlen, const uint8_t A[32],
                        const uint8_t scalar[32], uint8_t sig[64]);

// Sign the message m[0..mlen[ and store the signature in sig. ey is the
// public key in Edwards Y format and seed is the Ed25519 private key. This
// is similar to sign_sha(), but hashes the seed to obtain the private scalar
// and the hash prefix used to obtain r.
EXPORTFN void sign_sey (const uint8_t *m, size_t mlen, const uint8_t ey[32],
                        const uint8_t seed[32], uint8_t sig[64]);

// Verify the message m[0..mlen[ with the signature sig[0..63] using the
// public key stored in pub. If edwards is true then pub will be interpreted
// as an Edwards Y key. If edwards is false pub will be interpreted as a
// Montgomery X key. Return 0 if the signature is valid.
EXPORTFN int verify_sey (const uint8_t *m, size_t mlen, const uint8_t sig[64],
                         const uint8_t pub[32], bool edwards=true);

// Given the seed compute the corresponding Ed25519 public key.
EXPORTFN void ed25519_seed_to_ey (uint8_t ey[32], const uint8_t seed[32]);


///////////////////////////////////////////
// Support for XEd25519.

// negx = -x mod L (L == order or the group). If you have a scalar that
// produces a public key with the sign bit set, you can use negx. It will
// produce the same public key but with the opposite sign bit value.
EXPORTFN void negate_scalar (uint8_t negx[32], const uint8_t x[32]);


// Pass in ey the Edwards Y with the sign bit. If the sign bit is set then
// negate the scalar before signing. It will produce a signature with
// an Edwards Y with the sign bit set to zero. This is similar to XEd25519,
// where the scalar is negated if required to ensure that all sign bits are
// zero.

EXPORTFN void sign_conv (const uint8_t *m, size_t len, const uint8_t ey[32],
                         const uint8_t sc[32], uint8_t sig[64]);




//////////////////////////////////////////////

// Type safe interfaces. They prevent errors like passing public keys instead
// of secret keys.

struct Cu25519Sec { uint8_t b[32]; };   // The scalar.
struct Cu25519Pub { uint8_t b[32]; };   // Point in Montgomery X format.
struct Cu25519Rep { uint8_t b[32]; };   // Elligator representative.

struct Cu25519Pair {
	Cu25519Sec xs;
	Cu25519Pub xp;
};

// Fill xs with random bytes and call this function. It will adjust xs and
// generate the corresponding public key.
inline void cu25519_generate (Cu25519Sec *xs, Cu25519Pub *xp)
{
	Edwards e;
	mask_scalar (xs->b);
	scalarbase (e, xs->b);
	edwards_to_mx (xp->b, e);
}

// Fill xs with random bytes and call this function. It will adjust xs and
// generate the corresponding public key.
inline void cu25519_generate (Cu25519Pair *pair)
{
	Edwards e;
	mask_scalar (pair->xs.b);
	scalarbase (e, pair->xs.b);
	edwards_to_mx (pair->xp.b, e);
}

// Compute the secret shared by xp and xs. Needs hashing before use. Use
// mix_key() for that.
inline void cu25519_shared_secret (uint8_t sh[32], const Cu25519Pub &xp,
                                   const Cu25519Sec &xs)
{
	montgomery_ladder (sh, xp.b, xs.b);
}


// Sign the message m[0..mlen[ with the key xs, xp and store the signature in
// sig. The prefix of size plen is used to differentiate different contexts
// for the signature. If prefix == NULL then no prefix is used and it is the
// pure Ed25519 variant. The prefix turns the hash function H(X) into
// (H(prefix0||X), where prefix0 is prefix including the terminating null
// (this ensures that the prefix is unique).
inline void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
                          const Cu25519Pair &pair, uint8_t sig[64])
{
	sign_bmx (prefix, m, mlen, pair.xp.b, pair.xs.b, sig);
}
inline void cu25519_sign (const uint8_t *m, size_t mlen, const Cu25519Pair &pair, uint8_t sig[64])
{
	sign_bmx (NULL, m, mlen, pair.xp.b, pair.xs.b, sig);
}

// Verify the signature of m[0..mlen[ stored in sig[0..63] against the public
// key of the signer xp. Return 0 if the signature is correct. The prefix is
// used as in the signature.
inline int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen,
                           const uint8_t sig[64], const Cu25519Pub &xp)
{
	return verify_bmx (prefix, m, mlen, sig, xp.b);
}
inline int cu25519_verify (const uint8_t *m, size_t mlen,
                           const uint8_t sig[64], const Cu25519Pub &xp)
{
	return verify_bmx (NULL, m, mlen, sig, xp.b);
}



// Pass as input xs, filled with random bytes. The function will adjust xs
// and will compute xp and the corresponding representative.
EXPORTFN void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Pub *xp, Cu25519Rep *rep);

// Take a representative and convert it into a key. This key can be used only
// for the computation of shared secrets, not for signing or verifying
// signatures. It does not have the sign bit set.
EXPORTFN void cu25519_elligator2_rev (Cu25519Pub *u, const Cu25519Rep & rep);



}}

#endif


