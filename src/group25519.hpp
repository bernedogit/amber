#ifndef AMBER_GROUP25519_HPP
#define AMBER_GROUP25519_HPP

/*
 * Copyright (c) 2017-2019, Pelayo Bernedo.
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

// Our scalar multiplication routines work with 256 bit scalars. X25519 and
// Ed25519 require masking to make the scalar a multiple of eight and also
// limit it to 255 bits. Scalars should ideally be between 1 and the group
// order. Given that the main group has order of l = 2²⁵² + δ where δ is a
// much smaller number it is enough to have 253 bits to hold the scalar.
// X25519 use 255 bits and require masking. Note that a scalar n is
// equivalent to n mod l, but we do not require any modulo operation. We
// require processing at least 255 bits to maintain compatibility with
// X25519/Ed25519. We have chosen to support the full 256 bits. The caller
// has the choice about how much the scalar should be masked. Processing the
// additional bit has a negligible impact on speed but allows the use of
// scalars without worrying about any masking. Therefore, for this library,
// no masking is required but any masking can be applied by the user.




// MASKING THE SCALARS

// Mask the scalar according to X25519: make it a multiple of 8
// and  set the most significant bit (mod p)
inline void mask_scalar (uint8_t scb[32])
{
	scb[0] &= 0xF8;    // Clear the lower 3 bits. Multiply by cofactor.
	scb[31] &= 0x7F;   // Clear the bit 255, not used.
	scb[31] |= 0x40;   // Set the most significant bit.
}



// TRANSCODING BETWEEN INTERNAL EDWARDS AND COMPRESSED FORMS

// The sign bit is the least significant bit of the Edwards X coordinate.  We
// use Edwards y with sign bit (eys), Montgomery x with sign bit (mxs) and
// Ristretto. All the transformations below require a field exponentiation
// and take similar time with differences around 10%.

// Store the point as Montgomery x with the sign bit in bit 255.
EXPORTFN void edwards_to_mxs (uint8_t res[32], const Edwards &p);

// Store the point as Edwards y with the sign bit in bit 255.
EXPORTFN void edwards_to_eys (uint8_t res[32], const Edwards &p);

// Store in both formats. More efficient than separate calls.
EXPORTFN void edwards_to_eys_mxs (uint8_t ey[32], uint8_t mx[32], const Edwards &p);


// Load from compressed Edwards Y plus sign bit to full Edwards extended
// coordinates. Return 0 if ok, -1 on errors. If sign_change is true then it
// will select the negative value of the point.
EXPORTFN int eys_to_edwards (Edwards &res, const uint8_t ey[32], bool sign_change);

// Load from compressed Montgomery X plus sign bit to full Edwards
// extended coordinates. Return 0 on success. If will fail if the point is
// not on the curve or mx == 0 or mx == -1. If sign_change is true then it
// will select the negative value of the point.
EXPORTFN int mxs_to_edwards (Edwards &res, const uint8_t mx[32], bool sign_change);

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
EXPORTFN void eys_to_mxs (uint8_t mx[32], const uint8_t ey[32]);

// Convert compressed Montgomery x to compressed Edwards y, with sign bits.
EXPORTFN void mxs_to_eys (uint8_t ey[32], const uint8_t mx[32]);


// Ristretto format. The following are constant time.

// Encode the point p in the ristretto representation. Constant time.
EXPORTFN void edwards_to_ristretto (uint8_t s[32], const Edwards p);
// Decode the ristretto representation. Return 0 if success. Constant time.
EXPORTFN int ristretto_to_edwards (Edwards &res, const uint8_t sc[32]);

// Decode from ristretto to Edwards and Montgomery representations using a
// single exponentiation. Return 0 on success. Constant time. This can be
// used as direct input to the Montgomery ladder if the full point result
// (including x or v) are required.
EXPORTFN int ristretto_to_mont (Edwards &ed, Fe &u, Fe &v, const uint8_t sc[32]);


// Output the result of edwards_to_eys.
EXPORTFN std::ostream & operator<< (std::ostream &os, const Edwards &rhs);



// OPERATIONS IN EDWARDS COORDINATES

// For scalar multiplication of the base in constant time use scalarbase().
// For single and double scalar multiplication in variable time use
// scalarmult_wnaf(). For single scalar multiplication in constant time use
// montgomery_ladder().

// Compute sB using precomputed multiples of B (the base point). Constant
// time. Works with scalars of 256 bits. Very fast.
EXPORTFN void scalarbase (Edwards &res, const uint8_t scalar[32]);

// General scalar multiplication with variable base. Constant time. Works
// with scalars of 256 bits. Simple, but slow.
EXPORTFN void scalarmult (Edwards &res, const Edwards &p, const uint8_t s[32]);

// General scalar multiplication with variable base using a fixed window.
// Constant time. Faster. Works with scalars of 256 bits.
EXPORTFN void scalarmult_fw (Edwards &res, const Edwards &p, const uint8_t s[32]);

// The base point in Edwards coordinates.
EXPORTFN extern const Edwards edwards_base_point;

// Variable time res = s*P. Works with scalars of 256 bits.
EXPORTFN void scalarmult_wnaf (Edwards &res, const Edwards &p, const uint8_t s[32]);

// Variable time res = s1*B + s2*P, where B is the base point. Works with
// scalars of 256 bits.
EXPORTFN void scalarmult_wnaf (Edwards &res, const uint8_t s1[32],
                               const Edwards &p, const uint8_t s2[32]);

// Point arithmetic.
EXPORTFN void add (Edwards &res, const Edwards &a, const Edwards &b);
EXPORTFN void sub (Edwards &res, const Edwards &a, const Edwards &b);
EXPORTFN void negate (Edwards &res, const Edwards &p);
EXPORTFN void pdouble (Edwards &res, const Edwards &x);

// Write the table of multiples required by scalarbase.
EXPORTFN void write_base_multiples (const char *name);

// Write the table of multiples required by the wNAF multiplication of the
// base.
EXPORTFN void write_summands (const char *name);





// MODULUS GROUP ORDER.

// Reduce mod L, where L=order of curve.
EXPORTFN void reduce (uint8_t *dst, const uint8_t src[64]);
EXPORTFN void reduce32 (uint8_t *dst, const uint8_t src[32]);
typedef int32_t Limbtype;
EXPORTFN void modL (uint8_t r[32], Limbtype x[64]);




// RISTRETTO OPS IN EDWARDS

// Do the Edwards points p1 and p2 represent the same ristretto point?
EXPORTFN bool ristretto_equal (const Edwards &p1, const Edwards &p2);

// As defined in RFC. Generate a point from random bits.
EXPORTFN void ristretto_from_uniform (Edwards &p, const uint8_t b[64]);




// SIGNATURE SCHEMES


// Signatures using qDSA and X25519 keys.

// Generate a qDSA signature. The A is the public X25519 key.
EXPORTFN void curvesig (const char *prefix, const uint8_t *m, size_t mlen,
                        const uint8_t A[32], const uint8_t scalar[32],
                        uint8_t sig[64]);

// Verify signature using qDSA. What is checked is R == ±SB ± hA. The public
// key is the X25519 key.
EXPORTFN int curverify (const char *prefix, const uint8_t *m, size_t mlen,
                        const uint8_t sig[64], const uint8_t mx[32]);

// Verify signature using qDSA. What is checked is R == ±SB ± hA. This uses
// Montgomery arithmetic only and the public key is the X25519 key.
EXPORTFN int curverify_mont (const char *prefix, const uint8_t *m, size_t mlen,
                             const uint8_t sig[64], const uint8_t mx[32]);





// Ed25519-SHA512 using the Edwards Y format and the SHA-512 hash function.
// (S)ha512 with (e)dwards (y).

// Compute the scalar corresponding to a seed. The scalar is the
// corresponding private scalar in X25519. The seed is what Ed25519 calls the
// private key.
EXPORTFN void ed25519_seed_to_scalar (uint8_t scalar[32], const uint8_t seed[32]);

// Sign using the SHA-512 hash function. A is the public key used to compute
// H(R,A,M). It is otherwise not used for signing. It should be the Ed25519
// public key in the context of Ed25519.
EXPORTFN void sign_sha (const uint8_t *m, size_t mlen, const uint8_t A[32],
                        const uint8_t scalar[32], uint8_t sig[64]);

// Sign the message m[0..mlen[ and store the signature in sig. ey is the
// public key in Edwards Y format and seed is the Ed25519 private key. This
// is similar to sign_sha(), but hashes the seed to obtain the private scalar
// and the hash prefix used to obtain r. Fully compatible with existing
// Ed25519 implementations.
EXPORTFN void sign_sey (const uint8_t *m, size_t mlen, const uint8_t ey[32],
                        const uint8_t seed[32], uint8_t sig[64]);

// Verify the message m[0..mlen[ with the signature sig[0..63] using the
// public key stored in pub. Return 0 if the signature is valid.
EXPORTFN int verify_sey (const uint8_t *m, size_t mlen, const uint8_t sig[64],
                         const uint8_t pub[32]);

// Given the seed compute the corresponding Ed25519 public key.
EXPORTFN void ed25519_seed_to_ey (uint8_t ey[32], const uint8_t seed[32]);




// Ed25519-Blake2b signatures using the Montgomery X with sign format and the
// Blake2b hash function. (b)lake with (m)ontgomery (x)

// Sign the given message, m[0..mlen[ with the secret scalar. Mx is the
// public Montgomery X. This function uses Blake2b as hash. The prefix
// (including the terminating null) is prepended to the message.
EXPORTFN void sign_bmx (const char *prefix, const uint8_t *m, size_t mlen,
                        const uint8_t mx[32], const uint8_t scalar[32],
                        uint8_t sig[64]);

// Check the signature sig[0..63] for the message m[0..mlen[ using mx as A
// for the hashing in H(RAM) and decompressing mx to the public point of
// the signer. Return 0 if the signature is valid. Uses Blake2b as hash. The
// prefix is prepended to the message. This also works with keys without a
// sign bit.
EXPORTFN int verify_bmx (const char *prefix, const uint8_t *m, size_t mlen,
                         const uint8_t sig[64], const uint8_t mx[32]);





// Support for XEd25519.

// negx = -x mod L (L == order or the group). If you have a scalar that
// produces a public key with the sign bit set, you can use negx. It will
// produce the same public key but with the opposite sign bit value.
EXPORTFN void negate_scalar (uint8_t negx[32], const uint8_t x[32]);




//////////////////////////////////////////////

// Type safe interfaces. They prevent errors like passing public keys instead
// of secret keys.

struct Cu25519Sec { uint8_t b[32]; };   // The secret scalar.
struct Cu25519Mon { uint8_t b[32]; };   // Point in Montgomery X format.
struct Cu25519Ell { uint8_t b[32]; };   // Elligator representative.
struct Cu25519Ris { uint8_t b[32]; };   // The Ristretto point

struct Cu25519Pair {
	Cu25519Sec xs;
	Cu25519Ris xp;
};


// ELLIGATOR2. Create a representative that is undistinguishable from random.
// Pass  as input the scalar, filled with random bytes. The function will
// adjust  the scalar and will compute mon and the corresponding
// representative ell.
EXPORTFN void cu25519_elligator2_gen (Cu25519Sec *scalar, Cu25519Mon *mon, Cu25519Ell *ell);

// Take an Elligator2 representative and convert it into a Montgomery u. The
// resulting Montgomery u can be used only for the computation of shared
// secrets.
EXPORTFN void cu25519_elligator2_rev (Cu25519Mon *u, const Cu25519Ell & rep);


// KEY GENERATION

// Fill scalar with random bytes and call this function. It will adjust scalar
// and generate the corresponding public Montgomery u. The scalar will be
// masked according to X25519.
EXPORTFN void cu25519_generate (Cu25519Sec *scalar, Cu25519Mon *mon);

// Fill the scalar with random bytes before calling. It will mask the scalar
// according to the X25519 conventions and store in ris the Ristretto
// point.
EXPORTFN void cu25519_generate (Cu25519Sec *scalar, Cu25519Ris *ris);

// Shorthand for cu25519_generate (&pair->xs, &pair->xp);
EXPORTFN void cu25519_generate (Cu25519Pair *pair);


// Fill scalar with random bytes before calling. Scalar can use all 256 bits
// and no masking will be performed.
EXPORTFN void cu25519_generate_no_mask (const Cu25519Sec &scalar, Cu25519Ris *ris);




// DH. Compute the shared secret. Needs hashing before use. Use mix_key() for
// that.

// From scalar and Montgomery. Return 0 on success. Reject points of small
// order and on the twist.
inline int cu25519_shared_secret_checked (uint8_t sh[32], const Cu25519Mon &mon,
                                          const Cu25519Sec &scalar)
{
	return montgomery_ladder_checked (sh, mon.b, scalar.b, 255);
}
// No checks. Just like in the original Curve25519.
inline void cu25519_shared_secret_unchecked (uint8_t sh[32], const Cu25519Mon &mon,
                                             const Cu25519Sec &scalar)
{
	montgomery_ladder_unchecked (sh, mon.b, scalar.b, 255);
}
// Checks and throws on error.
EXPORTFN void cu25519_shared_secret (uint8_t sh[32], const Cu25519Mon &mon,
                                     const Cu25519Sec &scalar);


// DH using a montgomery ladder and Ristretto. Works only if the scalar is a
// multiple  of 8. It reuses the montgomery ladder of X25519 and is as fast.
// The scalar has 255 bits. Return 0 if successful. It returns non zero if
// the  resulting point is not on the curve or it is zero.
EXPORTFN int
cu25519_shared_secret_checked (uint8_t res[32], const Cu25519Ris &A,
                               const Cu25519Sec &scalar);
// No checks.
EXPORTFN void
cu25519_shared_secret_unchecked (uint8_t res[32], const Cu25519Ris &A,
                                 const Cu25519Sec &scalar);

// Checks and throws on error.
EXPORTFN void cu25519_shared_secret (uint8_t res[32], const Cu25519Ris &A,
                                     const Cu25519Sec &scalar);


// DH using a montgomery ladder and Ristretto. If multiplies the scalar by 8
// before computing the product. It works for scalars that are not a multiple
// of 8. Almost as fast as above. The scalar has 256 bits. Return 0 if
// successful. Return non zero if point was not on the curve or was small
// order.
EXPORTFN int
cu25519_shared_secret_cof_checked (uint8_t res[32], const Cu25519Ris &A,
                                   const Cu25519Sec &scalar);
// No checks. Everything accepted.
EXPORTFN void
cu25519_shared_secret_cof_unchecked (uint8_t res[32], const Cu25519Ris &A,
                                     const Cu25519Sec &scalar);
// Checks and throws on error.
EXPORTFN void cu25519_shared_secret_cof (uint8_t res[32], const Cu25519Ris &A,
                                         const Cu25519Sec &scalar);


// SIGNATURES

// Ed25519 signatures using the Ristretto representation. Sign the message
// m[0..mlen[ with the key A, sec and store the signature in sig. The prefix
// is used to differentiate different contexts for the signature. If prefix
// ==  NULL then no prefix is used and it is the pure Ed25519 variant. The
// prefix  turns the hash function H(X) into (H(prefix0||X), where prefix0 is
// prefix  including the terminating null (this ensures that the prefix is
// unique).

EXPORTFN void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
                            const Cu25519Ris &A, const Cu25519Sec &sec,
                            uint8_t sig[64]);
// Return 0 if ok.
EXPORTFN int cu25519_verify (const char *prefix, const uint8_t *m,
                             size_t mlen, const uint8_t sig[64],
                             const Cu25519Ris &A);


// Verify a ristretto signature using qDSA and Montgomery, no Edwards
// arithmetic. Return 0 on success.
EXPORTFN int ristretto_qdsa_verify (const char *prefix, const uint8_t *m, size_t mlen,
                        const uint8_t sig[64], const Cu25519Ris &A);


// qDSA signatures using only X25519 keys. You can use existing keys for
// signatures without any further modifications. These signatures are not
// compatible with the Ristretto signatures.
inline void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
                          const Cu25519Mon &A, const Cu25519Sec &sec,
                          uint8_t sig[64]) {
	curvesig (prefix, m, mlen, A.b, sec.b, sig);
}
inline int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen,
                    const uint8_t sig[64], const Cu25519Mon &A) {
	return curverify (prefix, m, mlen, sig, A.b);
}



}}

#endif


