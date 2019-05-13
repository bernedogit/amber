#ifndef AMBER_SYMMETRIC_HPP
#define AMBER_SYMMETRIC_HPP

/*
 * Copyright (c) 2015-2017, Pelayo Bernedo.
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



// Primitives for symmetric encryption.


#include "soname.hpp"
#include "blake2.hpp"
#include "misc.hpp"
#include <iostream>
#include <vector>


namespace amber {    namespace AMBER_SONAME {

// Key handling. DJB divides the 128 bits into a 64-bit nonce and a 64-bit
// block number within the message. IETF divides the 128 bits into a 96-bit
// nonce and a 32-bit block number within the message.

// We apply HChaCha20 to extend the nonce. We start with a 28 byte nonce. We
// call the original key K₁. The new key to be used is K₂=HChaCha20(K₁,
// nonce[0-15]).


struct Chakey {
	uint32_t kw[8];
};

EXPORTFN void load (Chakey *kw, const uint8_t bytes[32]);


// The raw chacha stream. kn is a set of 32 bit integers that hold the state
// of ChaCha20. It generates a 64-byte block based on the state. The state
// holds a key and a 128 bit block index. kn[0..7] is the key. The index is
// stored in little endian order in kn[8-11]. According to the definition by
// DJB the 128-bit index is divided into a 64-bit block number within the
// message, stored in kn[8..9] and a 64-bit message number kn[10..11] or
// nonce. The block counter and the nonce are interpreted as little endian
// 64 bit values. The kn[0..7] is obtained by reading the key as if it were
// a little endian sequence of 32 bit integers. The IETF splits the 128-bit
// index into a 96-bit nonce and a 32-bit block number. This split allows
// packets to be as big as 2^38 bytes.
EXPORTFN void chacha20 (uint8_t out[64], const uint32_t kn[12]);
EXPORTFN void chacha20 (uint32_t out[16], const uint32_t kn[12]);

// Same with explicit division into key, nonce and block number.
EXPORTFN
void chacha20 (uint8_t out[64], const Chakey &key, uint64_t n64, uint64_t bn);

EXPORTFN
void chacha20 (uint8_t out[64], const uint32_t key[8], uint64_t nonce, uint64_t bn);

// Note: HChaCha20 and XChaCha20 are provided for completeness in line with
// the XSalsa20 paper. However it is much better to use the Noise protocol
// for the establishment of session keys. Noise just works with 64 bit nonces
// starting at zero.

// Using the key and the nonce generate a new key.
EXPORTFN
void hchacha20 (Chakey *out, const uint8_t key[32], const uint8_t n[16]);

EXPORTFN
void hchacha20 (Chakey *out, const Chakey &key, const uint8_t n[16]);

EXPORTFN
void hchacha20 (uint32_t out[8], const uint8_t key[32], const uint8_t n[16]);


class EXPORTFN Chacha {
	uint8_t buf[64];
	uint32_t state[12];
	int buf_next;

public:
	Chacha() {}
	Chacha (const Chakey &key, uint64_t nonce, uint64_t pos=0) { reset (key, nonce, pos); }
	void reset (const Chakey &key, uint64_t nonce, uint64_t pos=0);
	void reset (const uint8_t *key, uint64_t nonce, uint64_t pos=0);
	void set_nonce (uint64_t nonce);
	// XOR the input in[0..n[ and store it in out. in and out may point to
	// the same place.
	void doxor (uint8_t *out, const uint8_t *in, size_t n);
	void doxor (char *out, const char *in, size_t n) { doxor ((uint8_t*)out, (const uint8_t*)in, n); }
	void copy (uint8_t *out, size_t n);
	// Seek to a new position of the stream.
	void seek (uint64_t pos);
};

// Pass a 32-byte secret key, a 24-byte nonce and turn them into the Chakey k
// and a 64-bit nonce. It uses XChaCha20 to generate the new key and put it
// in new_key and the last 64 bits of the nonce in *nonce64.
inline
void xchacha (Chakey *new_key, uint64_t *nonce64,
              const uint8_t key[32], const uint8_t n[24])
{
	hchacha20 (new_key, key, n);
	*nonce64 = leget64 (n + 16);
}

inline
void xchacha (Chakey *new_key, uint64_t *nonce,
              const Chakey &key, const uint8_t n[24])
{
	hchacha20(new_key, key, n);
	*nonce = leget64 (n + 16);
}


// The following functions use ChaCha20 with a 64 bit nonce and a 64 bit
// block number. IETF uses a 32 bit block number and a 96 bit nonce. It
// further divides the 96 bit nonce into a 64 random nonce and a 32 bit
// sender number. If you want to use the IETF convention pass in ietf_sender
// the sender number. If you pass more than one authentication key then
// ietf_sender must be zero.

// Encrypt the plaintext m[0..mlen[ into the ciphertext at cipher. The
// authenticated data ad[0..alen[ will be authenticated too. The encryption
// key is in kw. There are nka authentication keys, stored in ka[0..nka[.
// The function will append to the ciphertext a 16 byte tag for each
// authentication key. cipher must have space for mlen + nka*16 bytes.
EXPORTFN
void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
                    const uint8_t *ad, size_t alen, const Chakey &kw,
                    const Chakey *ka, size_t nka, uint64_t nonce64,
                    uint32_t ietf_sender=0);


// Decrypt the ciphertext cipher[0..clen[ to the plaintext and store it in m.
// Authenticate the additional data ad[0..alen[. The key used to authenticate
// is in ka. It is assumed that there are nka authentication tags and we are
// checking the ika-th tag.
EXPORTFN
int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen,
                   const uint8_t *ad, size_t alen, const Chakey &kw,
                   const Chakey &ka, size_t nka, size_t ika, uint64_t nonce64,
                   uint32_t ietf_sender=0);


// Single authentication key variants. The same key is used for encryption
// and authentication, just like in secretbox().
inline
void encrypt_one (uint8_t *cipher, const uint8_t *m, size_t mlen,
                  const uint8_t *a, size_t alen,
                  const Chakey &keyn, uint64_t nonce64, uint32_t ietf_sender=0)
{
	encrypt_multi (cipher, m, mlen, a, alen, keyn, &keyn, 1, nonce64, ietf_sender);
}

inline
int decrypt_one (uint8_t *m, const uint8_t *cipher, size_t clen,
                 const uint8_t *a, size_t alen,
                 const Chakey &keyn, uint64_t nonce64, uint32_t ietf_sender=0)
{
	return decrypt_multi (m, cipher, clen, a, alen, keyn, keyn, 1, 0, nonce64, ietf_sender);
}


// Derive a key based on a password and a salt. The password is passed in
// pwd[0..plen[, the salt is passed in salt[0..slen[. The key will be stored
// in dk[0..dklen[. The parameter shifts states the amount of memory and time
// to use to derive the key. The number of kilobytes used is 2^shifts.
// Selecting a value of 14 will require 16 MiB of memory to derive the key.
// The amount of time required is proportional to the memory required. r and
// p are the same as defined in the scrypt paper. The shifts parameter is
// related to the N parameter of the scrypt paper: N = 1 << shifts. The
// actual memory used is in bytes [(1 << shifts) + p]*r*128
EXPORTFN
void scrypt_blake2b (uint8_t *dk, size_t dklen,
                     const char *pwd, size_t plen,
                     const uint8_t *salt, size_t slen,
                     int shifts, int r=8, int p=1);


// On one of my computers shifts=14 takes around 70 ms to compute. Adding 1
// to the shifts doubles the time required. You select the shifts value to be
// something under 100 ms for your computer (assuming interactive sessions).
// Assuming custom hardware that runs at 10⁹ and 10¹² tests per second the
// following table shows the average time required to brute force a random
// password made of case insensitive letters and digits (base 32):
/*                                    10⁹ t/s              10¹² t/s
	10 letters, 50 bits of entropy:      6 days             9 minutes
	11 letters, 55 bits of entropy:    208 days             5 hours
	12 letters, 60 bits of entropy:     18 years            6 days
	13 letters, 65 bits of entropy:    584 years            7 months
	14 letters, 70 bits of entropy:  18718 years           18 years
	15 letters, 75 bits of entropy: 600000 years          600 years
	16 letters, 80 bits of entropy: 19 million years    19000 years
*/
// If the NSA is able to run 10¹² tests per second (as suggested by Snowden),
// using a 12 character password still requires 6 days to crack and a 15
// character password takes 600 years. Remember that this is valid for random
// generated passwords only. It is not clear which kind of capabilities are
// available for password cracking. Scrypt tries to make it more expensive to
// crack the password by requiring not only compute time but also memory.
// However there is a trade off and it is possible to trade speed for
// memory. There are ASICs being offered to crack Scrypt, so 10¹² attempts
// per second seems to be achievable.



// PRNG according to NIST-800-90A. It generates a new block of random output
// by running the output of Chacha. It gets random bytes once at the
// constructor and then generates the random numbers without making any
// system calls. It hashes the random bytes obtained from the system, the
// current system time and the current value of the
// std::chrono::high_resolution_clock. The hash is keyed with the given
// password or key. The output of this random generator can be used to
// generate nonces and temporary keys. After each call to get_bytes() we
// reset the internal state. This prevents Mallory from recovering past
// outputs of the random number generator.

// If the bytes returned by the system's random number generator are random
// then the output of Keyed_random is also random. If system's source of
// random bytes fails to produce random bytes then the output of Keyed_random
// can still be used as a nonce because it is keyed with the system clock
// and the high resolution clock. As long as you do not adjust your clock
// backwards it is likely that the nonces will not repeat. If the password
// or key that you pass is secret and unpredictable then the stream generated
// by Keyed_random key will be unpredictable without knowing the password,
// even if the system's random number generator fails.

// Note that this class is not thread safe and not fork safe. If you share an
// instance of Keyed_random among different threads you must provide your own
// locking. Also if a process forks then the child process will inherit the
// state of the parent and both will produce the same sequence of random
// bytes.

// This class generates chunks of 64 bytes of random sequence. If a call does
// not completely consume the last block then it will be kept for the next
// call. No attempt is done to provide for forward security by overwriting
// the internal buffer or internal state. Instead the focus is on efficiency
// even if very small amounts of output are requested at each time.

class EXPORTFN Keyed_random : public Chacha {
public:
	Keyed_random () { reset (NULL, 0); }
	Keyed_random (const char *password) { reset (password); }
	Keyed_random (const void *ikm, size_t n) { reset (ikm, n); }
	void reset (const char *password);
	void reset (const void *ikm, size_t n);
	void get_bytes (void *buf, size_t n) { copy ((uint8_t*)buf, n); }
	uint32_t get32() {
		uint32_t v;
		get_bytes (&v, sizeof v);
		return v;
	}
	uint64_t get64() {
		uint64_t v;
		get_bytes (&v, sizeof v);
		return v;
	}
};


// Retrieve n random bytes. This is thread and fork safe. You can call it
// from any thread. It internally arranges for mutual exclusion among
// threads. It also reseeds the internal state of the child after a fork has
// happened. Similar to arc4random_buf(). After each call the internal state
// is reset so that it is not possible to backtrack to previous output. This
// class is very secure but may be inefficient if very small amounts of
// output are requested on each call.
EXPORTFN
void randombytes_buf (void *p, size_t n);




// Same as encrypt_multi() but the plaintext is made of an unsigned integer
// (encoded as variable length integer) followed by the message followed by
// padding bytes.

EXPORTFN
size_t encrypt_packet (uint8_t *ct, const uint8_t *m, size_t mlen,
                       uint64_t uval, size_t padlen,
                       const Chakey &ke, uint64_t nonce,
                       const Chakey *ka, size_t nka,
                       const uint8_t *ad = nullptr, size_t alen = 0);

inline
size_t encrypt_packet (uint8_t *ct, const uint8_t *m, size_t mlen,
                       uint64_t uval, size_t padlen,
                       const Chakey &ke, uint64_t nonce,
                       const uint8_t *ad = nullptr, size_t alen = 0) {
	return encrypt_packet (ct, m, mlen, uval, padlen, ke, nonce, &ke, 1, ad, alen);
}


// Decrypt the packet removing padding.
EXPORTFN
int decrypt_packet (uint8_t *m, size_t *msglen, uint64_t *u,
                    const uint8_t *cipher, size_t clen, size_t padlen,
                    const Chakey &ke, uint64_t nonce,
                    const Chakey *ka, size_t nka, size_t ika,
                    const uint8_t *ad=nullptr, size_t alen=0);
inline
int decrypt_packet (uint8_t *m, size_t *msglen, uint64_t *u,
                    const uint8_t *cipher, size_t clen, size_t padlen,
                    const Chakey &ke, uint64_t nonce) {
	return decrypt_packet (m, msglen, u, cipher, clen, padlen, ke, nonce, &ke, 1, 0);
}

// Decrypt the unsigned integer at the beginning of the packet. This value is
// not authenticated. It should be considered as a preview only to be
// confirmed when the whole packet is decrypted and authenticated.
EXPORTFN
int peek_head (uint64_t *uval, const uint8_t ct[10], const Chakey &ke, uint64_t nonce);

}}

#endif


