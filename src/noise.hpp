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

#ifndef AMBER_NOISE_HPP
#define AMBER_NOISE_HPP

// Implementation of the Noise protocol. Noise_??_22519_ChaChaPoly_BLAKE2s

#include "symmetric.hpp"
#include "group25519.hpp"
#include "hkdf.hpp"

namespace amber {   inline namespace AMBER_SONAME {

// Big endian 16 bit lengths. Decode and encode from/to bytes.
inline uint16_t be16dec (const void *b) {
	const uint8_t *u8 = (const uint8_t*)b;
	return (uint16_t(*u8) << 8) | u8[1];
}
inline void be16enc (void *b, uint16_t v) {
	uint8_t *u8 = (uint8_t*)b;
	u8[0] = v >> 8;
	u8[1] = v & 0xff;
}


// Blake2s based HKDF with interface suitable for Noise. v1 points to 32
// bytes. If v2 is not null then it points to 32 bytes. If v3 is not null
// then it points to 32 bytes.
EXPORTFN
void hkdf2s (const uint8_t ck[32], const uint8_t *ikm, size_t ilen,
             uint8_t *v1, uint8_t *v2=0, uint8_t *v3=0);


// The CipherState object defined in Noise.
class EXPORTFN Cipher {
protected:
	Chakey key;
	uint64_t n;

public:
	void initialize_key (const uint8_t k[32]) {
		load (&key, k);
		n = 0;
	}
	// Encrypt the plaintext pt[0..plen-1] together with the authenticated
	// data in ad[0..alen-1] and write the resulting ciphertext in
	// ct[0..plen+15].
	void encrypt_with_ad (const uint8_t *ad, size_t alen,
	                      const uint8_t *pt, size_t plen,
	                      uint8_t *ct /*ct[plen+16]*/) {
		encrypt_one (ct, pt, plen, ad, alen, key, n++);
	}
	// Decrypt the ciphertext ct[0..clen-1] together with the authenticated
	// data in ad[0..alen-1] and write the resulting plaintext in
	// pt[0..clen-16-1]
	int  decrypt_with_ad (const uint8_t *ad, size_t alen,
	                      const uint8_t *ct, size_t clen,
	                      uint8_t *pt /*pt[clen-16]*/) {
		return decrypt_one (pt, ct, clen, ad, alen, key, n++);
	}
	// Create a NoiseSocket traffic block. This will put the length of the
	// body as a 16 bit big endian at the start of the plaintext and will pad
	// it with padlen bytes before encrypting. Precondition: plen + padlen +
	// 16 < 0x10000 in order to keep packets less than 64 kbytes.
	void encrypt_padded (const uint8_t *ad, size_t alen,
	                     const uint8_t *pt, size_t plen,
	                     size_t padlen, std::vector<uint8_t> &out) {
		out.clear();
		out.resize (2 + plen + padlen + 16);
		encrypt_padded (ad, alen, pt, plen, padlen, &out[0]);
	}

	// Decrypt a NoiseSocket traffic block. It will decrypt the ciphertext
	// and read the first two bytes of the resulting plaintext as the length
	// of the body. It will put the body in pt.
	int decrypt_padded (const uint8_t *ad, size_t alen,
	                    const uint8_t *ct, size_t clen,
	                    std::vector<uint8_t> &pt);

	// Same as before but with your buffer.
	void encrypt_padded (const uint8_t *ad, size_t alen,
	                     const uint8_t *pt, size_t plen,
	                     size_t padlen, uint8_t *ct /*[2+plen+padlen+16]*/);

	void rekey();
	void set_nonce (uint64_t nn) { n = nn; }
	const Chakey * get_key() const { return &key; }
	uint64_t get_nonce() const { return n; }
};



// The symmetric state as defined by Noise.
class EXPORTFN Symmetric : public Cipher {
	enum { hashlen = 32 };
	uint8_t ck[hashlen];
	uint8_t h[hashlen];
	bool with_key;
public:
	Symmetric() : with_key (false) {}
	// Provide the name of the protocol. For instance
	// Noise_XX_25519_ChaChaPoly_BLAKE2s
	Symmetric (const char *proto) { initialize (proto); }
	void initialize (const char *proto);
	void mix_key (const uint8_t *ikm, size_t ilen);
	void mix_hash (const uint8_t *data, size_t dlen) { amber::mix_hash (h, data, dlen); }
	void mix_key_and_hash (const uint8_t *ikm, size_t ilen);
	bool has_key() const { return with_key; }

	// Pass the plaintext and its length. It will append to the vector.
	void encrypt_and_hash (const uint8_t *pt, size_t plen, std::vector<uint8_t> &out);

	// Pass the ciphertext and the length of the plaintext to be
	// recovered. Return the number of ciphertext bytes processed. -1 on
	// error.
	ptrdiff_t decrypt_and_hash (const uint8_t *ct, size_t plen, uint8_t *pt);

	// Same but with a vector as destination. If will append to the vector.
	int decrypt_and_hash (const uint8_t *ct, size_t plen, std::vector<uint8_t> &out);

	// Split to two or one (one way case) cipher states or keys.
	void split (Cipher *cs1, Cipher *cs2=0);
	void split (Chakey *k1, Chakey *k2=0);

	// Get the hash value. You can use it as a unique id of the connection.
	const uint8_t * get_handshake_hash() const { return h; }
};


// Initialize the handshake and then write and read messages until the
// handshake is finished. You must fulfil the requirements of the handshake.
// If the handshake requires that you have a static key then you must call
// set_s(). If the other party already knows your static key then pass true
// to set_s(). If you know the static key of the remote party then call
// set_known_rs(). You must call these functions if the handshake requires
// them. When finished() is true call split to get the transport cipher
// states. Failure to satisfy the requirements of the handshake will throw an
// exception.
class EXPORTFN Handshake : public Symmetric {
	Cu25519Sec e_sec, s_sec;
	Cu25519Ris s_pub, rs_pub;
	Cu25519Mon e_pub, re_pub;
	uint8_t pskv[32];
	bool s_set, re_set, rs_set;
	bool s_known, psk_set;
	enum { e_not_set, e_sec_set, e_all_set } e_state;
	unsigned patidx;
	bool initiator, elligated;
	Cipher tx, rx;
	bool fallback;
	void setup (bool initiator);
public:
	enum Pattern { e, s, ee, es, se, ss, payload, finish, psk };
private:
		std::vector<Pattern> pat;
public:
	// Type of handshake. XF is the XX fallback.
	enum Predef { N, K, X,
	              NN, NK, NX,
	              KN, KK, KX,
	              XN, XK, XX,
	              IN, IK, IX,
	              XF };

	Handshake() {}
	Handshake (Predef pat, const uint8_t *prologue, size_t plen,
	           bool elligated) {
		initialize (pat, prologue, plen, elligated);
	}
	// You pass the two letter code with the sequence of pattern symbols and
	// a prologue. If elligated is true then ephemeral keys are passed as
	// elligator2 representatives. If fallback is true then the roles of the
	// initiator and responder are reversed. In case of fallback you are
	// responsible for adding the corresponding premessage keys.
	void initialize (const char *protolet, const Pattern *pattern,
	                 size_t npat, const uint8_t *prologue, size_t plen,
	                 bool elligated=false, bool fallback=false);

	// Same as above but selecting from the set of predefined patterns.
	// Select the handshake that you want. Set elligated if you want to make
	// the messages indistinguishable from random.
	void initialize (Predef pat, const uint8_t *prologue, size_t plen,
	                 bool elligated=false, bool fallback=false);

	// Return the name of the handshake type.
	static const char * name (Predef pd);

	// Set our own static key. Some handshakes require this. If our own
	// static key is known to the other party then set known to true.
	void set_s (const Cu25519Pair &pair, bool known);

	// If you know the static key of the correspondent use this.
	void set_known_rs (const Cu25519Ris &xp);

	// Set the remote ephemeral key. Required for fallbacks.
	void set_known_re (const Cu25519Mon &xp);

	// Used for testing. Set the secret part of our ephemeral key. Normally
	// this will be generated using a random string.
	void set_e_sec (const uint8_t xs[32]);

	// Add a preshared secret if it is used by the protocol.
	void set_psk (const uint8_t psk[32]);

	// Send a handshake message with the given payload.
	void write_message (const uint8_t *payload, size_t n, std::vector<uint8_t> &out);

	// Read a message and decrypt its payload. Return 0 on success.
	int read_message (const uint8_t *msg, size_t n, std::vector<uint8_t> &pay);

	// Are we finished with the handshake. This may happen after the first
	// messsage, at most at the third message.
	bool finished() const { return pat[patidx] == finish; }

	const Cu25519Ris * get_rs() const { return rs_set ? &rs_pub : NULL; }
	const Cu25519Mon * get_re() const { return re_set ? &re_pub : NULL; }

	// Create the cipher states for sending and receiving.
	void split (Cipher *tx, Cipher *rx);

	// One way splitting. Only for one way patterns.
	void split (Cipher *tx) { Symmetric::split (tx); }
	void split (Chakey *tx) { Symmetric::split (tx); }
};

}}
#endif


