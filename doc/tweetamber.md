Tweet Amber
===========

Similar to Tweet NaCl, Tweet Amber is an exercise in producing a more compact 
version of the full amber suite. It includes just the functions needed for 
secret and public key encryption together with signatures. The algorithms and 
implementations are the same as Amber except for the scalar base 
multiplication. Amber uses precomputed multiples of the base. Tweet Amber 
uses the Montgomery ladder for this purpose. This provides for a more compact 
source code at the cost of longer times for key generation and signing. The 
time required for key generation and signing is a bit more than twice the 
time required by the corresponding Amber functions. All other times are 
identical in both implementations.

The following functions are provided.

	int  blake2b_init(blake2b_ctx *ctx, size_t outlen,
	                  const void *key, size_t keylen);

Initialize a Blake2b context with an optional key. If keylen == 0 then no key
will be used. *outlen* is the size of the resulting hash. *outlen* <= 64.

	void blake2b_update (blake2b_ctx *ctx, const void *in, size_t inlen);

Add *inlen* bytes stored *in* in to the hash.

	void blake2b_final (blake2b_ctx *ctx, void *out);

Write the resulting hash to *out*.

	int  blake2b (void *out, size_t outlen, const void *key, size_t keylen,
	              const void *in, size_t inlen);

Single function doing init, update and final.

	void poly1305_init (poly1305_context *ctx, const unsigned char key[32]);

Initialize the Poly1305 context with a one time key.

	void poly1305_update (poly1305_context *ctx, const unsigned char *m, size_t bytes);

Add bytes to the poly input.

	void poly1305_finish (poly1305_context *ctx, unsigned char mac[16]);

Retrieve the authentication tag.


	int crypto_equal (const unsigned char *mac1, const unsigned char *mac2, size_t n);

Constant time comparison. It returns 1 if equal or 0 if they are not equal.
No other values are returned.

	int crypto_neq (const void *v1, const void *v2, size_t n);

Constant time comparison. It returns 0 if equal or 1 if they are not equal.
No other values are returned.

	void chacha20 (uint8_t out[64], const uint32_t kn[12]);

The raw ChaCha20 stream function. *kn* contains the state of the stream
generator. Each invocation of ChaCha20 produces 64 bytes which are stored in
*out*. The conventional partition of *kn* is that words 0-7 contain the key,
words 8 and 9 contain the little endian chunk counter and words 10 and 11
contain the nonce.

	struct Chakey {   uint32_t kw[8];   };

The ChaCha20 key already converted into 32 bit words.

	void load (Chakey *kw, const uint8_t bytes[32]);

Load the bytes and store them as 32 bit words.

	void chacha20 (uint8_t out[64], const Chakey &key, uint64_t n64, uint64_t bn);

Same as the other *chacha20()* function. The arguments are given as an
explicit key, the 64 bit nonce *n64* and the block counter *bn* that indexes
the 64 byte block within the generated stream.

	void hchacha20 (Chakey *out, const uint8_t key[32], const uint8_t n[16]);

Hash the given key and nonce and produce a new key.

	void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
	        const uint8_t *ad, size_t alen, const Chakey *ka, size_t nka,
	        const Chakey &kw, uint64_t nonce64);

Encrypt a message, m[0..mlen-1] and authenticate it including additional
authenticated data, ad[0..alen-1]. Store the resulting ciphertext in
*cipher*. *cipher* must have space for *mlen + nka\*16* bytes. The nonce to be
used in *nonce64*. The encryption key is *kw*. There are *nka* authentication
keys, passed in *ka[0..nka-1]*. The function will produce ciphertext
consisting of the encrypted message followed by *nka* authentication tags of
16 bytes each, one per authentication key. If you want to emulate the single
key `box()` function of NaCl just pass *ka = kw* and *nka=1*.

	int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen,
	        const uint8_t *ad, size_t alen, const Chakey &ka,
	        size_t nka, size_t ika, const Chakey &kw, uint64_t nonce64);

Decrypt a message. The ciphertext is passed in *cipher* and has *clen* bytes.
The resuling plaintext will be stored in *m* and will contain *clen -
nka\*16* bytes. You also pass data that is to be authenticated together with
the ciphertext in *ad*, containing *alen* bytes. The nonce to be used is
*nonce64*. The decryption key to be used is *kw*. The authentication key to
be used is *ka*. There are *nka* tags in the ciphertext and ours is at
position *ika*. The function will return 0 if the message could be decrypted
and authenticated with the given key. It returns non zero if the
authentication fails. If you want to emulate the single key `box_open`
function just pass *ka = kw* and *nka=ika=1*.

	void scrypt_blake2b (uint8_t *dk, size_t dklen,
	                 const char *pwd, size_t plen,
	                 const uint8_t *salt, size_t slen,
	                 int shifts, int r=8, int p=1);

Compute a key based on a password and salt. The password is passed in *pwd*
and has *plen* bytes. The salt is passed in *salt* and has *slen* bytes. The
generated key is stored in *dk*. You pass the required length of the key in
*dklen*. *shifts*, *r* and *p* are the parameters of the Scrypt algorithm.
The Scrypt paper uses *N* instead of *shifts*: *N=2^shifts*. N is the amount
of kilobytes of memory used by the algorithm. The running time is
proportional to this value. A good value would be *shifts=15*, which requires
32 MBytes of memory.

	void randombytes_buf (void *buf, size_t n);

Store *n* random bytes in *buf*.


	struct Cu25519Sec { uint8_t b[32]; };
	struct Cu25519Pub { uint8_t b[32]; };
	struct Cu25519Rep { uint8_t b[32]; };

These are types that represent the private key, the public key and the
Elligator2 representative. They are all 32 bytes, but the different structs
provide type safety and will catch any errors where the wrong key is passed
to the functions.

	void mask_scalar (uint8_t scb[32]);

This will mask the scalar in *scb* according to the requirements of X25519.
It will set the most significant bit and make the scalar a multiple of the
cofactor.

	void cu25519_generate (Cu25519Sec *xs, Cu25519Pub *xp);

Fill *xs.b* with random bytes and call this function. It will properly mask *xs* and
will compute the corresponding public key and store it in *xp*.

	void cu25519_shared_key (Chakey *k, const Cu25519Pub &xp, const Cu25519Sec &xs);

Compute the secret shared by the keys *xp* and *xs* and hash it. Store the result in *k*.

	void cu25519_shared_key (uint8_t sh[32], const Cu25519Pub &xp, const Cu25519Sec &xs);

Same as above but store it as bytes in *sh*.

	void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
	                   const Cu25519Pub &xp, const Cu25519Sec &xs, uint8_t sig[64]);

Sign the message stored in *m* of length *mlen* with the key pair *xp* and 
*xs* and store the signature in *sig*. The prefix is used to differentiate 
different signing contexts. It is just a null terminated string. Pass prefix 
== NULL if you do not want any context.

	int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen,
	                    const uint8_t sig[64], const Cu25519Pub &xp);

Verify that the signature stored in *sig* corresponds to the message stored
in *m* of length *mlen* and was produced with the private key corresponding
to *xp*. It returns 0 if the signature is correct. The prefix is the same as the one
passed to the signing function.

	void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Pub *xp, Cu25519Rep *rep);

Compute a public key and its elligator representative. Fill *xs* with random
bytes and call this function. It will adjust *xs* and will store in *xp* the
corresponding public key and in *rep* the corresponding representative. Note
that this key can be used only for DH and not for signing.

	void cu25519_elligator2_rev (Cu25519Pub *u, const Cu25519Rep & rep);

Compute the public key corresponding to the Elligator 2 representative *rep*.
Store the result in *u*.



