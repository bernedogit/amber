Symmetric algorithms
====================

This file contains functions for encryption and decryption with secret keys,
hashing, random number generation and password-based key derivation. They all
rely on the ChaCha20 algorithm.


ChaCha
------

This library uses ChaCha20 as the encryption algorithm. We use it to encrypt
packets or messages. If we have a very long message or file to encrypt then
we just divide it into chunks and encrypt and authenticate each of them
separately. This is in contrast to the strategy of writing or reading the
whole ciphertext file and then use just one authentication tag at the end. In
such an scheme we would have to read the whole file twice or we would have to
output unauthenticated chunks of plain text. Given that we are going to use
many chunks to encrypt big files we do not need huge chunks.

The original specification of Salsa/ChaCha uses 128 bits to specify which
block of 64 bytes will be generated under the current key. The conventional
usage is to use the least significant 64 bits as the counter within the
message and the most significant 64 bits as the 64-bit nonce. The IETF
specification of ChaCha20/Poly1305 divides the 128 bits into a 32-bit counter
within the message and a 96-bit nonce.

You can specify the nonce as a 64 bit nonce and an additional 32 bit value, 
which defaults to zero.


ChaCha20 encryption and decryption
----------------------------------

There are two functions that encrypt and decrypt a message. They take a
single encryption/decryption key and several authentication keys. The need
for these functions arises from the encryption of a text for multiple
recipients using hybrid encryption. We encrypt a symmetric key for each of the
recipients using the secret key shared between the sender and each recipient.
After that we encrypt the plain text using the symmetric key and for each of
the recipients we use the key shared by the sender and each recipient as the
authentication key. In this way each recipient can check that the message was
intended for them and came from the sender because only the sender and the
recipient know their shared secret key. Note that there is no signature, only
MAC based authentication: the receiver knows who is the sender and also knows
that the message is authentic, but cannot prove it to a third party. This
combination of authentication and repudiation is what is often required.

	void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen, 
						const uint8_t *ad, size_t alen, const Chakey &kw, 
						const Chakey *ka, size_t nka, uint64_t nonce64, 
						uint_least32_t ietf_nonce=0);

Encrypt a message with multiple authentication tags. The message to be
encrypted is passed in m[0..mlen[. The encrypted message will be stored in
cipher, followed by *nka* sets of tags. You pass an array ka[0..nka[ which
contains *nka* authentication keys. For each authentication key a different
tag is produced and appended to the resulting ciphertext. Cipher must have
space for mlen + 16*nka bytes. The encryption itself uses the encryption key
in kw. The nonce64 is the nonce for this message and is used both for the
encryption and the authentication. The poly1305 key for each authentication
tag, with index i, is taken from the first 32 bytes of the ChaCha stream
generated using the key, nonce and uint64_t(-i) as block number. The use of a
different block number means that even if the authentication keys are
repeated the tags will not repeat.

	int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen, 
					   const uint8_t *ad, size_t alen, const Chakey &kw, 
					   const Chakey &ka, size_t nka, size_t ika, 
					   uint64_t nonce64, uint_least32_t ietf_nonce=0);

Decrypt a message with multiple authentication tags. The ciphertext is stored
in cipher[0..clen[. This ciphertext is assumed to contain the authentication
tags too. It will be decrypted and the decrypted plain text will be stored in
m. You pass in *ka* a single authentication key. There are *nka*
authentication tags in the encrypted message and we use our authentication
key to check the tag at position *ika* in the message. m must have space for
clen - 16*nka bytes. The decryption key, *kw*, and the nonce, *nonce64*, must
be the same as the ones used for the encryption.

The function will return 0 if the decryption and authentication succeeds. A
non zero result signals that the ciphertext failed the authentication and it
should be discarded.

Note that when decrypting only the authentication tag that corresponds to our
key is checked. Therefore if the tags match we know that the message contents
were not altered and that our authentication tag was not altered either. It
may happen that the authentication tag of another recipient was altered and
his decryption will fail. This could enable an active attacker to modify the
message so that some recipients are able to receive it but others not.



Single key ChaCha20 encryption
------------------------------

	void encrypt_one(uint8_t *cipher, const uint8_t *m, size_t mlen,
	                 const uint8_t *a, size_t alen,
	                 const Chakey &keyn, uint64_t nonce64)

	int decrypt_one(uint8_t *m, const uint8_t *cipher, size_t clen,
	                const uint8_t *a, size_t alen,
	                const Chakey &keyn, uint64_t nonce64)

These functions are the same as the `_multi` versions but use a single key for
both encryption and authentication. They are similar to the `secretbox()`
function of NaCl.




Password based key derivation
-----------------------------


	void scrypt_blake2s(uint8_t *dk, size_t dklen,
	                    const char *pwd, size_t plen,
	                    const uint8_t *salt, size_t slen,
	                    int shifts);

This function derives a key based on a password and a salt. The password is
passed in pwd[0..plen[, the salt is passed in salt[0..slen[. The computed
password will be stored in dk[0..dklen[. The parameter shifts states the
amount of memory and time to use to derive the key. The number of kilobytes
used is 2^shifts. Selecting a value of 14 will require 16 MiB of memory to
derive the key. The amount of time required is proportional to the memory
required.





Random numbers
--------------

We ultimately need a source of random numbers for some of the tasks. The
obvious one is the creation of keys. Whenever a key is created you need to
make sure that the secret key cannot be guessed. This can be achieved by using
random bytes as the secret key. The need to create a key arises not only when
you explicitely need a long term key, but also when you create ephemeral
keys. Ephemeral keys are needed for instance when encrypting a message using
hybrid encryption. We first create an ephemeral key and encrypt the message
using ChaCha20 with the ephemeral key. Then we just encrypt the ephemeral key
using public key cryptography for each of the recipients.


	class Keyed_random {
	public:
		Keyed_random() { reset((uint8_t*)0, 0); }
		Keyed_random(const char *pwd, size_t len) { reset(pwd, len); }
		Keyed_random(const uint8_t *key, size_t len) { reset(key, len); }
		void reset(const char *pwd, size_t len) { reset((const uint8_t*)pwd, len); }
		void reset(const uint8_t *key, size_t len);
		void get_bytes(uint8_t *buf, size_t n);
		void get_bytes(char *buf, size_t n) { get_bytes((unsigned char*)buf, n); }
	};

This is a pseudorandom number generator, according to NIST-800-90A. It
generates a new request by running the output of ChaCha. It gets random bytes
once at the constructor and then generates the random numbers without making
any system calls. It hashes the random bytes obtained from the system, the
current system time and the current value of the
std::chrono::high_resolution_clock. The hash is keyed with the given password
or key. The output of this random generator can be used to generate nonces
and temporary keys.

If the bytes returned by the system's random number generator are random then
the output of Keyed_random is also random. If system's source of random bytes
fails to produce random bytes then the output of Keyed_random can still be
used as a nonce because it is keyed with the system clock and the high
resolution clock. As long as you do not adjust your clock backwards it is
likely that the nonces will not repeat. If the password or key that you pass
is unpredictable then the stream generated by Keyed_random will be
unpredictable, even if the system's random bytes generator fails. This
implementation uses the C++11's std::random_device as a source or random
numbers.



	void randombytes_buf(void *p, size_t n);

This is the general interface to obtain random bytes. Pass the buffer and the
requested size and it will be filled with random bytes.

