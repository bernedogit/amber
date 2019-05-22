Libamber
========

This file deals with the use of the *libamber* library. You may package it as
a separate library or you may include the files within your source tree.

If you need public key based encryption then you need to be familiar with the 
concept of public and private keys. Refer to the file **amber.md** for 
explanations of these concepts. The file *amber.md* refers to public keys as 
*padlocks* and private keys as *keys*. This is intended to make it easier for 
non experts to understand the concepts using an analogy with physical 
security.

There are several entry points to this library. If you just want a very
simple API to encrypt and decrypt files then use the high level API defined
in *combined.hpp*. There is very little that can go wrong using this level.

At the medium level we have the *amber::ofstream* and *amber::ifstream*
encrypting and decrypting classes. They look and operate like the std
counterparts but perform encryption and decryption under the hood. The higher
level API is just a wrapper around these classes. The archiving functionality
built into the library just uses these classes and knows nothing about
encryption.

The lowest level provides functions that perform shared secret computation, 
packet encryption, authentication, password hashing, etc. They allow you to 
create your own protocol or file format taylored to your needs. You must 
however know how to combine them to maintain the required level of security 
and not introduce errors.

If instead of encrypting files you want to exchange messages in a duplex
connection then use the Noise protocol as implemented in
`noise.hpp/noise.cpp` to perform a handshake and establish the cipher states
for sending and receiving.

Finally, independent of which level you want to use there is the task of
creating and managing keys. The library offers a file based keyring
functionality.


High level usage
================

The file *combined.hpp* declares an API that allows you to encrypt, decrypt,
sign and verify files using a single function.

To encrypt the file `pt` to the file `ct` using the password in `pass` then
use *sym_encrypt(pt, ct, pass)*. You can then decrypt this file by using
*sym_decrypt(ct, pt, pass)*. The functions throw exceptions if there are
errors.

To encrypt the file `pt` to the file `ct` by the sender to a list of
receivers use *pub_encrypt(pt, ct, sender, rxvec)*. *sender* is the bundle of
private and public key which is defined in the file *keys.hpp*. *rxvec* is a
vector of such keys containing the public keys of the recipients. You decrypt
the file `ct` to the file `pt` using the key of the receiver by calling
*pub_decrypt(ct, pt, rxkey, sender)*. You pass in *rxkey* the key bundle of
the receiver (which includes the public and private keys of the receiver).
The function stores in sender the public key of the sender.


Medium level usage
==================

Just include *<amber/blockbuf.hpp>* and use the *amber::ofstream* and
*amber::ifstream* classes. They work like the std counterparts but perform
encryption and decryption transparently. Except for opening files they have
the same API as the std classes. When using password based encryption just
use the *open(filename, password)* form or its equivalent constructor. This
works for both encrypting (ofstream) and decrypting (ifstream). There is
nothing else that you need to do to, except choosing a hard to guess password.
Decryption errors will throw exceptions, so that they will not be ignored by
default. The concept of password based encryption is intuitive and does not
need further explanations: it works as expected by non experts.

In order to encrypt a file using keys you need to have the private and public
keys of the sender and a vector with the public keys of the recipients. Then
you open the ofstream object using *open(filename, senderpair, rxpubvec)*
where *senderpair* contains the public and private keys of the sender and
*rxpubvec* is a std::vector containing the public keys of the recipients.

To decrypt a file using a private key open the file using *open(filename,
rxpair, &senderpub)*. This will try to open the file using the private key
passed in *rxpair*. If succesful it will store in *senderpub* the public key
of the sender.



Low level interface
===================

The low level interface just offers the primitives required as building
blocks for the upper layers. This is the same level of abstraction as NaCl or
libsodium: just a few functions that you are supposed to put together into a
working system.


group25519.hpp
--------------

The file *group25519.hpp* declares the functions that deal with public key
cryptography.

It provides four types that each contain 32 byte keys. They are different 
types to allow the compiler to catch errors if you pass the wrong type. Each 
of these types has a single member: `uint8_t b[32];` You can access the 
individual bytes by using something like `key.b[i]`. The private key, which 
is the secret scalar, is represented by the type Cu25519Sec. The type 
Cu25519Mon contains a Montgomery u coordinate. This is the same as what is 
used in X25519 as public key. The type Cu25519Ell contains an Elligator2 
representative. It can be converted to a Cu25519Mon value. Finally the type 
Cu25519Ris contains a Ristretto encoding of a point.

To generate a long term key you use `cu25519_generate (Cu25519Sec *xs,
Cu25519Ris *xp)`. The first argument is the input secret key and the second
argument is the output public key. You must fill `xs.b` with 32 random bytes
before calling this function. The function will then adjust the value of `xs`
and will compute the corresponding public key `xp`.

To generate an ephemeral key that will be used with Elligator2 use the
function `cu225191_elligator2_gen (Cu25519Sec *xs, Cu25519Mon *xp, Cu25519Ell
*xr)`. The first argument is the input secret key. You should fill it with 32
random bytes before calling this function. The function will adjust this key.
The second argument is the public Montgomery key corresponding to this secret
key. The third argument is the Elligator2 representative corresponding to
this secret key. The function adjusts `xs` and computes both `xp` and `xr`.

To recover the public Montgomery key from an Elligator2 representative you
use the function `cu25519_elligator2_rev (Cu25519Mon *xs, const Cu25519Ell
&rep)`. You pass in the representative and you get the corresponding public
key.

The Elligator2 representative cannot be distinguished from a random number.

To compute the secret shared by two keys use `cu25519_shared_secret (uint8_t
sh[32], const Cu25519Ris &xp, const Cu25519Sec &xs)` or
`cu25519_shared_secret (uint8_t sh[32], const Cu25519Mon &xp, const
Cu25519Sec &xs)` You pass the public key of the other party, `xp`, and your
own secret key, `xs`. The function computes the shared secret by both keys
and stores it in `sh`. Keep in mind that you need to hash this shared secret
before using it. The functions take the public key in either Montgomery or
Ristretto format. If the Montgomery and Ristretto values correspond to the
same secret key then the computed shared secret will be the same.

To sign a message use `cu25519_sign (const uint8_t *m, size_t mlen, const 
Cu25519Ris &xp, const Cu25519Sec &xs, uint8_t sig[64])` Pass the message to 
be signed in `m[0..mlen[` and the public and private keys of the signer. It 
will compute the signature and store it in `sig[0..64[`.

To verify a message use `cu25519_verify (const uint8_t *m, size_t mlen, const
uint8_t sig[64], const Cu25519Ris &xp)` Pass the message to be verified in
`m[0..mlen[`, the signature in `sig[0..64[` and the public key of the signer
in `xp`. The function will return 0 if the signature is valid or another
value if the signature is not valid.


symmetric.hpp
-------------

This file provides the functions dealing with secret key cryptography. It
defines the structure `Chakey`. *Chakey* represents a key used for secret key
cryptography. The function

	`void load (Chakey *kw, const uint8_t bytes[32])`

To encrypt a packet of data use

	`void encrypt_one (uint8_t *cipher, const uint8_t *m, size_t mlen,
	                   const uint8_t *a, size_t alen,
	                   const Chakey &keyn, uint64_t nonce64,
	                   uint_least32_t ietf_sender=0)`

Pass in `m[0..mlen[` the data to be encrypted. The key to be used is passed
in `keyn` and the 64 bit nonce for this packet is passed in `nonce64`. You
pass any additional data that is to be authenticated in `a[0..alen[`. If
there is no additional data to be authenticated then pass `alen=0`. The
function will encrypt the data and store the ciphertext in
`cipher[0..mlen+16[`. Note that `cipher` must point to storage for *mlen +
16* bytes. IETF uses 96 byte nonces. You define it using ietf_sender in
addition to the nonce64.

To decrypt an encrypted packet use

	`int decrypt_one (uint8_t *m, const uint8_t *cipher, size_t clen,
	                  const uint8_t *a, size_t alen,
	                  const Chakey &keyn, uint64_t nonce64,
	                  uint_least32_t ietf_sender=0)`

Pass in `cipher[0..clen[` the ciphertext. Pass in `a[0..alen[` the additional
data to be authenticated. If no additional data exists then pass `alen=0`.
Pass in `keyn` the key and in `nonce64` the 64 bit nonce for this packet. If
the packet can be correctly decrypted then this function will return 0. If
there was an error in the decryption the function will return a non zero
value. If the packet could be correctly decrypted the decrypted plaintext
will be put in `m[0..clen-16[`. Note that `m` must point to *clen - 16* bytes
of storage.

Some times you want to encrypt a packet using a single encryption key but
multiple authentication keys. For instance you encrypt a message for multiple
recipients. There is a single encrypted message, encrypted with a single
encryption key. However we use a different authentication key for each of the
recipients in order to generate a tag for each one. Each recipient can verify
with his own authentication key that the packet is authentic and has not been
tampered by any of the other recipients.

Use  this function to have multiple authentication tags:

	`void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
	                     const uint8_t *ad, size_t alen, const Chakey &kw,
	                     const Chakey *ka, size_t nka, uint64_t nonce64,
	                     uint_least32_t ieft_sender=0)`

The `m`, `mlen`, `ad`, `alen`, `kw` and `nonce64` are the plaintext, the
length of the plaintext, the autheticated data, the length of the
authenticated data, the encryption key and the nonce of this packet. They
have the same meaning as in the `encrypt_one` function. You must also pass in
`ka[0..nka[` an array of authentication keys. In addition to encrypting using
the key `kw` the function will also compute an authentication tag for each of
the authentication keys in `ka`. Each authentication tag has 16 bytes.
Therefore the encrypted message stored in `cipher` will have *nka* additional
tags, meaning that the total length of the ciphertext will be `mlen + nka*16`
bytes.

The following function is used to decrypt packets which have multiple
authentication tags.

	`int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen,
	                    const uint8_t *ad, size_t alen, const Chakey &kw,
	                    const Chakey &ka, size_t nka, size_t ika,
	                    uint64_t nonce64, uint_least32_t ietf_sender=0)`

The ciphertext is passed in `cipher[0..clen[`. The authenticated data is
passed in `ad[0..alen[`. The encryption key is passed in `kw` and the nonce
for this packet is passed in `nonce64`. You pass in `ka` the key that is to
be used to authenticate the packet. You must also pass in `nka` the total
number of authentication keys that were used to encrypt the packet. Pass in
`ika` the position of the key `ka` within the list of authentication keys
that were used to authenticate the packet. If the encryption is succesful the
function will return 0 and will store in `m` the plaintext. The plaintext will
take `clen - nka*16` bytes.


To derive a key from a password we use the Scrypt algorithm with the
Blake2b hashing function.

	`void scrypt_blake2b (uint8_t *dk, size_t dklen,
	                      const char *pwd, size_t plen,
	                      const uint8_t *salt, size_t slen,
	                      int shifts, int r=8, int p=1)`

Pass in `pwd[0..plen[` the password to be used. Pass in `salt[0..slen[` the
salt to be used to randomize the key. The function will store in
`dk[0..dklen[` the computed key. The `shifts` parameter states the amount of
memory and time to use to derive the key. The number of kilobytes used is
2^shifts. Selecting a value of 14 will require 16 MiB of memory to derive the
key. The amount of time required is proportional to the memory required. r
and p are the same as defined in the scrypt paper. The shifts parameter is
related to the N parameter of the scrypt paper: N = 1 << shifts. The actual
memory used is in bytes [(1 << shifts) + p]*r*128.


The library provides a PRNG according to NIST-800-90A. It generates a new
block of random output by running the output of Chacha. It gets random bytes
once at the constructor and then generates the random numbers without making
any system calls. It hashes the random bytes obtained from the system, the
current system time and the current value of the
std::chrono::high_resolution_clock. The hash is keyed with the given password
or key. The output of this random generator can be used to generate nonces
and temporary keys. The state of the random number generator is not reseeded
after the construction. You may however reset it explicitely whenever you wish
by calling `reset()`.

If the bytes returned by the system's random number generator are random then
the output of Keyed_random is also random. If system's source of random bytes
fails to produce random bytes then the output of Keyed_random can still be
used as a nonce because it is keyed with the system clock and the high
resolution clock. As long as you do not adjust your clock backwards it is
likely that the nonces will not repeat. If the password or key that you pass
is secret and unpredictable then the stream generated by Keyed_random key
will be unpredictable without knowing the password, even if the system's
random number generator fails.

	class Keyed_random {
	public:
		Keyed_random();
		Keyed_random (const char *pwd, size_t len);
		Keyed_random (const uint8_t *key, size_t len)
		void reset (const char *pwd, size_t len);
		void reset (const uint8_t *key, size_t  len);
		void get_bytes (uint8_t *buf, size_t n);
		void get_bytes (char *buf,  size_t n);
	};

Pass in the constructor or in the reset function either a key or a password
to be used as additional source of entropy. The get bytes will fill the
buffer with the requested amount of bytes. Note that this class is not thread
or fork safe. If several threads share the same Keyed_random object then you
must arrange for mutual exclusion among threads. Also if you fork then the
parent and the child processes will have the same Keyed_random object and
will generate the same random sequence. You must arrange for the Keyed_random
object to be reset after a fork.


The function

	`void randombytes_buf (void *p, size_t n)`

is used to generate random bytes. It is thread and fork safe. Therefore it
works even if two or more threads simultaneously call it. It also refreshes
its state after a fork so that the parent and child processes will generate
different random sequences.


noise.hpp
---------

This file implements the noise protocol. Select a handshake pattern and
initialize it according to its requirements as described in the Noise
protocol specification. Then exchange messages until the handshake is
finished. After finishing call `split()` to retrieve the encryption keys used
to transmit and receive transport messages.

Some useful patterns are X and XX.

The X pattern is used for one way message. You must set the local static key
with `set_s()` and in the case of the sender you must also set the
recipient's static public key. Then the sender writes a single message and
retrieves the encryption key. The recipient reads the message and retrieves
the encryption key.

The XX pattern is used for a two way handshake. Both the initiator and the
responder must set their own static key with `set_s()`. Then three messages
are exchanged. The initiator sends the first message (the client-hello
message), which is processed by the responder. The responder sends a reply
(the server-auth message), which is then processed by the initiator. Finally
the initiator sends a third message (the client-auth message) which is
processed by the responder. At this point both call split to get the
encryption keys for transmitting and receiving.

If no authentication of the initiator is required then you can use the NX
pattern which is the same as the XX pattern but omits the third message.


misc.hpp
--------

This file declares many utility functions.

	uint32_t leget32 (void *bytes)
	uint64_t leget64 (void *bytes)

These functions read a little endian value from unaligned storage.

	void leput32 (void *x, uint32_t u)
	void leput64 (void *x, uint64_t u)

The leget32, leput32, leget64, leput64 are defined in BSD systems.

These functions write a little endian value to unaligned storage.

	int crypto_neq (const void *v1, const void *v2, size_t n)

This function returns 0 if both byte arrays are equal. Another value if they
differ. This works in constant time.

	bool is_zero(const void *v1, size_t n);

This is a constant time check if v1[0..n[ is zero.

	void crypto_bzero (void *p, size_t n);

This is an out of line version of memset(0) that hopefully will not be
optimized away by the compiler.





Key management
==============

There remains the question of managing the public and private keys. There are
two levels for the handling of keys. If you just want to create keys and
manage them yourself then you should use the functions declared in
*group25519.hpp*. You create a key pair with `cu25519_generate()`. You can
then directly use such keys with the *ofstream* and *ifstream* classes above.
You are responsible for storing the keys, associating them with user
identities and distributing them. The *ofstream* and *ifstream* classes only
know about the keys themselves: they just ensure that something encrypted for
a public key can only be decrypted with the corresponding private key. They
do not associate an identity with a given key pair.

The functions declared in *keys.hpp* manage collections of keys into keyrings.
They support associating identities and other information to the raw keys and
also certifying keys. These functions provide enough support to maintain your
keyring and export and import keys. They use files as storage mechanism and
expect that you will distribute keys by distributing files. The library is
intended to be portable and therefore no networking functions are included.
The use of the keyring management functions is optional. If your scheme for
storing and exchanging keys uses a different paradigm (for instance key
servers) then you may want to implement a different set of key management
functions. The advantage of using only files are that the program runs
everywhere where C++11 is available and also that it allows you to build a
very simple implementation of online key servers by just exchanging these
files.



Comparison with Signal
----------------------

We are using the same model as PGP. It is intended for mail and file exchange
with offline correspondents. Key distribution and updating is considered to
happen separately from the encrypted communications. There is no concept of
forward secrecy except by creating a new work key. Updates of work keys are
not automatic because there is no server keeping the keys for us.

The Signal system uses a series of well documented protocols. You can see
them in https://whispersystems.org/docs/ It assumes that parties to the
communication will be offline at some times and a server stores the messages
for them.

Signal uses the XEd25519 signature scheme. The only advantage of this scheme 
over our Ristretto signatures is that it works with existing X25519 keys which 
are do not have a sign bit). XEd25519 requires that we keep the public 
Ed25519 key of the signer when signing. qDSA is a cleaner solution to this 
problem and the Ristretto format is the better solution for future extensions.

Signal uses the X3DH protocol for establishing the shared key. It uses an
ephemeral key (EK), a signed prekey (SPK) and a persistent identity key (IK).
These correspond to our ephemeral key, the work key and the master key. It
optionally uses one time prekeys (OPK) that are fetched from a server and used
only once. OPK require that there is a server that supplies OPKs. This is
not compatible with our e-mail paradigm of having offline encryption. X3DH
computes the key shared by a and b by using:

	DH1 = X25519 (IKa, SPKb)
	DH2 = X25519 (EKa, IKb)
	DH3 = X25519 (Eka, SPKb)
	SK = KDF (DH1 || DH2 || DH3)

We do not use IK for the computation of the shared secret. Instead we assume
that we always check the signature of SPK by the corresponding IK. In this
way we minimize the use of the private key corresponding to the IK to limit
the number opportunities to compromise it. We only need the master key to
sign the work keys. This is the only time that we need to use the private
master key. We use the Noise X protocol.

The Double Ratchet algorithm is used to compute new keys for each message.
The symmetric ratchet updates the key by using:

	Ki+1, MKi+1 = KDF (Ki, Di)

Where Ki is the Ratchet key at step i, MKi is the key used to encrypt the
message at step i and Di are the inputs to the ratchet at step i. Note that
the message key MKi is not further used for the computation of the next keys.
With this scheme we achieve forward secrecy for each message. Alice and Bob
also exchange new DH ephemeral keys. Each time a new shared secret is computed
and is used as the input data Di. There is a root chain and a sending and
receiving chain.

The double ratchet scheme provides protection against temporary compromises,
limiting the damage created by a key leak to a few messages. However it
requires that both Alice and Bob keep their state synchronized. A limited
buffer is provided for messages that are lost or received out of order. The
sesame protocol attempts to coordinate the selection of sessions among users
and devices.

It is not clear how the double ratchet algorithm could be effectively applied
to e-mail. e-mail does not have the concept of sessions. We could decide that
each correspondent gets a session, but then we may have sessions in which
messages are sent at very long intervals. Should all the mails from a sender
be considered a session? Only those within one day? Also e-mail messages are
usually kept for a longer time than Signal messages. We may also have very
asymmetric flows of messages: we may have a party sending many messages
without receiving any replies (for instance a mailing list server). The double
ratchet mechanism provides for forward secrecy by constantly changing the
keys. Many uses of e-mail require that messages persist and can be read long
after they were sent.

Given the complexity of keeping the ratchet state synchronized and the
apparent mismatch with existing e-mail systems we do not attempt to use it.

Note that Signal does not solve the problem of the initial distribution of
keys. It is either trust on first use or some other out of band protocol.
Given that this seems to be the major problem of e-mail encryption we are
left with additional complexity without an effective solution of the key
distribution problem.


Choice of algorithms
====================

There is just one algorithm for each task. No options are given. We follow
the lead of NaCl and provide simple to use APIs. Our choices are not unusual.
For encryption we use ChaCha20. For authentication we use Poly1305. The
combination of ChaCha20 and Poly1305 is well established. AES-GCM is also
popular but needs hardware support to run efficiently without side channels.
We use HKDF for hashing keys.

For hashing we use Blake2b. It is much faster than the SHA-2 or SHA-3
families and can be directly used in keyed mode without a HMAC construction.
Although Keccak and its derivative K12 offer a new way of implementing
symmetric cryptography using the sponge construction they are slower
than Blake2b.

For public key shared secret establishment we use X25519. For public key 
signatures we use Ed25519 with keys encoded using the Ristretto format. 
Ristretto keys can be directly used for signatures and for DH. 

For password based key derivation we use Scrypt. Scrypt is well established as
a memory hard function. Argon2 is still new. Although Argon2i was proposed as
a memory hard hash without side channels, it has been later shown that hash
functions with memory accesses independent of the input cannot be memory hard
(see the paper "Efficiently computing data independent memory hard
functions"). Therefore Argon2i is not a memory hard function (unless many
passes are used). The recommendation now is to use Argon2id. However it is not
clear what are the advantages over Scrypt in this case. Scrypt uses a data
independent pass (PBKDF2) before and after the mixing phase. This is similar
to using Argon2i and then Argon2d. In both cases the side channels cannot
give us the key, due to the data independent phase at the beginning. Also in
both cases Eve can detect the memory access patterns of the data dependent
phase and then effectively filter out all password tries that do not match
that pattern. Therefore in both cases the side channels do not recover the
key but remove the memory hard part. For now we stick to Scrypt.

For general session key establishment there is Noise. However Noise only
handles the case of encrypting to one single responder. For file encryption
we need to be able to encrypt for several keys without duplicating the
encrypted contents. This is done by encrypting with one single key and
authenticating with multiple keys. The actual key establishment for multiple
receivers is similar to running the X pattern of noise for each recipient.

