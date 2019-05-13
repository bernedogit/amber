Goals
=====

The main goal of amber is to have a set of functions for cryptography which
are based on portable C++ without using any system dependent customization
and with a simple compilation method. I should provide enough functionality
to create a file encryption program and at the same time it should be very
easy to integrate into an existing program. It should also be easy to use in
a secure way.

There are some alternatives that fall short of fulfilling the goals stated
above.

Libsodium has many source files and quite a complex directory structure. It
is not trivial to integrate libsodium into some other project. Its scope is
also quite limited. It provides enough primitives but no higher level
constructs. For instance if you want to encrypt a file you are left on your
own to compose the different functions for password based key derivation,
handling of multiple recipients and hybrid encryption.

Tweet NaCl achieves the goal of easy installation. It is small and can be
introduced in any program by just copying a single file to your program's
source directory. There is no need to configure anything: it is just standard
C that compiles cleanly. Tweet NaCl has another goal that we do not have:
Tweet NaCl is intended to have a very small source code size. We do not care
about the size of the source code. Instead we look for ease of compilation
and ease of introduction into existing programs. We use just a few pairs of
`.hpp`/`.cpp` files to provide the whole services. They need no configuration
and can be either packaged as a library or taken into your own project as
they are.

The other shortcoming of NaCl is that it fails to provide some functions that
are required for most practical work: you need a password based key
derivation function, access to a random number generator, a way to put
together hybrid encryption in order to have a working file encryption, a way
of writing binary files, ascii compatible files and key management
functions, including signing keys.

This library has the following properties:

* Very easy to integrate into existing projects.

* It provides a wider scope of functionality: from low level primitives to
  complete iostream classes that perform hybrid file encryption.

* Additional cryptographic properties not usually found in other libraries
  (see below).

This library provides all of this, including things unrelated to cryptography
but which are needed to create a working tool, like command line handling and
catching and displaying exceptions. In addition there is the file `amber.cpp`
that contains a utility that provides support for symmetric encryption of
files, public key encryption of files, public key signatures, key ring
management and packing and unpacking archives of files. It can be used in a
way similar to PGP/GPG.



Algorithms
----------

You do not get to choose any algorithm. Keeping with the philosophy of NaCl
there is a single algorithm for each function. We use:

 * Curve25519/X25519 and Elligator2 for public key encryption.

 * Ed25519 and qDSA for signatures.

 * Ristretto as the format for public keys.

 * ChaCha20 for secret key encryption.

 * Poly1305 for authentication.

 * Blake2b for hashing.

 * Scrypt for password based key derivation.

 * Noise for session key establishment.

 * Base 64 for encoding signatures when clear signing.

 * Base 58 for showing keys to the user and accepting them. This can be
   changed by the user to base 16, base 32 or base 64.

 * Protocol buffers wire format for storage of keys and archives.


Special properties of this library
----------------------------------

The library and tool provide the usual file encryption, signature and key
management features found in file encryption programs. In addition the
following cryptographic properties are supported, which are not common in
other libraries:

 * Public keys have 32 bytes and support both encryption and signature
   verification. The public key stores the ristretto encoding of the point.
   This allows both encryption and signature verification using a single
   32-byte key. The implication is that you only need to distribute a single
   32-byte key. You do not need to have one X25519 key pair for encryption
   and another Ed25519 key pair for signatures. One single Ristretto key pair
   is enough. There is no need to manage key ids and fingerprints like in PGP
   because the key is short enough that it can be used as the ID.

 * The encrypted stream is made of packets that use sequential nonces plus
   additional authenticated data to authenticate the starting packet, middle
   packets and the ending packet. Therefore the library/tool never outputs
   any decrypted plain text which has not been authenticated, even if using
   its output for a pipe. It detects any truncation of the encrypted file,
   and also any attempt to rearrange or drop packets within the stream. See
   <https://www.imperialviolet.org/2015/05/16/aeads.html> for ideas on how
   this works.

 * The encrypting and decrypting ofstream and ifstream classes support random
   access when writing or reading the encrypted streams. Users are not
   restricted to sequential access. You can seek within the file at any time
   to any position, both while writing to or reading from the encrypted file.
   Both classes have a simple API and throw exceptions on decryption errors,
   making it difficult to ignore tampering with the files.

 * When encrypting for multiple recipients, each packet carries as many
   authentication tags as there are recipients. Therefore each recipient can
   verify that the data came from the sender and that it was not manipulated
   by one of the other recipients. Using a single authentication tag just
   makes sure that the packet was written by anyone who knows the secret key
   used to authenticate the packet: this could be any of the multiple
   receivers and the sender. By using a different tag for each recipient, we
   make sure that the recipient knows that the packet has been written by
   somebody who knows the secret shared only by this particular receiver and
   the sender. Therefore we bring the same authentication guarantee (with
   repudiation) that is present in the normal one to one encryption to the
   case of multiple receivers.

 * The encrypted file is not distinguishable from a random sequence of bits
   without having the key or the password. Due to the use of Elligator2 Eve
   cannot even figure out if there is something encrypted or not. Therefore
   without being able to decrypt the file Eve knows nothing about the sender
   or the receivers or if there is any encryption. You can use the encrypted
   file in whatever steganographic scheme you may wish without further
   modifications. The encrypted file itself will not reveal that there is any
   encryption at all. This applies both to the password based version and to
   the public key version of the encryption. Note that higher level
   protocols may leak information concerning the presence of encryption. If
   Alice and Bob are exchanging messages and Mallory observes that there is
   a reply for each message then she can tamper with one message and see if
   a reply comes or not. If there is a change in the behaviour of Alice and
   Bob then Mallory can deduce that the exchanged "random" files were
   encrypted. Note also that the bits of the encrypted file are not
   distinguishable from pure random. If you embed them within pink noise it
   will be possible to detect that there are two types of noise. A simple
   spectral analysis of the bits may reveal that the surrounding bits have
   some signals in them that are missing in the generated encrypted file.

 * The library adds to each packet padding bytes before the encryption and
   removes them after decryption. It uses random padding sizes so that the
   size of the ciphertext is not the same as the size of the plaintext. The
   user can select the amount of padding. If no size is given explicitly by
   the user then a random amount of padding is selected. Therefore each time
   that you encrypt the same file you will get an encrypted file with a
   different length. This is a simple measure to make traffic analysis harder.

 * The program and library support deniable encryption. The padding bytes are
   filled with random bytes for each packet. The library offers a function
   that encrypts another file into the padding bytes with a second password
   or a second key in addition to the normal encryption process with the
   first password or first key. The corresponding routine decrypts the
   padding bytes using the second password or second key after having
   decrypted the whole packet with the first password or first key. There is
   no way to distinguish an encrypted file which carries a second file from a
   normal encrypted file. The padding bytes are randomly generated when
   encrypting a normal file. The padding bytes that carry the second file are
   the result of applying the ChaCha encryption and the Poly1305 tag in the
   case of a second encrypted file. The definition of ChaCha is such that the
   output of encrypting with it is not distinguishable from random. The
   Poly-1305 tag is also not distinguishable from random bytes.

 * The program and library offer the functionality to spoof a message. We can
   create an encrypted message using our private and public keys and any
   other public key so that it looks like the message was encrypted by the
   other public key for us. This functionality is necessary for practical
   repudiation of the message by the sender. Every cryptographer knows that a
   message authentication code is not a signature and therefore it can be
   repudiated. However if Bob does not have the knowledge to spoof a message
   then Alice can pretend that Bob created the message but nobody will
   believe her, even if it is theoretically possible to do that. The spoofing
   functionality that is embedded in the program allows anyone who can use
   the program to also create spoofed messages. Therefore the claim by Alice
   that Bob created the message is credible because Bob already knows how to
   use the program.



Sources
-------

The Poly1305 code has been taken from Floodyberry's donna implementation.

The Blake2 algorithm uses the reference implementation from the RFC 7693.

The Siphash-2-4 uses the portable implementation written by Gregory
Petrosyan.

The other parts were written by Pelayo Bernedo.

Daniel J. Bernstein created Salsa20, ChaCha20, Poly1305 and Curve25519.

The Ed25519 signature scheme was designed by Daniel J. Bernstein, Niels Duif,
Tanja Lange, Peter Schwabe, and Bo-Yin Yang.

Scrypt was devised by Colin Percival. It uses the Salsa20/8 algorithm.

Blake2 was designed by Jean-Philippe Aumasson, Samuel Neves, Zooko
Wilcox-O'Hearn and Christian Winnerlein. It uses the ChaCha algorithm for
the mixing of the input.

Siphash was designed by Jean-Philippe Aumasson and Daniel J. Bernstein.

Noise was designed by Trevor Perrin.

Given that Bernstein's work has directly or indirectly affected the above
algorithms, this library and its associated tool are called amber.

The author of this program and most of the files in the library is Pelayo
Bernedo. Although the ideas and some of the implementations are taken from
others, please do not blame any of the people mentioned above for any errors
or bugs in this library or program.



License
-------

The parts taken from other persons use public domain, MIT, or BSD licenses.

The parts written by Pelayo Bernedo are licensed according to the two clause
BSD license.



Installing the program and library
----------------------------------

There are several ways in which you can use this library. You may just take
the source files and copy them into your own source tree and just compile it
together with your program. You may also use the provided makefile and create
a library. You would install this library into your system and then use it.

The program has all public items inside an inline namespace which is itself
in the `amber` namespace. You call its functions by using the `amber::`
prefix or with a `using` directive. The inline namespace within `amber` is
the value of the macro AMBER_SONAME. Whenever the ABI changes in an
incompatible way the SONAME of the library should be increased. The soname is
set in two places: the file soname.hpp contains the definition of the macro
AMBER_SONAME. If this is defined like this:

  #define AMBER_SONAME v3

then all the exported names will be within the namespace `amber::v3::` within
the library's object code. However client programs still refer to them as
`amber::` in the source code. The other place that must contain the correct
SONAME is the makefile. Set it like this:

  SONAME=3

With this set up you are generating the version 3 of the library. When the
ABI changes the version should be bumped to 4. When compiling the header
soname.hpp sets the version that client programs will use. In this way we can
have several versions coexisting within the same executable. Assume that the
program `foobar` uses the libraries `libfoo.so` and `libbar.so`. Both
`libfoo.so` and `libbar.so` use the `libamber.so` library but were compiled
with different versions. At runtime `libfoo.so` uses `libamber.so.3` and
requires symbols named `amber::v3::...`. The library `libbar.so` uses
`libamber.so.4` and requires symbols named `amber::v4::...`. They all coexist
within the same executable.


Documentation
-------------

The file *amber.md* describes the use of the program *amber*. It is intended
for users of the program that do not know about cryptography. It tries to
explain the concepts behind the program and the actual usage of the program.

The file *libamber.md* gives an starting point on how to use the library in
your programs. You should read it and then each of the header files that
declares and documents the particula API.

The file *amber-format.md* describes the format of the encrypted files, the
keyrings and the packed archives. It also shows how the different algorithms
are used in order to provide for hybrid encryption. Read this file if you are
interested on the internal working of the library and program.

TweetAmber is similar to TweetNaCl. It is a reduced version of amber which
fits in a single file. Its companion tool tweetcmd is able to encrypt,
decrypt, sign and verify files which are compatible with amber. Tweetcmd also
fits in one single file. See *tweetamber.md* for details.


