C++ Streams with Encryption
===========================

These ofstream and ifstream classes support reading and writing encrypted
streams as if they were normal C++ streams. You can pass them as ostream& and
istream& to any function performing input and output and they will handle
encryption and decryption transparently. They only differ from the normal
ifstream and ofstream in the constructors and `open` functions. They support
random access within the stream, both for writing and for reading. Reading
from the ifstream will never return unauthenticated data. Reordering and
deletion of chunks (either at the beginning, middle or end of the stream)
will be detected, the badbit flag will be set and an exception will be
thrown. The classes support both password based encryption and key based
encryption. In both cases there is a header and then a sequence of chunks
encrypted with `encrypt_multi()`. They differ in the contents of the header
and the encryption parameters.



Padding
-------

The ofstream and ifstream classes also support padding of messages in order
to obfuscate the real size of the encrypted message and make traffic analysis
harder. Each chunk has an encrypted content made of up to *block_size* bytes.
All chunks except the last one have *block_size* bytes. The last one may have
less. All the *block_size* bytes are encrypted and if any of them is modified
the authentication will fail. Within the *block_size* bytes of encrypted
material the first *block_filler* bytes are discarded when reading and only
the remaining *block_size - block_filler* bytes are used as payload. In other
words, each block consists of bogus *block_filler* bytes followed by payload
bytes. All contents (both the bogus and payload bytes) are encrypted and
protected by the authentication tag. The user can set the number of
*block_filler* and *block_size* bytes and this controls the expansion of the
payload. The ratio *block_filler/block_size* is approximately the amount of
overhead that will be added to the encrypted stream in order to obfuscate the
real size. Selecting *block_filler/block_size*=0.5 will for instance expand
the resulting stream by 100%. If you do not explicitely set the *block_size*
and *block_filler* values they will be selected at random. This ensures that
encrypting the same file will give different lengths of encrypted output each
time that you encrypt the file. It will make Eve's task harder because there
will be some variation in the resulting length. The default is that the
expansion will be between 0 and 50% at random. You can override this by
specifying the bf and bs parameters to the constructor or the open functions.
bs is the *block_size* and bf is the *block_filler*. Pass -1 if you want the
value to be selected at random.



Chunks and detection of deletion, truncation and reordering
-----------------------------------------------------------

After the header, either for password based encryption or key based
encryption, there is a sequence of encrypted chunks. They are encrypted using
the symmetric session key. For password based encryption each chunk will be
encrypted with one single byte of additional data. The first chunk will have
1 as the value of the additional data byte. The last chunk will have 3 as the
value of the additional data byte. All other blocks will have 2 as the value
of the additional data byte. This setting ensures that we will detect
tampering with the chunks. If the chunks are reordered or if any chunk in the
middle is removed this will be detected because the nonce is incremented
sequentially for each chunk: a missing chunk will trigger an authentication
failure due to the wrong nonce. If the stream is truncated by removing chunks
from the tail of the stream this will be detected because the last block is
authenticated with a byte with value 3 instead of the value 2 used for blocks
in between. Eve could also try to remove blocks from the beginning and adjust
the nonce accordingly so that the manipulated nonce starts with the nonce
expected for the first block that Eve does not remove. This tampering will be
detected because the first block is authenticated with a byte with value 1
instead of the value 2 or 3 used for the other blocks. In case that there is
a single block, then we use the value 3. The additional authenticated data is
not transmitted, it is just used by both the sender and the receiver to
detect tampering of blocks.

There is a second mechanism to detect truncation. The nonces are fixed by the 
protocol. They start with a fixed value. If blocks are removed from the 
beginning then the remaining blocks will have the wrong nonce and their 
decryption will fail. The last block has a special nonce: it is the nonce 
that would correspond according to the sequence of blocks, but it has its 
highest bit set. This also detects truncations.



Random access
-------------

The ofstream and ifstream support random access. If they are used
sequentially they will also write or read sequentially to their underlying
iostream, allowing their use with pipes. If you tell ifstream to seekg()
within the stream, then it will move to the corresponding chunk and read the
chunk. This is done transparently. Therefore you can always seek to wherever
you like and whatever is read will have been authenticated. When writing to
an ofstream a different strategy is required. If you want to seekp() to
another position and this requires moving to another chunk then the seekp()
will first write the current chunk, seek to the new chunk position and
**READ** the new chunk's existing contents. Whenever you write to the new
position, the suitable part of the chunk will be updated while leaving the
parts that already where there. Note that seekp() in the ofstream requires
read access to the underlying stream. This may fail if the underlying stream
allows writing but not reading. For files, the ofstream class handles this
transparently. Whenever you write to the ofstream, even after seekp()ing, the
correct chunk will be written, with the correct authentication tag.




