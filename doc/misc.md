Miscellaneous support routines
==============================

This file contains several routines used to format binary blocks and manipulate them.


	int crypto_neq(const void *v1, const void *v2, size_t n);

Return 0 if both byte arrays are equal. Another value if they differ. This
works in constant time.

	bool is_zero(const void *v1, size_t n);

Return true if the byte array v1[0..n[ is filled with zeros.

	void show_block(std::ostream &os, const char *label, const void *b, size_t nbytes);

This will show a block of bytes as hexadecimal. It will write the label first.


	ptrdiff_t read_block(const char *in, const char **next, std::vector<uint8_t> &dst);

This will read hexadecimal bytes from the string in and store the read bytes in
dst. It will skip spaces but it will stop either at the end of the string or
when a non-hexadecimal and non space character is found. *next will be set to
point to the character that stopped the conversion. It returns the number of
bytes converted or -1 if there was an error.


	void get_password(const char *prompt, std::string &pass);

Show the prompt and get a password. On UNIX it will use the system's
`getpass()` function to hide the password.


	uint_fast32_t update_crc32(const void *buf, size_t nbytes, uint_fast32_t crc=0);

CRC32 as defined by 802.11, TCP, zlib and PNG. To compute the CRC32 of a buffer
call as update_crc32(buf,count). To maintain a running count (for instance
while outputting to a stream) use new_crc = update_crc32(buf,count,old_crc).
Note that a CRC will catch typing or transmission errors, but is not a
cryptographic primitive.





Base 32, 58 and 64 encoding
===========================

Base 32 encoding
----------------

This is an encoding of binary bytes into characters that is case insentive and
avoids the letters 1, 0, o and l. It only contains letters and numbers. You can
read the resulting encoding over the phone and it will be unambiguous. This
encoding encodes every 5 bytes into 8 characters, resulting in a 60% expansion.

	void base32enc(const uint8_t *by, size_t nbytes, std::string &s, bool sep=true,
	               bool terminators=false);

Encode the array by[0..nbytes] in base 32 and store the result in the string s.
If sep is true then group the resulting string in groups of four characters,
writing a space to separate the groups. This improves the readability. If
terminator is true it will store equal signs, '=', at the end of the string
until it completes a group of 5 encoded bytes.

	int  base32dec(const char *s, std::vector<uint8_t> &v, ptrdiff_t n=-1);

Decode the contents of the string s and store them in the vector v. If you pass
n then it is the number of characters to convert. Otherwise it will convert the
whole string. It returns the number of bytes converted or -1 if there was an
errror.




Base 58 encoding
----------------

Base 58 encoding uses digits, lower case letters and upper case letters. It is
readable by humans but you cannot read it easily over the phone because it
distinguishes lower and upper case. On the other hand it is much more compact
than base 32 encoding.

	void base58enc(std::string &res, const uint8_t *num, size_t nsize);

Encode in res the array of bytes num[0..nsize].


	void base58dec(std::vector<uint8_t> &res, const char *s, size_t n);

Decode the base 58 string in s[0..n] and store the decoded bytes in res.




Base 64 encoding
----------------

This encoding encodes every 3 bytes into 4 characters (33% expansion). It uses upper case
letters, lower case letters, digits and the +/ signs.


	void base64enc(const unsigned char *bytes, size_t nbytes,
	               std::string &dest, bool wrap, bool terminators);

Encode bytes[0..nbytes] in Base 64 into the string. Pass true to wrap if you
want to wrap the resulting text in to lines. If you want to encode
incrementally  make sure that you allways pass a multiple of 3 for the size
nbytes, except for the last block.


	void base64dec(const char *s, size_t n, std::vector<unsigned char> &v);

Decode the text and append it to the vector. It will not clear the vector, it will
always append. The decoding stops when n characters have read or when a '=' is
encountered. Non base 64 characters (A-Za-z0-9+/) are ignored.



	class export Base64_encoder {
	public:
	   Base64_encoder()
	   void reset();
	   void encode_append(const unsigned char *bytes, size_t nbytes, std::string *dest);
	   void flush_append(std::string *dest);
	};

Base64 encoder. encode_append() appends text to the string dest. When you
are finished call flush_append() to append the trailing bytes. You may at
any time clear the string dest.


	class export Base64_decoder {
	public:
		 Base64_decoder();
		 void reset();
		 bool decode_append(const char *s, size_t n, std::vector<unsigned char> *dest);
		 void flush_append(std::vector<unsigned char> *dest);
	};

Base 64 decoder. decode_append() appends decoded bytes to dest.
flush_append() is called at the end of the stream to recover the trailing
bytes. decode_append() returns true if we have read a '=' sign, which
ends the stream.


