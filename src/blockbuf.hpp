#ifndef AMBER_BLOCKBUF_HPP
#define AMBER_BLOCKBUF_HPP

/* Copyright (c) 2015-2019  Pelayo Bernedo.
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



// Encrypted input and output usign C++ streams. If you are processing a file
// or stream it will be divided into chunks and each processed chunk will be
// authenticated. Therefore you can pipe the output of the decryption and be
// sure that whatever is written to the output has been authenticated. Of
// course you still have to handle what you do if the encrypted file has
// been truncated. This will be reflected in the badbit of the encrypted
// file and it may throw an exception, but you have to decide what to do
// about it.

#include <streambuf>
#include <fstream>
#include <vector>

#ifndef __STDC_LIMIT_MACROS
	#define __STDC_LIMIT_MACROS 1
#endif
#include <stddef.h>
#include "symmetric.hpp"
#include "group25519.hpp"
#include "misc.hpp"

namespace amber {  namespace AMBER_SONAME {


// This is the streambuf that handles encrypted input and output. Call
// init_read() or init_write() to set up. Construct a iostream object with
// this buffer and use it. Then when you are finished, flush the iostream
// object and call this close() function.
class EXPORTFN Blockbuf : public std::streambuf {
	Chakey keyw;
	uint64_t nonce64, base_nonce64;
	// Each block has block_filler bytes at the beginning of the block,
	// followed by payload bytes up to a total size (filler + payload) of
	// block_size bytes.
	size_t   block_size, block_filler;
	ptrdiff_t block_number, last_block_written;
	size_t   mac_size;
	ptrdiff_t   payload_bytes;
	std::streamoff first_block; // Offset in bytes of the first block.
	std::streambuf *io;
	bool writing;
	bool eof;
	std::istream *owner_is;
	std::ostream *owner_os;
	std::vector<char> buf;
	std::vector<Chakey> kaw;
	Chakey kar;
	size_t nka, ika;
	bool closed;
	int shifts;
	Keyed_random krand;

	void init(const Chakey &key, uint64_t nonce64, size_t block_size,
	          size_t block_filler, std::streambuf *sb);
	void set_writing() { writing = true; }
	void set_adw(const Chakey *ka, size_t nk);
	void set_adr(const Chakey &ka, size_t nk, size_t ik);
	bool flush_current(bool last);   // return true if it was type 3.
	int read_block();

	void write_sym_header(std::streambuf *io, const char *pass, size_t npass,
	        const uint8_t nonce[24], unsigned block_size,
	        unsigned block_filler, int shifts,  Chakey *kw, uint64_t *nonce64);
	void write_pub_header(std::streambuf *io, unsigned block_size,
	    unsigned block_filler, const Cu25519Pair &tx,
	    const std::vector<Cu25519Ris> &rx,
        Chakey *kw, uint64_t *nonce64, std::vector<Chakey> &kav,
        bool spoof = false, uint32_t info_size=0);

protected:

	virtual int overflow(int ch);
	virtual int underflow();
	virtual std::streamsize showmanyc();
	virtual pos_type seekoff (off_type off, std::ios_base::seekdir dir,
	                    std::ios_base::openmode which) override;
	virtual pos_type seekpos(std::streampos pos, std::ios_base::openmode which) override;



public:
	enum { default_shifts = 14 };
	Blockbuf() : closed(true) {}
	~Blockbuf();
	std::string error_info;

	void set_owner(std::istream *is) { owner_is = is; }
	void set_owner(std::ostream *os) { owner_os = os; writing = true; }
	void close();
	void clear() { eof = false; }

	const std::string & get_error_info() const { return error_info; }
	size_t get_block_size() const { return block_size; }
	size_t get_block_filler() const { return block_filler; }
	int get_shifts() const { return shifts; }

	const Chakey * get_key() const { return &keyw; }
	uint64_t get_nonce64() const { return nonce64; }
	uint64_t get_base_nonce64() const { return base_nonce64; }

	const Chakey * get_kaw() const { return &kaw[0]; }
	const Chakey * get_kar() const { return &kar; }
	size_t get_nka() const { return nka; }
	size_t get_ika() const { return ika; }

	void init_write (std::streambuf *sb, const char *password, ptrdiff_t bs=-1,
	                 ptrdiff_t bf=-1, int shifts=default_shifts);
	void init_write (std::streambuf *sb, const Cu25519Pair &tx,
	                 const std::vector<Cu25519Ris> &rx, ptrdiff_t bs=-1,
	                 ptrdiff_t bf=-1);
	void init_spoof(std::streambuf *sb, const Cu25519Pair &rx, const Cu25519Ris &txpub,
	                int ndummies, ptrdiff_t bs, ptrdiff_t bf);

	void init_read (std::streambuf *sb, const char *password, int shift_max=0);
	void init_read (std::streambuf *sb, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx);
};



class EXPORTFN Amber_stream_base {
protected:
	virtual ~Amber_stream_base() {}
	Blockbuf bbe;
public:
	// Error reporting. This gives a descriptive text with the reason for the
	// failure.
	const std::string & get_error_info() const { return bbe.get_error_info(); }
	size_t get_block_size() const { return bbe.get_block_size(); }
	size_t get_block_filler() const { return bbe.get_block_filler(); }
	int get_shifts() const { return bbe.get_shifts(); }
};


// Both ofstream and ifstream may throw when opening a file. Use the
// nothrow_t variants of ifstream if you want to check the badbit yourself.
// When reading or writing if there is an error the badbit will be set. The
// constructors call exceptions(std::ios_base::badbit) so that when an
// error occurs an exception is thrown. Normal formatting and eof errors
// will not throw, but decryption errors will throw. The default is that
// decryption errors at any stage will throw.



// Write to an encrypted file. The file is written in chunks, which are
// authenticated separately. The class supports seeking into the stream for
// random access writing. If you want to use the seeking capabilities the
// underlying file must support writing AND reading from the file.

class EXPORTFN ofstream : public Amber_stream_base, public std::ostream {
	std::fstream os;
public:
	ofstream();
	// Open a file with password based encryption. shifts is the parameter to
	// scrypt. It will require time proportional to 2^shifts and the required
	// memory will be 2^shifts kilobytes. bs is the size of the blocks of the
	// stream. Each block is authenticated separately. bf is the number of
	// padding bytes that are used for each block. Within the bs bytes of
	// each block, the first bf bytes are just filler bytes and the rest
	// is the payload.
	ofstream(const char *name, const char *password, ptrdiff_t bs=-1,
	         ptrdiff_t bf=-1, int shifts = Blockbuf::default_shifts);

	// Same as above but using an underlying stream for output.
	ofstream(std::ostream &oss, const char *password, ptrdiff_t bs=-1,
	         ptrdiff_t bf=-1, int shifts = Blockbuf::default_shifts);

	// Open a file with key based encryption. You pass the keys of the sender
	// in txpub and txsec. You pass a list of keys for which the message will
	// be encrypted in rx. bs and bf are as above.
	ofstream(const char *name, const Cu25519Pair &tx, const std::vector<Cu25519Ris> &rx,
	         ptrdiff_t bs=-1, ptrdiff_t bf=-1);
	~ofstream();
	// Same as the corresponding constructors.
	void open(const char *name, const char *password, ptrdiff_t bs=-1,
	          ptrdiff_t bf=-1, int shifts = Blockbuf::default_shifts);
	void open(const char *name, const Cu25519Pair &tx,
	          const std::vector<Cu25519Ris> &rx,
	          ptrdiff_t bs=-1, ptrdiff_t bf=-1);

	// Spoof a file. It will look like if it had been encrypted by txpub for
	// rxsec. ndummies additional bogus recipients will be added to the
	// message. This feature is essential to have a credible repudiation.
	// Alice can always pretend that Bob spoofed the file to look like she
	// wrote it. As long as Bob knows how to use the program or library then
	// Alice's claim is credible.
	void open_spoof(const char *name, const Cu25519Pair &rx,
	          const Cu25519Ris &txpub, int ndummies, ptrdiff_t bs=-1, ptrdiff_t bf=-1);
	void close();
};


// Read from an encrypted file. The class support seeking for random access.
class EXPORTFN ifstream : public Amber_stream_base, public std::istream {
	std::ifstream is;

public:
	ifstream();

	// For the nothrow versions use the state flags and get_error_info() to
	// inquire about the errors.

	// Open a file encrypted with a password. Throw on errors.
	ifstream(const char *name, const char *password, int shifts_max=0);
	// Same but doesn't throw. It sets the badbit.
	ifstream(const char *name, const char *password, std::nothrow_t, int shifts_max=0);

	// Open a file encrypted with a key. Pass in the receiver's Cu25519 secret key and
	// read the sender's public key. Throw on errors.
	ifstream(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx);
	// Same but doesn't throw. It sets the badbit.
	ifstream(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx, std::nothrow_t);

	// Same as above.
	void open(const char *name, const char *password, int shifts_max=0);
	void open(const char *name, const char *password, std::nothrow_t, int shifts_max=0);
	void open(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx);
	void open(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx, std::nothrow_t);
	void close();
	void clear(std::ios_base::iostate = std::ios_base::goodbit);
};

void insert_icryptbuf(std::istream &is, Blockbuf *bb);

class EXPORTFN ocryptwrap : public std::ostream {
	Blockbuf *buf;
public:
	ocryptwrap(Blockbuf *bb);
	~ocryptwrap();
	void close();
};


// Hide the real file in the block_filler bytes so that when decrypting the
// file will look like if only bogus has been encrypted with the password
// *pass1*. The output will be written to the file *ename*. The innocent
// looking file *bogus* will be encrypted as the normal encrypted file with
// the password *pass1*. The file *real* will be encrypted into the filler
// bytes using the password *pass2*.
EXPORTFN
void hide(const char *ename, const char *bogus, const char *real,
          const char *pass1, const char *pass2, int bs, int bf, int shifts);

// Decrypt the second file present in the encrypted file *iname* using the
// passwords *pass1* and *pass2* and store the decrypted file in oname.
EXPORTFN
void reveal(const char *oname, const char *iname, const char *pass1,
            const char *pass2, int shifts_max=0);

// Hide the real file in the block_filler bytes as above. The file looks like
// it was encrypted for rx but the hidden text is encrypted for rx2.
EXPORTFN
void hide(const char *ename, const char *bogus, const char *real,
          const Cu25519Pair &tx, const std::vector<Cu25519Ris> &rx,
          const Cu25519Ris &rx2, int bs, int bf);

// Decrypt the second file using the key rx2.
EXPORTFN
void reveal(const char *oname, const char *iname, const Cu25519Pair &rx1,
            const Cu25519Sec &rx2, Cu25519Ris *sender, int *nrx);

}}

#endif

