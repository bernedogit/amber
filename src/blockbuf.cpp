/* Copyright (c) 2015-2019 Pelayo Bernedo.
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


#include "blockbuf.hpp"
#include "symmetric.hpp"
#include "blake2.hpp"
#include "hasopt.hpp"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <sstream>
#include "hasopt.hpp"
#include "misc.hpp"
#include "hkdf.hpp"
#include "noise.hpp"
#include <assert.h>

//#define DEBUG_VERBOSE 1

namespace amber {  namespace AMBER_SONAME {

// Amount to add to the nonce when encrypting the last packet of the stream.
// This detects truncation of the last packet.
static const uint64_t ndelta = 0x8000000000000000;

// The compiler will put the vtable here.
Blockbuf::~Blockbuf() {}


void Blockbuf::init(const Chakey &key, uint64_t n64, size_t block_sz,
                    size_t block_fill, std::streambuf *si)
{
	keyw = key;
	nonce64 = base_nonce64 = n64;
	block_number = 0;
	block_size = block_sz;
	block_filler = block_fill;
	payload_bytes = 0;
	first_block = si->pubseekoff(0, std::ios_base::cur, std::ios_base::in);
	last_block_written = -1;
	io = si;
	writing = false;
	eof = false;
	error_info.clear();
	mac_size = 16;
	buf.resize(block_size + mac_size);
	krand.get_bytes(&buf[0], block_filler);
	setp(&buf[block_filler], &buf[block_size]);
	setg(&buf[block_filler], &buf[block_filler], &buf[block_filler]);
	owner_is = 0;
	owner_os = 0;
	nka = 0;
	ika = 0;
	closed = false;
	kaw.clear();
}

void Blockbuf::set_adw (const Chakey *ka, size_t nk)
{
	kaw.resize(nk);
	nka = nk;

	for (unsigned i = 0; i < nk; ++i) kaw[i] = ka[i];
	mac_size = nk * 16;

	buf.resize(block_size + mac_size);
	krand.get_bytes (&buf[0], block_filler);
	setp(&buf[block_filler], &buf[block_size]);
	setg(&buf[block_filler], &buf[block_filler], &buf[block_filler]);
	kar = ka[0];
	ika = 0;
}

void Blockbuf::set_adr (const Chakey &ka, size_t nk, size_t ik)
{
	kar = ka;
	mac_size = nk * 16;
	nka = nk;
	ika = ik;

	buf.resize(block_size + mac_size);
	setp(&buf[block_filler], &buf[block_size]);
	setg(&buf[block_filler], &buf[block_filler], &buf[block_filler]);
}


Blockbuf::pos_type
Blockbuf::seekoff (off_type off, std::ios_base::seekdir dir,
                   std::ios_base::openmode which)
{
	// When reading block_number is the next block to be read. When writing
	// it is the next block to be written.
	std::streamoff bn = block_number;
	if (bn != 0 && !(which & std::ios_base::out)) --bn;
	std::streamoff base = bn * (block_size - block_filler);

	if (dir == std::ios_base::cur) {
		ptrdiff_t boff;
		if (which & std::ios_base::out) {
			boff = pptr() - &buf[block_filler];
		} else {
			boff = gptr() - &buf[block_filler];
		}
		off += boff + base;
	} else if (dir == std::ios_base::end) {
		std::streamoff file_size = io->pubseekoff(0, std::ios_base::end, std::ios_base::in);
		file_size -= first_block;
		std::streamoff last_block = file_size / (block_size + mac_size);
		std::streamoff boff = file_size - last_block * (block_size + mac_size);
		if (size_t(boff) < block_filler + mac_size) {
			boff = 0;
		} else {
			boff -= block_filler + mac_size;
		}
		off += last_block * (block_size - block_filler) + boff;
	}

	if (!(which & std::ios_base::out) && (base <= off && off < base + payload_bytes)) {
		// We stay in the current block.
		setg(&buf[block_filler], &buf[block_filler + off - base], &buf[block_filler + payload_bytes]);
		if (payload_bytes != 0) return off;
	} else if (writing) {
		// Flush current block contents.
		flush_current(false);
	}

	size_t saved_bn = block_number = off / (block_size - block_filler);
	std::streamoff tmp = block_number * (block_size + mac_size) + first_block;
	nonce64 = base_nonce64 + block_number;
	base = block_number * (block_size - block_filler);

	// Seek to the new block and read its old contents.
	eof = false;
	io->pubseekoff (tmp, std::ios_base::beg, std::ios_base::in | std::ios_base::out);
	uint64_t saved_nonce = nonce64;
	// If we are seeking to the end, we do not need to read the block.
	// Attempting to read the block will fail and set the stream to badbit.
	if ((which & std::ios_base::in) || block_number <= last_block_written) {
		read_block();
	}

	if (which & std::ios_base::in) {
		setg (&buf[block_filler], &buf[block_filler + off - base], &buf[block_filler + payload_bytes]);
	}
	if (which & std::ios_base::out) {
		setp (&buf[block_filler + off - base], &buf[block_size]);
		// Go back to the beginning of the new block.
		io->pubseekoff (tmp, std::ios_base::beg, std::ios_base::in | std::ios_base::out);
		// and bring back the nonce;
		nonce64 = saved_nonce;
	}
	if (writing) {
		block_number = saved_bn;
	}
	return off;
}

int Blockbuf::read_block()
{
	if (closed || eof) {
		if (owner_is) owner_is->setstate(std::ios_base::eofbit);
		return EOF;
	}

	ptrdiff_t request = block_size + mac_size;
	buf.resize(request);
	std::streamsize nr = io->sgetn(&buf[0], request);

	if (nr < 0 || nr < std::streamsize(block_filler + mac_size)) {
		std::ostringstream os;
		format(os, _("Read too few bytes, number read: %d, expected (filler + mac): %d."),
		        nr, block_filler + mac_size);
		std::streamoff curpos = io->pubseekoff(0, std::ios_base::cur, std::ios_base::in);
		std::streamoff lastpos = io->pubseekoff(0, std::ios_base::end, std::ios_base::in);
		io->pubseekoff (curpos, std::ios_base::beg, std::ios_base::in);
		format (os, _(". Current position in file %d, file size %d"), curpos, lastpos);
		error_info = os.str();
		if (owner_is) {
			owner_is->setstate(std::ios_base::badbit);
		}

		throw std::runtime_error (error_info);
		return EOF;
	}

	// This logic fails if the last block happens to have exactly 'request'
	// bytes. But the writing routine avoids this case by putting an
	// additional empty block.
	uint64_t nm = 0;
	uint8_t type = block_number == 0 ? 1 : 2;
	if(nr < request) {
		type = 3;
		nm = ndelta;
		eof = true;
		// This is the only way to reach the end of the file: getting a type
		// 3 block
		if (nonce64 >= ndelta - 1) {
			throw_rte (_("Trying to read more than 2⁶³ packets."));
		}
	}

	int res = decrypt_multi((uint8_t*)&buf[0], (uint8_t*)&buf[0], nr, &type, 1,
	                         keyw, kar, nka, ika, (nonce64++) + nm);
	if (res != 0) {
		std::ostringstream os;
		format(os, _("Error while trying to decrypt the block number %d starting at %d with %d bytes."),
		       block_number, block_number * block_size, nr);
		format(os, _(" nka=%d ika=%d payload=%d, nonce=%d, type=%d"),
		        nka, ika, nr - block_filler - 16*nka, nonce64 - 1 + nm, (unsigned)type);
		error_info = os.str();
		if (owner_is) {
			owner_is->setstate(std::ios_base::badbit);
		}
		throw std::runtime_error (error_info);
		return EOF;
	}
	payload_bytes = nr - mac_size - block_filler;
	setg(&buf[block_filler], &buf[block_filler], &buf[nr - mac_size]);
	++block_number;
	return payload_bytes > 0 ? (unsigned char)buf[block_filler] : EOF;
}


int Blockbuf::overflow(int ch)
{
	if (closed) {
		if (owner_os) {
			owner_os->setstate(std::ios_base::badbit);
		}
		return EOF;
	}
	writing = true;
	if (pptr() != epptr()) {
		*pptr() = ch;
		pbump(1);
	} else if (ch != EOF) {
		uint8_t type = block_number == 0 ? 1 : 2;
		ptrdiff_t mlen = pptr() - &buf[0];
		if (ptrdiff_t(payload_bytes + block_filler) > mlen) {
			mlen = payload_bytes + block_filler;
		}
		krand.get_bytes (&buf[0], block_filler);
		encrypt_multi((uint8_t*)&buf[0], (uint8_t*)&buf[0], mlen, &type, 1,
		              keyw, &kaw[0], nka, nonce64++);

		ptrdiff_t request = mlen + 16*nka;
		if (io->sputn(&buf[0], request) != request) {
			error_info = _("Can't write encrypted data to final destination.");
			if (owner_os) {
				owner_os->setstate(std::ios_base::badbit);
			}
			return EOF;
		}
		buf[block_filler] = ch;
		setp(&buf[block_filler], &buf[block_size]);
		pbump(1);
		payload_bytes = 0;
		if (last_block_written < block_number) {
			last_block_written = block_number;
		}
		++block_number;
	}

	return 0;
}

int Blockbuf::underflow()
{
	return read_block();
}

std::streamsize Blockbuf::showmanyc()
{
	return eof ? -1 : 0;
}


bool Blockbuf::flush_current(bool last)
{
	// Save the bytes that we have cumulated till now.
	ptrdiff_t count = pptr() - &buf[block_filler];

	if (block_number <= last_block_written && payload_bytes + block_filler != block_size) {
		// We are somewhere in the middle of the file after a seek.
		std::vector<char> current(count);
		memcpy(&current[0], &buf[block_filler], count);

		std::streampos pos = io->pubseekoff(0, std::ios_base::cur, std::ios_base::in | std::ios_base::out);
		uint64_t saved_nonce = nonce64;
		size_t saved_bn = block_number;
		read_block();
		nonce64 = saved_nonce;
		block_number = saved_bn;
		io->pubseekpos(pos, std::ios_base::in | std::ios_base::out);
		memcpy(&buf[block_filler], &current[0], count);

		// We now have a block with the first bytes having the data that we
		// just wrote and the last bytes are the data that was written to the
		// file before the seek.
	}

	ptrdiff_t mlen = pptr() - &buf[0];
	if (payload_bytes + block_filler > size_t(mlen)) {
		mlen = payload_bytes + block_filler;
	}

	uint8_t type = block_number == 0 ? 1 : 2;
	uint64_t nm = 0;
	if (block_number >= last_block_written || last) {
		if (size_t(mlen) != block_size) {
			type = 3;
			nm = ndelta;
			if (nonce64 >= ndelta - 1) {
				throw_rte (_("Trying to encode more than 2⁶³ packets."));
			}
		}
	}
	krand.get_bytes (&buf[0], block_filler);
	encrypt_multi((uint8_t*)&buf[0], (uint8_t*)&buf[0], mlen, &type, 1,
	              keyw, &kaw[0], nka, (nonce64++) + nm);

	ptrdiff_t request = mlen + 16*nka;

	if (io->sputn(&buf[0], request) != request) {
		error_info = _("Can't write encrypted data to final destination.");
		if (owner_os) {
			owner_os->setstate(std::ios_base::badbit);
		}
		return type == 3;
	}
	setp(&buf[block_filler], &buf[block_size]);
	payload_bytes = 0;
	if (last_block_written < block_number) {
		last_block_written = block_number;
	}
	++block_number;

	return type == 3;
}


void Blockbuf::close()
{
	if (closed) return;
	if (writing) {
		// Save the bytes that we have cumulated till now.

		if (block_number < last_block_written) {
			seekoff(last_block_written * (block_size - block_filler), std::ios_base::beg,
			        std::ios_base::out);
		}
		if (!flush_current(true)) {
			uint8_t type = 3;
			uint64_t nm = ndelta;
			size_t mlen = block_filler;
			encrypt_multi((uint8_t*)&buf[0], (uint8_t*)&buf[0], mlen, &type, 1,
			              keyw, &kaw[0], nka, (nonce64++) + nm);

			io->sputn(&buf[0], mlen + 16 * (nka == 0 ? 1 : nka));
			setp(&buf[block_filler], &buf[block_size]);
			++block_number;
		}
	}
	closed = true;
}


std::streampos
Blockbuf::seekpos(std::streampos pos, std::ios_base::openmode which)
{
	return this->seekoff(std::streamoff(pos), std::ios_base::beg, which);
}



void Blockbuf::write_sym_header(std::streambuf *io,
        const char *pass, size_t npass,
        const uint8_t salt[32], unsigned block_size,
        unsigned block_filler, int shifts, Chakey *kw, uint64_t *nonce64)
{
	unsigned char key[32];

	scrypt_blake2b (key, sizeof key, pass, npass, salt, 32, shifts);
	load (kw, key);
	*nonce64 = 0;

	io->sputn((char*)salt, 32);

	uint8_t blocks[8], enc[24];
	leput32 (blocks, block_size);
	leput32 (blocks + 4, block_filler);
	encrypt_one (enc, blocks, sizeof blocks, NULL, 0, *kw, (*nonce64)++);
	io->sputn((char*)enc, 24);
}


void create_hsx (const Cu25519Pair &tx, const Cu25519Ris &rx, const uint8_t symk[33],
                 std::vector<uint8_t> &out, Chakey *ka, Chacha &krand, bool spoofed=false)
{
	Symmetric s;
	s.initialize ("Noise_X_25519_ChaChaPoly_BLAKE2s");
	s.mix_hash (NULL, 0);   // prologue
	s.mix_hash (spoofed ? tx.xp.b : rx.b, 32);
	Cu25519Sec es;
	Cu25519Mon ep;
	Cu25519Ell er;
	krand.copy (es.b, 32);
	cu25519_elligator2_gen (&es, &ep, &er);
	out.resize (32);
	memcpy (&out[0], er.b, 32);
	s.mix_hash (er.b, 32);
	uint8_t sh[32];
	if (spoofed) {
		cu25519_shared_secret (sh, tx.xp, es);
	} else {
		cu25519_shared_secret (sh, rx, es);
	}
	s.mix_key (sh, 32);
	s.encrypt_and_hash (spoofed ? rx.b : tx.xp.b, 32, out);
	cu25519_shared_secret (sh, rx, tx.xs);
	s.mix_key (sh, 32);
	s.encrypt_and_hash (symk, 33, out);
	s.split (ka);
}


void Blockbuf::write_pub_header (std::streambuf *io, unsigned block_size,
        unsigned block_filler, const Cu25519Pair &tx,
        const std::vector<Cu25519Ris> &rx,
        Chakey *kw, uint64_t *nonce64, std::vector<Chakey> &kav,
        bool spoof, uint32_t info_size)
{
	Handshake hsg;
	hsg.initialize (hsg.X, NULL, 0, true);
	hsg.set_s (tx, false);

	uint8_t symk[33];
	krand.get_bytes (symk, 32);
	symk[32] = rx.size();

	std::vector<uint8_t> out;
	kav.resize (rx.size());

	if (spoof) {
		create_hsx (tx, rx[0], symk, out, &kav[0], krand, true);
		io->sputn ((char*) &out[0], out.size());
		for (unsigned i = 1; i < rx.size(); ++i) {
			char dummy[129];
			krand.get_bytes (dummy, sizeof dummy);
			io->sputn (dummy, sizeof dummy);
			krand.get_bytes (kav[i].kw, 32);
		}
	} else {
		for (unsigned i = 0; i < rx.size(); ++i) {
			create_hsx (tx, rx[i], symk, out, &kav[i], krand);
			io->sputn ((char*)&out[0], out.size());
		}
	}
	load (kw, symk);
	*nonce64 = 0;
	out.resize (12 + rx.size() * 16);
	uint8_t pt[12];
	leput32 (pt, block_size);
	leput32 (pt + 4, block_filler);
	leput32 (pt + 8, info_size);
	encrypt_multi (&out[0], pt, 12, NULL, 0, *kw, &kav[0], kav.size(), (*nonce64)++);

	io->sputn((char*) &out[0], out.size());
}


enum { block_size_def = 1 << 12,
       mask_bs = block_size_def - 1,
     };

static void adjust_bsbf (ptrdiff_t *bs, ptrdiff_t *bf)
{
	if (*bs < 0) {
		uint32_t bz;
		randombytes_buf((uint8_t*)&bz, sizeof bz);
		*bs = block_size_def + (bz & mask_bs);
	}
	if (*bf < 0 || *bf >= *bs) {
		uint32_t bz;
		randombytes_buf((uint8_t*)&bz, sizeof bz);
		// Ensure that the maximum possible expansion is to 3 times the
		// plaintext size. This does not apply for files which fit within a
		// single block.
		*bf = *bs * 2.0/3.0 * bz / 0x100000000;
		assert (*bf < *bs);
	}
}



// Init a symmetric encrypting block buffer.
void Blockbuf::init_write (std::streambuf *sb, const char *password,
                           ptrdiff_t bs, ptrdiff_t bf, int sh)
{
	// We ensure that all the random number generation is also keyed with the
	// password. We will have at least the unpredictability of the password
	// as entropy source. See the class Keyed_random.

	krand.reset (password, strlen(password));
	adjust_bsbf (&bs, &bf);

	Chakey kw;
	uint64_t nonce64;
	uint8_t  salt[32];

	krand.get_bytes(salt, sizeof salt);

	shifts = sh;
	write_sym_header(sb, password, strlen(password), salt, bs, bf, shifts,
	                 &kw, &nonce64);
	// No info block. It is reserved for future expansion.
	init(kw, nonce64, bs, bf, sb);
	set_adw(&kw, 1);
	set_writing();
}


void Blockbuf::init_write (std::streambuf *sb, const Cu25519Pair &tx,
                           const std::vector<Cu25519Ris> &rx, ptrdiff_t bs,
                           ptrdiff_t bf)
{
	// We ensure that all the random number generation is also keyed with the
	// secret key of the sender. We will have at least the unpredictability
	// of the secret key as entropy source. See the class Keyed_random. If
	// the sender remains anonymous then the txsec will be all zeros and no
	// additional entropy will be contributed by the sender key. In the case
	// of an anonymous sender we are dependent on the system's random number
	// generator.
	krand.reset (tx.xs.b, 32);
	adjust_bsbf (&bs, &bf);

	Chakey kw;
	uint64_t nonce64;
	std::vector<Chakey> kv;

	write_pub_header(sb, bs, bf, tx, rx, &kw, &nonce64, kv);
	init(kw, nonce64, bs, bf, sb);
	set_writing();
	set_adw(&kv[0], rx.size());
}



void Blockbuf::init_spoof(std::streambuf *sb, const Cu25519Pair &rxpair,
                          const Cu25519Ris &txpub,
                          int ndummies, ptrdiff_t bs, ptrdiff_t bf)
{
	krand.reset (rxpair.xs.b, 32);
	adjust_bsbf (&bs, &bf);

	uint64_t nonce64;
	Chakey kw;

	Cu25519Sec dummysec;
	krand.get_bytes(dummysec.b, 32);

	std::vector<Cu25519Ris> rx(ndummies + 1);
	for (int i = 0; i < ndummies; ++i) {
		krand.get_bytes(rx[i + 1].b, 32);
	}
	rx[0] = txpub;

	std::vector<Chakey> ka(ndummies);

	write_pub_header (sb, bs, bf, rxpair, rx, &kw, &nonce64, ka, true);
	init (kw, nonce64, bs, bf, sb);
	set_writing();
	set_adw(&ka[0], rx.size());
}

struct Sym_info {
	uint8_t nonce[24], key[32];
	std::streamoff loc;
};

static
void read_sym_header(std::streambuf *io, const char *password, Chakey *kw,
                     uint64_t *nonce64, ptrdiff_t *bs, ptrdiff_t *bf,
                     int *shifts, int shifts_max, Sym_info *info=NULL)
{
	uint8_t salt[32], blocks_enc[24];
	if (io->sgetn((char*)salt, 32) != 32) {
		throw_rte(_("The file is too short. Could not read the salt."));
	}
	if (io->sgetn((char*)blocks_enc, 24) != 24) {
		throw_rte(_("The file is too short. Could not read the block size."));
	}

	unsigned char key[32];
	uint8_t blocks[8];
	*nonce64 = 0;

	try {
		for (*shifts = 0; *shifts <= shifts_max; ++*shifts) {
			scrypt_blake2b (key, sizeof key, password, strlen(password), salt, 32,
			                *shifts);
			load (kw, key);
			*nonce64 = 0;
			if (decrypt_one(blocks, blocks_enc, 24, NULL, 0, *kw, *nonce64) == 0) {
				break;
			}
		}
	} catch (std::bad_alloc &) {
		// We may run out of memory while trying big values of shifts.
		throw_rte(_("Wrong decryption of parameter block. Wrong password?"));
	}

	if (*shifts == shifts_max + 1) {
		throw_rte(_("Wrong decryption of parameter block. Wrong password?"));
	}
	++(*nonce64);
	if (info) memcpy(info->key, key, 32);

	*bs = leget32(&blocks[0]);
	*bf = leget32(&blocks[4]);

	if (*bf >= *bs) {
		throw_rte(_("There is more filler, %d, than block space, %d."), *bf, *bs);
	}
	enum { block_max = 10000000 };
	if (*bs > block_max) {
		throw_rte(_("Block size is too big, %d. We accept up to %d."), *bs, block_max);
	}
}



static
void read_pub_header (std::streambuf *io, const Cu25519Pair &rx,
            Cu25519Ris *sender, Chakey *ka, int *nrx, int *keypos,
            ptrdiff_t *bs, ptrdiff_t *bf, Chakey *kn, uint64_t *nonce64,
            uint32_t *info_size)
{
	Handshake hsg (hsg.X, NULL, 0, true);
	hsg.set_s (rx, true);
	uint8_t ct[32 + 48 + 49];
	std::vector<uint8_t> pay, ctv;
	unsigned i;

	*keypos = -1;
	for (i = 0; i < 256; ++i) {
		if (io->sgetn ((char*)ct, sizeof ct) != sizeof ct) {
			throw_rte(_("This message is not addressed to me. End of file reached."));
		}
		Handshake hs (hsg);
		if (hs.read_message (ct, sizeof ct, pay) != 0) {
			continue;
		}
		if (pay.size() != 33) {
			throw_rte (_("Wrong payload length."));
		}
		load (kn, &pay[0]);
		*keypos = i;
		*nrx = pay[32];
		hs.split (ka);
		*sender = *hs.get_rs();
		break;
	}
	if (*keypos == -1) {
		throw_rte (_("This message is not addressed to me. Tried up to 256 recipients."));
	}
	for (int i = *keypos + 1; i < *nrx; ++i) {
		if (io->sgetn ((char*)ct, sizeof ct) != sizeof ct) {
			throw_rte(_("Error reading header."));
		}
	}

	ctv.resize (12 + *nrx * 16);
	if (io->sgetn ((char*)&ctv[0], ctv.size()) != (ptrdiff_t)ctv.size()) {
		throw_rte(_("Bad format in header."));
	}
	uint8_t pt[12];
	*nonce64 = 0;
	if (decrypt_multi (pt, &ctv[0], ctv.size(), NULL, 0, *kn, *ka, *nrx, *keypos, (*nonce64)++) != 0) {
		throw_rte (_("Wrong key in header."));
	}
	*bs = leget32 (pt);
	*bf = leget32 (pt + 4);
	*info_size = leget32 (pt + 8);
}

enum { default_shifts_max = 20 };

void Blockbuf::init_read (std::streambuf *sb, const char *password, int shifts_max)
{
	Chakey kw;
	uint64_t nonce64;
	ptrdiff_t bs, bf;
	if (shifts_max == 0) {
		shifts_max = default_shifts_max;
	}
	read_sym_header(sb, password, &kw, &nonce64, &bs, &bf, &shifts, shifts_max);
	init(kw, nonce64, bs, bf, sb);
	set_adr(kw, 1, 0);
}

void Blockbuf::init_read (std::streambuf *sb, const Cu25519Pair &rx,
                          Cu25519Ris *sender, int *nrx)
{
	Chakey kw;
	uint64_t nonce64;
	ptrdiff_t bs, bf;
	int keypos;
	Chakey ka;
	uint32_t info_size;

	read_pub_header(sb, rx, sender, &ka, nrx,
	                &keypos, &bs, &bf, &kw, &nonce64, &info_size);

	if (info_size != 0) {
		// If there is an info block after the block sizes read it. We don't
		// use it yet but we ignore it if it is present. Its presence means
		// that we are using older software to process a new version.
		size_t toread = info_size + *nrx * 16;
		std::vector<uint8_t> info;
		info.resize (toread);
		if (sb->sgetn ((char*)&info[0], toread) != (std::streamsize) toread) {
			throw_rte (_("Bad format in header."));
		}
		if (decrypt_multi (&info[0], &info[0], info.size(), NULL, 0, kw, ka, *nrx, keypos, nonce64++) != 0) {
			throw_rte (_("Bad decryption of extra parameter block"));
		}
		// Nothing implemented yet.
		// process_info (&info[0], info_size);
	}
	init(kw, nonce64, bs, bf, sb);
	set_adr(ka, *nrx, keypos);
}



void insert_icryptbuf(std::istream &is, Blockbuf *bb)
{
	is.rdbuf(bb);
	bb->set_owner(&is);
}

ocryptwrap::ocryptwrap(Blockbuf *bb)
	: std::ostream(bb)
	, buf(bb)
{
	bb->set_owner(this);
}

ocryptwrap::~ocryptwrap()
{
	flush();
	buf->close();
}

void ocryptwrap::close()
{
	flush();
	buf->close();
}




ofstream::ofstream()
	: std::ostream(&bbe)
{
	exceptions(std::ios_base::badbit);
}

ofstream::ofstream(const char *name, const char *password, ptrdiff_t bs,
                   ptrdiff_t bf, int shifts)
	: std::ostream(&bbe)
{
	exceptions(std::ios_base::badbit);
	open(name, password, bs, bf, shifts);
}


ofstream::ofstream(const char *name, const Cu25519Pair &tx,
                   const std::vector<Cu25519Ris> &rx,
                   ptrdiff_t bs, ptrdiff_t bf)
	: std::ostream(&bbe)
{
	exceptions(std::ios_base::badbit);
	open(name, tx, rx, bs, bf);
}

ofstream::~ofstream()
{
	close();
}



void ofstream::open(const char *name, const char *password, ptrdiff_t bs,
                    ptrdiff_t bf, int shifts)
{

	try {
		os.clear();
		bbe.clear();
		os.open(name, os.binary | os.in | os.out | os.trunc);
		if (!os) {
			setstate(badbit);
			throw_rte (_("Could not open the underlying file for %s."), name);
		}
		bbe.init_write(os.rdbuf(), password, bs, bf, shifts);
		bbe.set_owner(this);
	} catch (...) {
		throw_nrte (_("Could not open the encrypted file %s for writing."), name);
	}
}


void ofstream::open(const char *name, const Cu25519Pair &tx,
                    const std::vector<Cu25519Ris> &rx, ptrdiff_t bs,
                    ptrdiff_t bf)
{
	try {
		os.open(name, os.binary | os.in | os.out | os.trunc);
		if (!os) {
			setstate(badbit);
			throw_rte (_("Coult not open the underlying file %s"), name);
		}
		bbe.init_write(os.rdbuf(), tx, rx, bs, bf);
		bbe.set_owner(this);
	} catch (...) {
		throw_nrte (_("Could not open the encrypted file %s for writing."), name);
	}
}


void ofstream::open_spoof(const char *name, const Cu25519Pair &rx,
                          const Cu25519Ris &txpub,
                          int ndummies, ptrdiff_t bs, ptrdiff_t bf)
{
	try {
		os.open(name, os.binary | os.in | os.out | os.trunc);
		if (!os) {
			setstate(badbit);
			throw_rte (_("Coult not open the underlying file %s"), name);
		}
		bbe.init_spoof(os.rdbuf(), rx, txpub, ndummies, bs, bf);
		bbe.set_owner(this);
	} catch (...) {
		throw_nrte (_("Could not open the encrypted file %s for writing."), name);
	}
}


void ofstream::close()
{
	os.flush();
	bbe.close();
	os.close();
}



ifstream::ifstream()
	: std::istream(&bbe)
{
	exceptions(std::ios_base::badbit);
}

ifstream::ifstream(const char *name, const char *password, int shifts_max)
	: std::istream(&bbe)
{
	exceptions(std::ios_base::badbit);
	open(name, password, shifts_max);
}


ifstream::ifstream(const char *name, const char *password, std::nothrow_t, int shifts_max)
	: std::istream(&bbe)
{
	exceptions(std::ios_base::badbit);
	open(name, password, std::nothrow, shifts_max);
}


ifstream::ifstream(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx)
	: std::istream(&bbe)
{
	exceptions(std::ios_base::badbit);
	open(name, rx, sender, nrx);
}

ifstream::ifstream(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx,
                   std::nothrow_t)
	: std::istream(&bbe)
{
	exceptions(std::ios_base::badbit);
	open(name, rx, sender, nrx, std::nothrow);
}


void ifstream::open(const char *name, const char *password, int shifts_max)
{
	try {
		is.open(name, is.binary);
		if (!is) {
			setstate(badbit);
			throw_rte (_("Could not open the underlying file %s"), name);
		}
		bbe.init_read(is.rdbuf(), password, shifts_max);
		bbe.set_owner(this);
	} catch (...) {
		throw_nrte (_("Cannot open the encrypted file %s"), name);
	}
}

void ifstream::open(const char *name, const char *password, std::nothrow_t, int shifts_max)
{
	try {
		open(name, password, shifts_max);
	} catch (std::exception &e) {
		bbe.error_info = describe(e);
		clear(this->failbit);
	} catch (...) {
		bbe.error_info = _("Unknown exception has been caught.\n");
		clear(this->failbit);
	}
}


void ifstream::open(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx)
{
	try {
		is.open(name, is.binary);
		if (!is) {
			setstate(badbit);
			throw_rte (_("Could not open the underlying file %s"), name);
		}
		bbe.init_read(is.rdbuf(), rx, sender, nrx);
		bbe.set_owner(this);
	} catch (...) {
		throw_nrte (_("Could not open the encrypted file %s"), name);
	}
}

void ifstream::open(const char *name, const Cu25519Pair &rx, Cu25519Ris *sender, int *nrx, std::nothrow_t)
{
	try {
		open(name, rx, sender, nrx);
	} catch (std::exception &e) {
		bbe.error_info = describe(e);
		clear(this->failbit);
	} catch (...) {
		bbe.error_info = _("Unknown exception has been caught.\n");
		clear(this->failbit);
	}
}



void ifstream::close()
{
	is.close();
	bbe.close();
}

void ifstream::clear(std::ios_base::iostate state)
{
	std::istream::clear(state);
	is.clear(state);
	bbe.clear();
}

enum { tagsz = 16 };

static void hide_common(const char *bogus, const char *real,
                        std::ostream &os, const Chakey &kw9,
                        const Chakey &innerkw, uint64_t n64,
                        uint64_t innern64, int bs, int bf, Blockbuf &bbe)
{
	std::ifstream is1(bogus, is1.binary);
	std::ifstream is2(real, is2.binary);
	is1.seekg(0, is1.end);
	is2.seekg(0, is2.end);
	std::streamoff sz1 = is1.tellg();
	std::streamoff sz2 = is2.tellg();

	if (sz1/(bs - bf) < (sz2 + 8)/(bf - (int)tagsz)) {
		throw_rte(_("There is no space to hide the second file. Increase the slack space. sz1=%d sz2=%d  bs=%d bf=%d"),
		        sz1, sz2, bs, bf);
	}

	const Chakey *kaw = bbe.get_kaw();
	size_t nka = bbe.get_nka();
	uint8_t ad;
	size_t ntags = nka != 0 ? nka : 1;

	std::vector<uint8_t> buf(bs + ntags * 16);
	is1.seekg(0);
	is2.seekg(0);

	randombytes_buf(&buf[0], bs);
	leput64 (&buf[0], sz2);
	is2.read((char*)&buf[8], bf - 8 - tagsz);
	is1.read((char*)&buf[bf], bs - bf);

	uint64_t nm;
	// Hide first block.
	if (is1.gcount() > 0 || is2.gcount() > 0) {
		encrypt_one(&buf[0], &buf[0], bf - tagsz, NULL, 0, innerkw, innern64++);
		if (is1.gcount() == bs - bf) {
			ad = 1;
			nm = 0;
		} else {
			ad = 3;
			nm = ndelta;
		}
		encrypt_multi (&buf[0], &buf[0], bf + is1.gcount(), &ad, 1,
		               kw9, kaw, nka, (n64++) + nm);
		os.write((const char*)&buf[0], bf + is1.gcount() + 16 * ntags);
	}

	for (;;) {
		is2.read((char*)&buf[0], bf - tagsz);
		is1.read((char*)&buf[bf], bs - bf);

		if (is1.gcount() == 0 && is2.gcount() == 0) break;

		encrypt_one(&buf[0], &buf[0], bf - tagsz, NULL, 0, innerkw, innern64++);
		if (is1.gcount() == bs - bf) {
			ad = 2;
			nm = 0;
		} else {
			ad = 3;
			nm = ndelta;
		}
		encrypt_multi (&buf[0], &buf[0], bf + is1.gcount(), &ad, 1,
		               kw9, kaw, nka, (n64++) + nm);
		os.write((const char*)&buf[0], bf + is1.gcount() + 16 * ntags);
	}

	if (ad != 3) {
		ad = 3;
		encrypt_multi(&buf[0], &buf[0], bf + is1.gcount(), &ad, 1, kw9, kaw, nka, n64++ + ndelta);
		os.write((const char*)&buf[0], bf + 16 * ntags);
	}
}

void hide (const char *ename, const char *bogus, const char *real,
           const char *pass1, const char *pass2, int bs, int bf, int shifts)
{
	std::ofstream os (ename, os.binary);
	if (!os) {
		throw_rte (_("Cannot open the output file %s"), ename);
	}

	Blockbuf bbe;
	bbe.init_write (os.rdbuf(), pass1, bs, bf, shifts);
	bs = bbe.get_block_size();
	bf = bbe.get_block_filler();

	if (bf <= int(8 + tagsz)) {
		throw_rte (_("The block filler size is too small."));
	}

	const Chakey *kw = bbe.get_key();
	uint64_t n64 = bbe.get_nonce64();
	uint8_t salt[32];
	for (unsigned i = 0; i < 6; ++i) {
		leput32 (salt + i*4, kw->kw[i]);
	}
	leput64 (salt + 24, n64);
	uint8_t innerkey[32];
	Chakey innerkw;
	uint64_t innern64;
	scrypt_blake2b (innerkey, sizeof innerkey, pass2, strlen(pass2), salt, 32, shifts);
	load (&innerkw, innerkey);
	innern64 = 0;

	hide_common (bogus, real, os, *kw, innerkw, n64, innern64, bs, bf, bbe);
}


void hide (const char *ename, const char *bogus, const char *real,
           const Cu25519Pair &tx, const std::vector<Cu25519Ris> &rx,
           const Cu25519Ris &rx2, int bs, int bf)
{
	std::ofstream os (ename, os.binary);
	if (!os) {
		throw_rte (_("Cannot open the output file %s"), ename);
	}

	Blockbuf bbe;
	bbe.init_write (os.rdbuf(), tx, rx, bs, bf);
	bs = bbe.get_block_size();
	bf = bbe.get_block_filler();

	if (bf <= int(8 + tagsz)) {
		throw_rte (_("The block filler size is too small."));
	}

	const Chakey *kw = bbe.get_key();
	uint8_t kwle[32];
	for (int i = 0; i < 8; ++i) {
		leput32 (kwle + i*4, kw->kw[i]);
	}

	uint8_t sh[32];
	cu25519_shared_secret (sh, rx2, tx.xs);
	// Mix ss and the outer encryption key (treated as nonce).
	mix_key (sh, kwle, 32);
	Chakey innerkw;
	load (&innerkw, sh);

	hide_common (bogus, real, os, *kw, innerkw, bbe.get_nonce64(), 0, bs, bf, bbe);
}

static
void reveal_common(const char *oname, std::istream &is,
                   const Chakey &kw, const Chakey &innerkw,
                   uint64_t n64, uint64_t innern64, int bs, int bf,
                   Blockbuf &bbe)
{
	std::ostream *pos = &std::cout;
	std::ofstream fos;
	if (strcmp(oname, "-") != 0) {
		fos.open(oname, fos.binary);
		if (!fos) {
			throw_rte(_("Cannot open the output file %s"), oname);
		}
		pos = &fos;
	}

	const Chakey *kar = bbe.get_kar();
	size_t nka = bbe.get_nka();
	size_t ika = bbe.get_ika();

	std::vector<uint8_t> buf(bs + 16*nka);
	is.seekg(is.rdbuf()->pubseekoff(0, is.cur, is.in));

	is.read((char*)&buf[0], bs + 16*nka);
	if (is.gcount() < (std::streamsize)bf) {
		throw_rte(_("The input file is too small."));
	}

	uint8_t ad;
	uint64_t nm;
	if (is.gcount() == std::streamsize(bs + 16*nka)) {
		ad = 1;
		nm = 0;
	} else {
		ad = 3;
		nm = ndelta;
	}

	if (0 != decrypt_multi(&buf[0], &buf[0], is.gcount(), &ad, 1, kw, *kar, nka, ika, (n64++) + nm)) {
		throw_rte(_("Error in the outer decryption in first block. Wrong first password?"));
	}

	if (0 != decrypt_one(&buf[0], &buf[0], bf, NULL, 0, innerkw, innern64++)) {
		throw_rte(_("Error in the inner decryption in first block. Wrong second password or no second file?"));
	}

	std::streamsize flen = leget64 (&buf[0]);
	if (flen > std::streamsize(bf - 8 - tagsz)) {
		pos->write((char*)&buf[8], bf - 8 - tagsz);
		flen -= bf - 8 - tagsz;
	} else {
		pos->write((char*)&buf[8], flen);
		flen = 0;
	}

	while (is) {
		is.read((char*)&buf[0], bs + 16*nka);
		if (is.gcount() < std::streamsize(bf)) {
			throw_rte(_("The input file is too small."));
		}
		if (is.gcount() == std::streamsize(bs + 16*nka)) {
			ad = 2;
			nm = 0;
		} else {
			ad = 3;
			nm = ndelta;
		}
		if (0 != decrypt_multi(&buf[0], &buf[0], is.gcount(), &ad, 1, kw, *kar, nka, ika, (n64++) + nm)) {
			throw_rte(_("Error in the outer decryption. Wrong first password?"));
		}

		if (0 != decrypt_one(&buf[0], &buf[0], bf, NULL, 0, innerkw, innern64++)) {
			throw_rte(_("Error in the inner decryption. Wrong second password or no second file?"));
		}

		if (flen > std::streamsize(bf - tagsz)) {
			pos->write((char*)&buf[0], bf - tagsz);
			flen -= bf - tagsz;
		} else {
			pos->write((char*)&buf[0], flen);
			flen = 0;
		}
	}
}


void reveal (const char *oname, const char *iname, const char *pass1,
             const char *pass2, int shifts_max)
{
	std::ifstream is(iname, is.binary);
	if (!is) {
		throw_rte(_("Cannot open the input file %s"), iname);
	}

	Blockbuf bbe;
	bbe.init_read(is.rdbuf(), pass1, shifts_max);

	size_t bs = bbe.get_block_size();
	size_t bf = bbe.get_block_filler();
	const Chakey *kw = bbe.get_key();
	uint64_t n64 = bbe.get_nonce64();

	uint8_t salt[32];
	for (unsigned i = 0; i < 6; ++i) {
		leput32 (salt + i*4, kw->kw[i]);
	}
	leput64 (salt + 24, n64);
	uint8_t innerkey[32];
	Chakey innerkw;
	uint64_t innern64;
	scrypt_blake2b (innerkey, sizeof innerkey, pass2, strlen(pass2),
	                salt, 32, bbe.get_shifts());
	load (&innerkw, innerkey);
	innern64 = 0;
	reveal_common(oname, is, *kw, innerkw, n64, innern64, bs, bf, bbe);
}


void reveal(const char *oname, const char *iname, const Cu25519Pair &rx1,
            const Cu25519Sec &rx2, Cu25519Ris *sender, int *nrx)
{
	std::ifstream is(iname, is.binary);
	if (!is) {
		throw_rte(_("Cannot open the input file %s"), iname);
	}

	Blockbuf bbe;
	bbe.init_read(is.rdbuf(), rx1, sender, nrx);

	size_t bs = bbe.get_block_size();
	size_t bf = bbe.get_block_filler();
	const Chakey *kw = bbe.get_key();
	uint64_t n64 = bbe.get_nonce64();

	uint8_t kwle[32];
	for (int i = 0; i < 8; ++i) {
		leput32 (kwle + i*4, kw->kw[i]);
	}

	uint8_t sh[32];
	cu25519_shared_secret (sh, *sender, rx2);
	// Mix ss and the outer encryption key (treated as nonce).
	mix_key (sh, kwle, 32);
	Chakey innerkw;
	load (&innerkw, sh);

	reveal_common (oname, is, *kw, innerkw, n64, 0, bs, bf, bbe);
}

}}


