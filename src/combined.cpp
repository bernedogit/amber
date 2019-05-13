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



#include "combined.hpp"
#include "hasopt.hpp"
#include "misc.hpp"
#include <fstream>
#include "blockbuf.hpp"
#include "blake2.hpp"
#include "protobuf.hpp"
#include <string.h>
#include <iomanip>


namespace amber {   namespace AMBER_SONAME {

static const char armor_beg[] = "------------AMBER ARMOR BEGIN--------------";
static const char armor_end[] = "------------AMBER ARMOR END----------------";


void sym_encrypt (const char *iname, const char *oname, std::string &password,
                  int bs, int bf, int shifts, bool wipe)
{
	std::ios_base::openmode mode = std::ios_base::in | std::ios_base::binary;
	if (wipe) {
		mode |= std::ios_base::out;
	}
	std::fstream is(iname, mode);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), iname);
	}
	if (password.empty()) {
		get_password (_("Password for output file: "), password);
		std::string p2;
		get_password (_("Repeat the password: "), p2);
		if (password != p2) {
			throw_rte (_("The supplied passwords do not match!\n"));
		}
	}
	amber::ofstream os(oname, password.c_str(), bs, bf, shifts);
	if (!os) {
		throw_rte (_("Error while opening output file %s"), oname);
	}
	char buf[100000];
	Janitor jan(buf, sizeof buf);
	unsigned long long count = 0;
	while (is) {
		is.read(buf, sizeof buf);
		os.write(buf, is.gcount());
		count += is.gcount();
	}

	if (wipe) {
		is.clear();
		is.seekp(0, is.beg);
		Keyed_random kr(iname, strlen(iname));
		while (count > 0) {
			size_t nw = count > sizeof buf ? sizeof buf : count;
			kr.get_bytes(buf, nw);
			is.write(buf, nw);
			count -= nw;
		}
	}
}

void sym_decrypt(const char *iname, const char *oname, std::string &password,
                 bool verbose, int shifts_max)
{
	try {
		if (password.empty()) {
			get_password("Password for input file: ", password);
		}
		amber::ifstream is(iname, password.c_str(), shifts_max);
		// We don't want exceptions to be thrown on decryption errors.
		// Instead we explicitely check for badbit and throw an exception
		// with a better error messsage.
		is.exceptions(std::ios_base::goodbit);
		if (!is) {
			throw_rte (_("Error while opening encrypted input file %s"), iname);
		}
		if (verbose) {
			format(std::cout, _("block size: %d, block filler size: %d  shifts=%d\n"),
			       is.get_block_size(), is.get_block_filler(), is.get_shifts());
		}

		if (strcmp(oname, "-") == 0) {
			char buf[100000];
			Janitor jan(buf, sizeof buf);
			while (is) {
				is.read(buf, sizeof buf);
				std::cout.write(buf, is.gcount());
			}
			if (is.bad()) {
				throw_rte(
					_("Error while decrypting the input file %s. The file has been tampered with.\n%s"),
					iname, is.get_error_info());
			}
		}

		std::ofstream os(oname, is.binary);
		if (!os) {
			throw_rte (_("Error while opening output file %s"), oname);
		}

		char buf[100000];
		Janitor jan(buf, sizeof buf);
		while (is) {
			is.read(buf, sizeof buf);
			os.write(buf, is.gcount());
		}
		if (is.bad()) {
			os.close();
			remove(oname);
			throw_rte(
				_("Error while decrypting the input file %s. The file has been tampered with.\n%s"),
				iname, is.get_error_info());
		}
	} catch (...) {
		throw_nrte(_("Cannot decrypt the input file %s to the output file %s"), iname, oname);
	}
}



void pub_encrypt(const char *iname, const char *oname, const Key &sender,
                 const Key_list &rx, int bs, int bf, bool wipe)
{
	try {
		std::ios_base::openmode mode = std::ios_base::in | std::ios_base::binary;
		if (wipe) {
			mode |= std::ios_base::out;
		}
		std::fstream is(iname, mode);
		if (!is) {
			throw_rte(_("Error while opening input file %s"), iname);
		}

		if (rx.empty()) {
			throw_rte (_("Select at least one recipient."));
		}
		if (!sender.secret_avail) {
			throw_rte(_("The sender padlock has no private key."));
		}
		std::vector<Cu25519Ris> curx(rx.size());
		for (unsigned i = 0; i < rx.size(); ++i) curx[i] = rx[i].pair.xp;
		amber::ofstream os(oname, sender.pair, curx, bs, bf);
		if (!os) {
			throw_rte (_("Error while opening output file %s"), oname);
		}
		char buf[100000];
		Janitor jan(buf, sizeof buf);
		unsigned long long count = 0;
		while (is) {
			is.read(buf, sizeof buf);
			os.write(buf, is.gcount());
			count += is.gcount();
		}

		if (wipe) {
			is.clear();
			is.seekp(0, is.beg);
			Keyed_random kr(iname, strlen(iname));
			while (count > 0) {
				size_t nw = count > sizeof buf ? sizeof buf : count;
				kr.get_bytes(buf, nw);
				is.write(buf, nw);
				count -= nw;
			}
		}

	} catch (...) {
		throw_nrte(_("Could not encrypt %s to %s"), iname, oname);
	}
}


void pub_decrypt (const char *iname, const char *oname, const Key &rx,
                  Cu25519Ris &sender, int *nrx, bool verbose)
{
	try {
		if (!rx.secret_avail) {
			throw_rte(_("The decoding padlock has no private key."));
		}
		Key_list receiver;
		amber::ifstream is(iname, rx.pair, &sender, nrx);
		// We don't want exceptions to be thrown on decryption errors.
		// Instead we explicitely check for badbit and throw an exception
		// with a better error messsage.
		is.exceptions(std::ios_base::goodbit);
		if (!is) {
			std::ostringstream es;
			throw_rte(_("Error while opening encrypted input file %s %s"),
			                                iname, is.get_error_info());
		}
		if (verbose) {
			format(std::cout, _("block size: %d,  block filler size: %d\n"),
			       is.get_block_size(), is.get_block_filler());
		}

		if (strcmp(oname, "-") == 0) {
			char buf[100000];
			Janitor jan(buf, sizeof buf);
			while (is) {
				is.read(buf, sizeof buf);
				std::cout.write(buf, is.gcount());
			}
			if (is.bad()) {
				throw_rte(
					_("Error while decrypting the file %s. The file has been tampered with.\n%s"),
					iname, is.get_error_info());
			}
			return;
		}
		std::ofstream os(oname, os.binary);
		if (!os) {
			throw_rte (_("Error while opening output file %s."), oname);
		}
		char buf[100000];
		Janitor jan(buf, sizeof buf);
		while (is) {
			is.read(buf, sizeof buf);
			os.write(buf, is.gcount());
		}
		if (is.bad()) {
			os.close();
			remove(oname);
			throw_rte(_("Error while decrypting the file %s. The file has been tampered with.\n%s"),
			        iname, is.get_error_info());
		}
	} catch (...) {
		throw_nrte(_("Could not decrypt %s to %s."), iname, oname);
	}
}


void pub_spoof(const char *iname, const char *oname, const Key &rx,
               const Key_list &sender_dummies, int bs, int bf)
{
	try {
		if (!rx.secret_avail) {
			throw_rte(_("The spoofing padlock has no private key."));
		}
		std::ios_base::openmode mode = std::ios_base::in | std::ios_base::binary;
		std::fstream is(iname, mode);
		if (!is) {
			throw_rte(_("Error while opening input file %s"), iname);
		}

		amber::ofstream os;
		os.open_spoof(oname, rx.pair, sender_dummies[0].pair.xp,
		              sender_dummies.size() - 1, bs, bf);
		if (!os) {
			throw_rte (_("Error while opening output file %s"), oname);
		}
		char buf[100000];
		Janitor jan(buf, sizeof buf);
		unsigned long long count = 0;
		while (is) {
			is.read(buf, sizeof buf);
			os.write(buf, is.gcount());
			count += is.gcount();
		}
	} catch (...) {
		throw_nrte(_("Could not encrypt %s to %s"), iname, oname);
	}
}



static const char sig_anchor[] = "-----------AMBER SIGNED TEXT BEGIN------------";
static const char sig_begin[]  = "-----------AMBER SIGNATURE BEGIN--------------";
static const char sig_end[]    = "-----------AMBER SIGNATURE END----------------";
static const char sig_prefix[] = "Amber signature prefix";

enum { sig_group, sig_signer, sig_signature, sig_comment, sig_cert, sig_name, sig_ctime, sig_self, sig_date };

static void write_signature (Protobuf_writer &pw, const Key &signer,
                             const uint8_t sig[64], const char *comment,
                             time_t now, bool add_certs)
{
	pw.start_group (sig_group);

	pw.write_bytes (sig_signer, signer.pair.xp.b, 32);
	pw.write_bytes (sig_signature, sig, 64);
	if (comment && comment[0]) {
		pw.write_bytes (sig_comment, comment, strlen(comment));
	}
	pw.write_uint64 (sig_date, now);

	if (add_certs) {
		pw.write_bytes (sig_name, &signer.name[0], signer.name.size());
		pw.write_uint64 (sig_ctime, signer.creation_time);
		pw.write_bytes (sig_self, signer.self_signature, 64);

		for (unsigned i = 0; i < signer.sigs.size(); ++i) {
			pw.start_group (sig_cert);
			pw.write_bytes (sig_signer, signer.sigs[i].signer.b, 32);
			pw.write_bytes (sig_signature, signer.sigs[i].signature, 64);
			pw.end_group();
		}
	}
	pw.end_group();
}

static void read_one_sig (Protobuf_reader &pr, Key *key, uint8_t sig[64], std::string *cmt, time_t *date)
{
	uint32_t tagwt;
	uint64_t val;

	pr.add_requirement (sig_signer, pr.needed_once,
	                    sig_signature, pr.needed_once,
	                    sig_comment, pr.optional_once,
	                    sig_name, pr.optional_once,
	                    sig_ctime, pr.optional_once,
	                    sig_self, pr.optional_once);

	key->only_xpub = true;

	while (pr.read_tagval (&tagwt, &val, true)) {
		switch (tagwt) {
		case maketag (sig_signer, length_val):
			if (val != 32) {
				throw_rte ("The signer size is wrong");
			}
			pr.get_bytes (key->pair.xp.b, 32);
			break;

		case maketag (sig_signature, length_val):
			if (val != 64) {
				throw_rte ("The size of the signature is wrong.");
			}
			pr.get_bytes (sig, 64);
			break;

		case maketag (sig_comment, length_val):
			if (cmt) {
				cmt->resize (val);
				pr.get_bytes (&(*cmt)[0], val);
			} else {
				pr.skip (tagwt, val);
			}
			break;

		case maketag (sig_date, fixed64):
			if (date) {
				*date = val;
			}
			break;

		case maketag (sig_name, length_val):
			key->name.resize (val);
			pr.get_bytes (&key->name[0], val);
			key->only_xpub = false;
			break;

		case maketag (sig_ctime, fixed64):
			key->creation_time = val;
			key->only_xpub = false;
			break;

		case maketag (sig_self, length_val):
			if (val != 64) {
				throw_rte ("The size of the self signature is wrong.");
			}
			pr.get_bytes (key->self_signature, 64);
			key->only_xpub = false;
			break;

		case maketag (sig_cert, group_len):
			Signature s;
			pr.add_requirement (sig_signer, pr.needed_once, sig_signature, pr.needed_once);
			while (pr.read_tagval (&tagwt, &val)) {
				switch (tagwt) {
				case maketag (sig_signer, length_val):
					if (val != 32) {
						throw_rte ("The size of the signer is wrong");
					}
					pr.get_bytes (s.signer.b, 32);
					break;

				case maketag (sig_signature, length_val):
					if (val != 64) {
						throw_rte ("The size of the signature is wrong");
					}
					pr.get_bytes (s.signature, 64);
					break;

				default:
					pr.skip (tagwt, val);
				}
			}
			key->sigs.push_back (s);
			key->only_xpub = false;
			break;

		default:
			pr.skip (tagwt, val);
		}
	}
}

static void read_sig (Protobuf_reader &pr, Key *key, uint8_t sig[64], std::string *cmt, time_t *date)
{
	uint32_t tagwt;
	uint64_t val;

	while (pr.read_tagval (&tagwt, &val, true)) {
		switch (tagwt) {
		case maketag (sig_group, group_len):
			read_one_sig (pr, key, sig, cmt, date);
			break;

		default:
			pr.skip (tagwt, val);
		}
	}
}


static void add_certs_to_hash (Blake2b *bl, const Key &key)
{
	if (!key.name.empty()) {
		bl->update (key.name.c_str(), key.name.size(), true);
		bl->update (key.creation_time);
	}
	for (unsigned i = 0; i < key.sigs.size(); ++i) {
		bl->update (key.sigs[i].signer.b, 32);
		bl->update (key.sigs[i].signature, 64);
		bl->finish_item();
	}
}

void sign_file (const char *iname, const char *oname, const Key &signer, const char *comment, bool b64, bool add_certs)
{
	try {
		if (!signer.secret_avail) {
			throw_rte(_("The signing padlock has no private key."));
		}
		std::ifstream is(iname, is.binary);
		if (!is) {
			throw_rte (_("Error while opening input file %s."), iname);
		}

		std::ofstream os(oname, b64 ? os.out : os.binary);
		if (!os) {
			throw_rte (_("Error while opening output file %s."), oname);
		}
		char buf[100000];
		Blake2b bl;
		while (is) {
			is.read(buf, sizeof buf);
			bl.update (buf, is.gcount());
		}
		bl.finish_item();

		bl.update (comment, strlen(comment), true);

		time_t now = time(0);
		bl.update (now);

		if (add_certs) {
			add_certs_to_hash (&bl, signer);
		}

		unsigned char bh[64];
		bl.final (bh);
		uint8_t sig[64];
		cu25519_sign (sig_prefix, bh, 64, signer.pair.xp, signer.pair.xs, sig);

		Protobuf_writer pw (NULL, pw.seek, 0xFFFFFF);

		if (!b64) {
			pw.set_ostream (&os);
		}
		write_signature (pw, signer, sig, comment, now, add_certs);
		pw.flush();

		if (b64) {
			std::string sig64;
			Base64_encoder benc;
			const std::vector<char> &v (pw.get_buffer());
			benc.encode_append ((const unsigned char*)&v[0], v.size(), &sig64);
			benc.flush_append(&sig64);
			os << sig_begin << '\n';
			os << sig64 << '\n';
			os << sig_end << '\n';
		}
	} catch (...) {
		throw_nrte (_("Could not sign the file %s."), iname);
	}
}




int verify_file (const char *iname, const char *sname, Key &signer, std::string *comment, time_t *date, bool b64)
{
	try {
		std::ifstream is(iname, is.binary);
		if (!is) {
			throw_rte (_("Error while opening input file %s."), iname);
		}

		std::ifstream ss(sname, b64 ? ss.in : ss.binary);
		if (!ss) {
			throw_rte (_("Error while opening signature file %s."), sname);
		}
		char buf[100000];
		Blake2b bl;
		while (is) {
			is.read(buf, sizeof buf);
			bl.update (buf, is.gcount());
		}
		bl.finish_item();

		uint8_t sig[64];

		if (b64) {
			std::string ln;
			while (getline(ss, ln)) {
				if (ln == sig_begin) break;
			}
			if (ln != sig_begin) {
				throw_rte (_("Did not find a signature"));
			}

			Base64_decoder bdec;
			std::vector<uint8_t> sigbin;
			while (getline(ss, ln)) {
				if (ln == sig_end) {
					bdec.flush_append(&sigbin);
					Protobuf_reader pr ((const char*)&sigbin[0], sigbin.size());
					read_sig (pr, &signer, sig, comment, date);
					break;
				} else {
					bdec.decode_append(ln.c_str(), ln.size(), &sigbin);
				}
			}
			if (ln != sig_end) {
				throw_rte (_("Could not find the end of the signature"));
			}
		} else {
			Protobuf_reader pr(&ss);
			read_sig (pr, &signer, sig, comment, date);
		}

		bl.update (comment->c_str(), comment->size(), true);
		bl.update (*date);
		add_certs_to_hash (&bl, signer);

		unsigned char bh[64];
		bl.final (bh);

		// We check the signature of the document by the signer.
		if (0 != cu25519_verify (sig_prefix, bh, 64, sig, signer.pair.xp)) {
			return -1;
		}

		// We check the self signature. If we don't then Eve could take Bob's
		// working key, change its name and sign Bob's working key with her
		// master key. Then we would assume that the document was signed by
		// Eve, although it was signed by Bob. This is the same as GPG's
		// subkey cross certification.
		if (!signer.name.empty()) {
			hash_key (signer, bh);
			if (0 != cu25519_verify (get_sig_prefix(), bh, 64, signer.self_signature, signer.pair.xp)) {
			   return -1;
			}
		}

		return 0;
	} catch (...) {
		throw_nrte(_("Could not verify the signature %s of the file %s."),
		           sname, iname);
	}
	return 0;
}


static void trim_right(std::string *s)
{
	ptrdiff_t n = s->size();
	if (n == 0) return;
	ptrdiff_t i = n - 1;
	while (i >= 0 && isspace((*s)[i])) {
		--i;
	}
	s->erase(i + 1);
}



void clear_sign(const char *iname, const char *oname, const Key &signer, const char *comment, bool add_certs)
{
	try {
		if (!signer.secret_avail) {
			throw_rte(_("The signing padlock has no private key."));
		}
		std::ifstream is(iname);
		if (!is) {
			throw_rte (_("Error while opening input file %s."), iname);
		}

		std::ofstream os(oname);
		if (!os) {
			throw_rte (_("Error while opening output file %s."), oname);
		}

		Blake2b bl;
		std::string ln;
		os << sig_anchor << '\n';
		while (getline(is, ln)) {
			trim_right(&ln);
			bl.update (ln.c_str(), ln.size());
			os << ln << '\n';
		}
		bl.finish_item();

		if (comment) {
			bl.update (comment, strlen(comment), true);
		}

		time_t now = time(0);
		bl.update (now);

		if (add_certs) {
			add_certs_to_hash (&bl, signer);
		}

		unsigned char bh[64];
		bl.final (bh);

		uint8_t sig[64];
		cu25519_sign (sig_prefix, bh, 64, signer.pair.xp, signer.pair.xs, sig);
		Protobuf_writer pw (NULL, pw.seek, 50000);
		write_signature (pw, signer, sig, comment, now, add_certs);
		os << sig_begin << '\n';
		const std::vector<char> &v (pw.get_buffer());
		base64enc((const uint8_t*)&v[0], v.size(), ln, true, true);
		os << ln << '\n';
		os << sig_end << '\n';
	} catch (...) {
		throw_nrte(_("Could not clear sign the file %s."), iname);
	}
}

// Return 0 if the signature is valid.
int clear_verify (const char *name, Key &signer, std::string *comment, time_t *date)
{
	try {
		comment->clear();

		std::ifstream is(name);
		if (!is) {
			throw_rte (_("Error while opening input file %s."), name);
		}

		Blake2b bl;
		std::string ln;
		while (getline(is, ln) && ln != sig_anchor) ;
		while (getline(is, ln)) {
			trim_right(&ln);
			if (ln == sig_begin) break;
			bl.update (ln.c_str(), ln.size());
		}
		bl.finish_item ();

		if (ln == sig_begin) {
			std::string sigs;
			while (getline(is, ln) && ln != sig_end) {
				sigs += ln;
			}
			std::vector<uint8_t> sig;
			base64dec(sigs.c_str(), sig, sigs.size());
			Protobuf_reader pr ((const char*)&sig[0], sig.size());
			uint8_t signature[64];
			read_sig (pr, &signer, signature, comment, date);

			if (!comment->empty()) {
				bl.update (comment->c_str(), comment->size(), true);
			}
			bl.update (*date);

			add_certs_to_hash (&bl, signer);

			unsigned char bh[64];
			bl.final (bh);

			if (0 != cu25519_verify(sig_prefix, bh, 64, signature, signer.pair.xp)) {
				return -1;
			}

			if (!signer.name.empty()) {
				hash_key (signer, bh);
				if (0 != cu25519_verify (get_sig_prefix(), bh, 64, signer.self_signature, signer.pair.xp)) {
					return -1;
				}
			}

			return 0;
		}
		throw_rte (_("Did not find a signed text."));
	} catch(...) {
		throw_nrte(_("Could not clear verify the file %s."), name);
	}
	return 0;
}


void clear_sign_again(const char *name, const Key &signer, const char *comment, bool add_certs)
{
	std::string oname = name;
	oname += ".tmp";
	try {
		if (!signer.secret_avail) {
			throw_rte(_("The signing padlock has no private key."));
		}
		std::ifstream is(name);
		if (!is) {
			throw_rte (_("Error while opening input file %s."), name);
		}

		std::ofstream os(oname);
		if (!is) {
			throw_rte (_("Error while opening input file %s."), oname);
		}

		Blake2b bl;
		std::string ln;
		while (getline(is, ln) && ln != sig_anchor) {
			os << ln << '\n';
		}
		os << sig_anchor << '\n';
		while (getline(is, ln)) {
			if (ln == sig_begin) break;
			bl.update (ln.c_str(), ln.size());
			os << ln << '\n';
		}
		bl.finish_item();

		if (comment) {
			size_t clen = strlen (comment);
			bl.update (comment, clen, true);
		}
		time_t now = time(0);
		bl.update (now);

		if (add_certs) {
			add_certs_to_hash (&bl, signer);
		}

		unsigned char bh[64];
		bl.final (bh);

		if (ln == sig_begin) {
			while (getline(is, ln) && ln != sig_end) ;
			if (ln != sig_end) {
				throw_rte (_("Did not find the end of the signature"));
			}

			uint8_t sig[64];
			cu25519_sign (sig_prefix, bh, 64, signer.pair.xp, signer.pair.xs, sig);

			Protobuf_writer pw (NULL, pw.seek, 50000);
			write_signature (pw, signer, sig, comment, now, add_certs);

			os << sig_begin << '\n';
			const std::vector<char> &v (pw.get_buffer());
			base64enc((const uint8_t*)&v[0], v.size(), ln, true, true);
			os << ln << '\n';
			os << sig_end << '\n';

			// Copy the rest of the file.
			while (getline(is, ln)) os << ln << '\n';

			os.close();
			is.close();

			remove(name);
			rename(oname.c_str(), name);
		} else {
			throw_rte (_("Did not find a signed text."));
		}
	} catch(...) {
		throw_nrte(_("Could not clear resign the file %s."), name);
	}
}

}}


