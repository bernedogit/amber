/* Copyright (c) 2015-2016, Pelayo Bernedo.
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



#include "keys.hpp"
#include "blake2.hpp"
#include <string.h>
#include <sstream>
#include "blockbuf.hpp"
#include "misc.hpp"
#include "hasopt.hpp"
#include "protobuf.hpp"
#include <time.h>
#include <algorithm>
#include <assert.h>

namespace amber { namespace AMBER_SONAME {

static const char ksigh[] = "Key signature prefix";

const char * get_sig_prefix()
{
	return ksigh;
}


void dump_key(std::ostream &os, const Key &k)
{
	format(os, _("Key for %s\n"), k.name);
	format(os, _("  secret_avail: %s\n"), k.secret_avail);
	show_block(os, "  xpub", k.pair.xp.b, 32);
	show_block(os, "  xsec", k.pair.xs.b, 32);
	for (unsigned i = 0; i < k.sigs.size(); ++i) {
		show_block(os, "  signed by", k.sigs[i].signer.b, 32);
		show_block(os, "    signature", k.sigs[i].signature, 64);
	}
}




void list_key(const Key &k, std::ostream &os, bool pubonly, bool sigs,
              const Key_list *kl1, const Key_list *kl2, Key_encoding kenc)
{
	std::string enc;
	if (k.secret_avail && !pubonly) {
		if (k.master) {
			format(os, _("Master private key:\n"));
		} else {
			format(os, _("Working private key:\n"));
		}
		format(os, _("    name:    %s\n"), k.name);
		if (!k.alias.empty()) format(os, _("    alias:   %s\n"), k.alias);
		encode_key (k.pair.xp.b, 32, enc, true, kenc);
		format(os, _("    padlock: %s\n"), enc);
		encode_key(k.pair.xs.b, 32, enc, true, kenc);
		format(os, _("    key:     %s\n"), enc);
	} else {
		if (k.secret_avail) {
			if (k.master) {
				format(os, _("Master private key:\n"));
			} else {
				format(os, _("Working private key:\n"));
			}
		} else {
			if (k.master) {
				format(os, _("Master padlock:\n"));
			} else {
				format(os, _("Working padlock:\n"));
			}
		}
		format(os, _("    name:    %s\n"), k.name);
		if (!k.alias.empty()) format(os, _("    alias:   %s\n"), k.alias);
		encode_key (k.pair.xp.b, 32, enc, true, kenc);
		format(os, _("    padlock: %s\n"), enc);
	}

	char ts[100];
	strftime (ts, sizeof ts, "%F %T %z", localtime(&k.creation_time));
	format (os, "    ctime:   %s\n", ts);

	if (sigs) {
		for (unsigned i = 0; i < k.sigs.size(); ++i) {
			std::string enc;
			encode_key(k.sigs[i].signer.b, 32, enc, true, kenc);
			const Key *kp = NULL;
			if (kl1) {
				kp = find_key (*kl1, k.sigs[i].signer);
				if (kp == 0 && kl2) {
					kp = find_key(*kl2, k.sigs[i].signer);
				}
			}
			if (kp) {
				format(os, _("    certified by [%s] %c %s\n"), enc, kp->master ? 'M' : 'W', kp->name);
			} else {
				format(os, _("    certified by [%s]\n"), enc);
			}
		}
	}
	os << '\n';
}


void list_keys(const Key_list &kl, std::ostream &os, bool pubonly, bool sigs,
               const Key_list *names, Key_encoding kenc)
{
	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();

	while (i != e) {
		list_key(*i++, os, pubonly, sigs, &kl, names, kenc);
	}
}


// If the key is not present insert it. If it is present and the name is
// identical then add the signatures that are not already present.

bool insert_key(Key_list &kl, const Key &k, bool force)
{
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	while (i != e) {
		if (memcmp (i->pair.xp.b, k.pair.xp.b, 32) == 0) {
			if (force) {
				*i = k;
			} else if (i->name == k.name) {
				for (auto j = k.sigs.begin(); j != k.sigs.end(); ++j) {
					bool found = false;
					for (auto u = i->sigs.begin(); u != i->sigs.end(); ++u) {
						if (memcmp(j->signer.b, u->signer.b, 32) == 0) {
							found = true;
							break;
						}
					}
					if (!found) {
						i->sigs.push_back(*j);
					}
				}
			}
			if (k.secret_avail && !i->secret_avail) {
				memcpy (i->pair.xs.b, k.pair.xs.b, 32);
				i->secret_avail = true;
			}
			return false;
		}
		++i;
	}
	kl.push_back(k);
	return true;
}



void hash_key(const Key &k, uint8_t hash[64])
{
	Blake2b b;

	// Prepend variable length fields with their length.
	b.update (k.pair.xp.b, 32);
	b.update (k.name.size());
	b.update (k.name.c_str(), k.name.size());
	b.update (k.creation_time);
	b.final (hash);
}



bool verify_key_sigs_ok (const Key &key, std::vector<bool> &valid)
{
	uint8_t hash[64];
	hash_key (key, hash);
	int some_error = 0;

	// First verify the self signature.
	if (cu25519_verify (ksigh, hash, 64, key.self_signature, key.pair.xp) != 0) {
		return false;
	}

	for (unsigned i = 0; i < key.sigs.size(); ++i) {
		int err = cu25519_verify (ksigh, hash, 64, key.sigs[i].signature, key.sigs[i].signer);
		some_error |= err;
		valid.push_back (!err);
	}
	return some_error == 0;
}

static
bool assign_valid_sigs(Key &key, const std::vector<Signature> &sigs, std::string *errinfo)
{
	uint8_t hash[64];
	hash_key(key, hash);

	bool valid = true;
	for (unsigned i = 0; i < sigs.size(); ++i) {
		if (cu25519_verify(ksigh, hash, 64, sigs[i].signature, sigs[i].signer) == 0) {
			key.sigs.push_back(sigs[i]);
		} else {
			valid = false;
			if (errinfo) {
				std::ostringstream os;
				std::string enc;
				encode_key(sigs[i].signer.b, 32, enc, false);
				format(os, _("\nThe signature of the lock %s (%c) by %s is wrong. "),
				        key.name, key.master ? 'M' : 'W', enc);
				*errinfo += os.str();
			}
		}
	}
	return valid;
}




enum { top_key };
enum { key_pub, key_sec, key_name, key_sig, key_alias, key_time, key_master, key_self_sig };
enum { key_sig_signer, key_sig_signature };



void read_single_key (Protobuf_reader &pr, Key &k, bool recalc)
{
	std::vector<Signature> sigs;
	Signature sig;

	pr.add_requirement (key_pub,      pr.needed_once,
	                    key_sec,      pr.optional_once,
	                    key_name,     pr.needed_once,
	                    key_alias,    pr.optional_once,
	                    key_master,   pr.needed_once,
	                    key_self_sig, pr.needed_once,
	                    key_sig,      pr.optional_many);
	k.clear();
	memset(k.pair.xp.b, 0, 32);
	memset(k.pair.xs.b, 0, 32);

	uint32_t tagwt;
	uint64_t val;

	while (pr.read_tagval (&tagwt, &val)) {
		switch (tagwt) {
		case maketag (key_pub, length_val):
			if (val != 32) {
				throw_rte (_("The public key must have 32 bytes. Got %d."), val);
			}
			pr.get_bytes (k.pair.xp.b, 32);
			break;

		case maketag (key_sec, length_val):
			if (val != 32) {
				throw_rte (_("The secret key must be 32 bytes long. Got %d."), val);
			}
			pr.get_bytes (k.pair.xs.b, 32);
			k.secret_avail = true;
			break;

		case maketag(key_name, length_val):
			k.name.resize(val);
			pr.get_bytes (&k.name[0], val);
			break;

		case maketag(key_alias, length_val):
			k.alias.resize (val);
			pr.get_bytes (&k.alias[0], val);
			break;

		case maketag(key_time, varint):
			// We just assume the POSIX encoding of seconds since 1970-1-1.
			k.creation_time = val;
			break;

		case maketag(key_master, varint):
			k.master = val;
			break;

		case maketag (key_self_sig, length_val):
			if (val != 64) {
				throw_rte (_("The self signature must be 64 bytes long. Got %d."), val);
			}
			pr.get_bytes (k.self_signature, 64);
			break;

		case maketag  (key_sig, group_len):
			pr.add_requirement (key_sig_signer, pr.needed_once,
			                    key_sig_signature, pr.needed_once);
			while (pr.read_tagval (&tagwt, &val)) {
			switch (tagwt) {
				case maketag (key_sig_signer, length_val):
					if (val != 32) {
						throw_rte (_("The signer must be 32 bytes long. Got %d."), val);
					}
					pr.get_bytes (sig.signer.b, 32);
					break;

				case maketag (key_sig_signature, length_val):
					if (val != 64) {
						throw_rte (_("The signature must be 64 bytes long. Got %d."), val);
					}
					pr.get_bytes (sig.signature, 64);
					break;

				default:
					pr.skip (tagwt, val);
				}
			}
			sigs.push_back(sig);
			break;

		default:
			pr.skip (tagwt, val);
		}
	}

	encode_key (k.pair.xp.b, 32, k.enc, false);
	if (recalc) {
		assign_valid_sigs(k, sigs, NULL);
	} else {
		k.sigs = std::move(sigs);
	}
}



int read_keys (std::istream &is, Key_list &kl, bool recalc, bool force)
{
	Key k;
	int count = 0;
	uint32_t tagwt;
	uint64_t val;

	Protobuf_reader pr (&is);

	while (is && !is.eof() && pr.read_tagval (&tagwt, &val, true)) {
		switch (tagwt) {
		case maketag (top_key, group_len):
			read_single_key (pr, k, recalc);
			insert_key (kl, k, force);
			++count;
			break;

		default:
			pr.skip (tagwt, val);
		}
	}
	return count;
}




int read_keys(const std::string &name, Key_list &kl, std::string &password,
              bool recalc, bool force, std::string *errinfo)
{
	amber::ifstream isc;
	std::ifstream isp;
	std::istream *is;

	if (name.size() > 4 && name.compare(name.size() - 4, 4, ".cha") == 0) {
		if (password.empty()) {
			std::ostringstream os;
			format(os, _("Password for key file %s: "), name);
			get_password(os.str().c_str(), password);
		}
		isc.open(name.c_str(), password.c_str());
		is = &isc;
	} else {
		isp.open(name.c_str(), isp.binary);
		is = &isp;
		// We do not trust unencrypted files. We recalc them always.
		recalc = true;
	}

	if (!*is) {
		if (errinfo) {
			*errinfo = _("Cannot open the key ring file.");
			return -1;
		}
	}
	int count = read_keys (*is, kl, recalc, force);
	if (count < 0 || !errinfo->empty()) {
		if (errinfo) {
			errinfo->insert(0, _("Error reading keys from the file. "));
		}
	}
	return count;
}



void write_key(Protobuf_writer &pw, const Key &key, bool pubonly)
{
	pw.start_group (top_key);

	pw.write_bytes (key_pub, key.pair.xp.b, 32);
	if (key.secret_avail && !pubonly) {
		pw.write_bytes (key_sec, key.pair.xs.b, 32);
	}

	pw.write_bytes (key_name, key.name.c_str(), key.name.size());
	pw.write_bytes (key_alias, key.alias.c_str(), key.alias.size());
	// We just assume the POSIX encoding of seconds since 1970-1-1.
	pw.write_uint (key_time, key.creation_time);
	pw.write_uint (key_master, key.master);
	pw.write_bytes (key_self_sig, key.self_signature, 64);

	for (unsigned i = 0; i < key.sigs.size(); ++i) {
		pw.start_group (key_sig);
		pw.write_bytes (key_sig_signer, key.sigs[i].signer.b, 32);
		pw.write_bytes (key_sig_signature, key.sigs[i].signature, 64);
		pw.end_group();
	}

	pw.end_group();
}



void write_keys(std::ostream &os, const Key_list &kl, bool pubonly)
{
	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();
	int count = 0;

	Protobuf_writer pw (&os, pw.seek, 10000);
	while (i != e) {
		if (i->write_what != Key::discard) {
			write_key(pw, *i, pubonly || i->write_what == Key::write_pub);
		}
		++i;
		++count;
	}
	pw.flush();
	format(std::cout, _("Wrote %d keys\n"), count);
}


void generate_master_from_secret (const uint8_t priv[32], const char *name, Key *key)
{
	key->clear();
	memcpy (key->pair.xs.b, priv, 32);
	cu25519_generate (&key->pair);
	key->name = name;
	key->secret_avail = true;
	encode_key (key->pair.xp.b, 32, key->enc, false);
	key->master = true;
	key->creation_time = time(NULL);
	key->write_what = Key::write_all;

	uint8_t hash[64];
	hash_key(*key, hash);
	cu25519_sign (ksigh, hash, 64, key->pair.xp, key->pair.xs, key->self_signature);
}

void generate_master_key(const uint8_t priv[32], const char *name, Key *key)
{
	key->clear();
	blake2b (key->pair.xs.b, 32, priv, 32, NULL, 0);
	cu25519_generate (&key->pair);
	key->name = name;
	key->secret_avail = true;
	encode_key(key->pair.xp.b, 32, key->enc, false);
	key->master = true;
	key->creation_time = time(NULL);
	key->write_what = Key::write_all;

	uint8_t hash[64];
	hash_key(*key, hash);
	cu25519_sign (ksigh, hash, 64, key->pair.xp, key->pair.xs, key->self_signature);
}


void generate_work_key (const uint8_t priv[32], const char *name, Key *key, const Key &master)
{
	key->clear();
	blake2b (key->pair.xs.b, 32, priv, 32, NULL, 0);
	cu25519_generate (&key->pair);
	key->name = name;
	key->secret_avail = true;
	encode_key(key->pair.xp.b, 32, key->enc, false);
	key->master = false;
	key->creation_time = time(NULL);
	key->write_what = Key::write_all;

	uint8_t hash[64];
	hash_key(*key, hash);

	cu25519_sign (ksigh, hash, 64, key->pair.xp, key->pair.xs, key->self_signature);

	Signature s;
	memcpy (s.signer.b, master.pair.xp.b, 32);
	cu25519_sign (ksigh, hash, 64, master.pair.xp, master.pair.xs, s.signature);
	key->sigs.push_back(s);
}

static bool idmatch(const std::string &s1, const std::string &id)
{
	for (size_t pos = s1.find(id); pos != id.npos; pos = s1.find(id, pos + 1)) {
		if (pos != 0 && s1[pos-1] != ' ') continue;
		if (pos + id.size() < s1.size() && s1[pos + id.size()] == ' ') return true;
		if (pos + id.size() == s1.size()) return true;
	}
	return false;
}

static bool idmatch(const Key &k, const std::string &name)
{
	// If we find the name as the prefix of the encoding we got it.
	if (k.enc.find(name) == 0) return true;

	if (idmatch(k.name, name)) return true;
	return idmatch(k.alias, name);
}



void select_keys(const Key_list &kl, const std::vector<std::string> &names,
                 Key_list &dst)
{
	std::vector<bool> used(names.size());
	for (unsigned i = 0; i < used.size(); ++i) used[i] = false;

	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();
	while (i != e) {
		for (unsigned j = 0; j < names.size(); ++j) {
			if (i->enc.find(names[j]) == 0) {
				if (used[j]) {
					throw_rte (_("The identifier '%s' matches more than one key"), names[j]);
				}
				used[j] = true;
			}
			if (idmatch(*i, names[j])) {
				dst.push_back(*i);
				break;
			}
		}
		++i;
	}
}


void select_last_keys(const Key_list &kl, const std::vector<std::string> &names,
                      Key_list &dst)
{
	std::vector<bool> used(names.size());
	for (unsigned i = 0; i < used.size(); ++i) used[i] = false;

	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();
	while (i != e) {
		for (unsigned j = 0; j < names.size(); ++j) {
			if (i->enc.find(names[j]) == 0) {
				if (used[j]) {
					throw_rte (_("The identifier '%s' matches more than one key"),
					           names[j]);
				}
				used[j] = true;
			}
			if (idmatch(*i, names[j]) /*&& !i->master*/) {
				dst.push_back(*i);
				break;
			}
		}
		++i;
	}

	std::sort(dst.begin(), dst.end(), [](const Key &k1, const Key &k2) {
			int cmp = strcmp(k1.name.c_str(), k2.name.c_str());
			// Primary order: name
			if (cmp < 0) return true;
			if (cmp > 0) return false;
			// Both keys have the same name. Sort by creation time in reverse
			// order.
			if (k1.creation_time > k2.creation_time) return true;
			return false;
		});

	std::string last_name;
	Key_list tmp;
	for (unsigned i = 0; i < dst.size(); ++i) {
		if (dst[i].name != last_name) {
			tmp.push_back(dst[i]);
			last_name = dst[i].name;
		}
	}
	tmp.swap(dst);
}




void select_keys(const Key_list &kl, const std::string &name, Key_list &dst)
{
	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();
	bool used = false;
	while (i != e) {
		if (i->enc.find(name) == 0) {
			if (used) {
				throw_rte (_("The identifier matches more than one key"));
			}
			used = true;
		}
		if (idmatch(*i, name)) {
			dst.push_back(*i);
		}
		++i;
	}
}


void select_secret_keys(const Key_list &kl, Key_list &dst)
{
	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();
	while (i != e) {
		if (i->secret_avail) {
			dst.push_back(*i);
		}
		++i;
	}
}




void select_one(const Key_list &kl, const std::string &name, Key &key)
{
	Key_list sel;
	if (name.empty()) {
		select_secret_keys(kl, sel);
	} else {
		std::vector<std::string> vs;
		vs.push_back(name);
		select_last_keys(kl, vs, sel);
	}

	if (sel.size() != 1) {
		throw_rte (_("Select just one key."));
	}

	key = sel[0];
}


void select_recent_one(const Key_list &kl, const std::string &name, Key &key, bool master)
{
	Key_list sel;
	if (name.empty()) {
		select_secret_keys(kl, sel);
	} else {
		select_keys(kl, name, sel);
	}

	if (sel.size() == 1) {
		key = sel[0];
	} else if (sel.empty()) {
		throw_rte (_("No keys match the given name."));
	} else {
		time_t newest_time = -1;
		unsigned newest_index = 0;
		for (unsigned i = 0; i < sel.size(); ++i) {
			if (sel[i].creation_time > newest_time) {
				if (!master || sel[i].master) {
					newest_time = sel[i].creation_time;
					newest_index = i;
				}
			}
		}
		key = sel[newest_index];
	}
}



void change_name(Key_list &kl, const std::vector<std::string> &selected, const char *new_name)
{
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	while (i != e) {
		for (auto j = selected.begin(); j != selected.end(); ++j) {
			if (idmatch(*i, *j)) {
				i->name = new_name;
				uint8_t hash[64];
				hash_key(*i, hash);
				cu25519_sign (ksigh, hash, 64, i->pair.xp, i->pair.xs, i->self_signature);
				break;
			}
		}
		++i;
	}
}


void change_alias(Key_list &kl, const std::vector<std::string> &selected, const char *new_alias)
{
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	while (i != e) {
		for (auto j = selected.begin(); j != selected.end(); ++j) {
			if (idmatch(*i, *j)) {
				i->alias = new_alias;
				break;
			}
		}
		++i;
	}
}


void append_alias(Key_list &kl, const std::vector<std::string> &selected, const char *new_alias)
{
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	while (i != e) {
		for (auto j = selected.begin(); j != selected.end(); ++j) {
			if (idmatch(*i, *j)) {
				if (!i->alias.empty()) {
					i->alias.push_back(' ');
				}
				i->alias += new_alias;
				break;
			}
		}
		++i;
	}
}


int sign_keys(Key_list &kl, const char *signer, const std::vector<std::string> &selnames)
{
	Key ksig;
	select_recent_one(kl, signer, ksig, true);
	if (!ksig.secret_avail) {
		throw_rte(_("The signing padlock has no private key."));
	}
	return sign_keys(kl, ksig, selnames);
}

#if 0

int sign_keys(Key_list &kl, const Key &ksig, const std::vector<std::string> &selnames)
{
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	while (i != e) {
		for (auto j = selnames.begin(); j != selnames.end(); ++j) {
			if (idmatch(*i, *j)) {
				bool skip = false;
				for (auto u = i->sigs.begin(); u != i->sigs.end(); ++u) {
					if (memcmp(u->signer.b, ksig.xpub.b, 32) == 0) {
						skip = true;
						break;
					}
				}
				if (skip) continue;
				Signature s;
				memcpy(s.signer.b, ksig.xpub.b, 32);
				uint8_t hash[64];
				hash_key(*i, hash);
				cu25519_sign(ksig.xpub, ksig.xsec, s.signature, ksigh, sizeof(ksigh)-1, hash, 64);
				i->sigs.push_back(s);
			}
		}
		++i;
	}
	return 0;
}
#endif


int sign_keys(Key_list &kl, const Key &signer, const std::vector<std::string> &selnames)
{
	if (!signer.secret_avail) {
		throw_rte(_("The signing padlock has no private key."));
	}
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	
	while (i != e) {
		for (auto j = selnames.begin(); j != selnames.end(); ++j) {
			if (idmatch(*i, *j)) {
				bool skip = false;
				for (auto u = i->sigs.begin(); u != i->sigs.end(); ++u) {
					if (memcmp(u->signer.b, signer.pair.xp.b, 32) == 0) {
						skip = true;
						break;
					}
				}
				if (skip) continue;
				Signature s;
				memcpy(s.signer.b, signer.pair.xp.b, 32);
				uint8_t hash[64];
				hash_key(*i, hash);
				cu25519_sign (ksigh, hash, 64, signer.pair.xp, signer.pair.xs, s.signature);
				i->sigs.push_back(s);
			}
		}
		++i;
	}
	return 0;
}



int sign_keys(Key_list &kl, const Key &signer)
{
	if (!signer.secret_avail) {
		throw_rte(_("The signing padlock has no private key."));
	}

	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();

	while (i != e) {
		bool skip = false;
		for (auto u = i->sigs.begin(); u != i->sigs.end(); ++u) {
			if (memcmp(u->signer.b, signer.pair.xp.b, 32) == 0) {
				skip = true;
				break;
			}
		}
		if (skip) continue;
		Signature s;
		memcpy(s.signer.b, signer.pair.xp.b, 32);
		uint8_t hash[64];
		hash_key(*i, hash);
		cu25519_sign (ksigh, hash, 64, signer.pair.xp, signer.pair.xs, s.signature);
		i->sigs.push_back(s);
		++i;
	}
	return 0;
}




int remove_signature(Key_list &kl, const char *signer, const std::vector<std::string> &selnames)
{
	size_t slen = strlen(signer);
	Key_list::iterator i = kl.begin();
	Key_list::iterator e = kl.end();
	while (i != e) {
		for (auto j = selnames.begin(); j != selnames.end(); ++j) {
			if (idmatch(*i, *j)) {
				for (auto u = i->sigs.begin(); u != i->sigs.end(); ++u) {
					std::string enc;
					encode_key(u->signer.b, 32, enc, false);
					if (enc.compare(0, slen, signer) == 0) {
						i->sigs.erase(u);
						break;
					}
				}
			}
		}
		++i;
	}
	return 0;
}


const Key * find_key (const Key_list &kl, const Cu25519Ris &pub)
{
	Key_list::const_iterator i = kl.begin();
	Key_list::const_iterator e = kl.end();
	while (i != e) {
		if (memcmp(i->pair.xp.b, pub.b, 32) == 0) {
			return &*i;
		}
		++i;
	}
	return NULL;
}



void find_key_name (const Key_list &kl, const Cu25519Ris &pub, std::string &name, Key_encoding kenc)
{
	if (is_zero(pub.b, 32)) {
		name = _("Anonymous");
		return;
	}

	std::string enc;
	encode_key(pub.b, 32, enc, true, kenc);
	name = "[" + enc + "]";
	const Key *kp = find_key(kl, pub);
	if (kp) {
		name += kp->master ? " M " : " W ";
		name += kp->name;
	}
#if 0
	struct tm *ptm = gmtime(&kp->creation_time);
	name += format(_(" %04d-%02d-%02d %2d:%02d:%02d UTC"),
	            ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
	            ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
#endif
}



void show_sig_key (const Key_list &kl, const Key &key, Key_encoding kenc)
{
	std::string enc;
	encode_key (key.pair.xp.b, 32, enc, true, kenc);
	format (std::cout, "[%s] ", enc);
	const Key *kp = find_key(kl, key.pair.xp);
	if (kp) {
		format (std::cout, "%c %s\n", kp->master ? 'M' : 'W', kp->name);
		return;
	}

	if (key.only_xpub) {
		format (std::cout, _("The signing padlock could not be found.\n"));
		return;
	}

	// Not in our list.
	format (std::cout, "Unverified padlock of %s\n", key.name);
	char ts[100];
	// The first one is C90/C++98, whereas the second one is C99/C++11
	// compliant. It seems that Mingw still has the old C90 library of M$.
	strftime (ts, sizeof ts, "%Y-%m-%d %H:%M:%S %z", localtime (&key.creation_time));
//  strftime (ts, sizeof ts, "%F %T %z", localtime (&key.creation_time));
	format (std::cout, _("Padlock allegedly created on: %s\n"), ts);

	// First check the self signature.
	uint8_t hk[64];
	hash_key (key, hk);

	if (cu25519_verify (ksigh, hk, 64, key.self_signature, key.pair.xp) != 0) {
		format (std::cout, _("Wrong self signature. THIS IS A FAKE SIGNATURE.\n"));
		return;
	}

	std::string name;
	for (unsigned i = 0; i < key.sigs.size(); ++i) {
		if (cu25519_verify (ksigh, hk, 64, key.sigs[i].signature, key.sigs[i].signer) == 0) {
			find_key_name (kl, key.sigs[i].signer, name, kenc);
			format (std::cout, _("Padlock certified by %s\n"), name);
		}
	}
}





bool delete_keys(Key_list &kl, const Key_list &selected)
{
	bool changed = false;
	Key_list::iterator i = kl.begin();
	while (i != kl.end()) {
		Key_list::const_iterator si = selected.begin();
		Key_list::const_iterator se = selected.end();
		while (si != se) {
			if (memcmp(si->pair.xp.b, i->pair.xp.b, 32) == 0) {
				Key_list::iterator tmp = i;
				--i;
				kl.erase(tmp);
				changed = true;
				break;
			}
			++si;
		}
		++i;
	}
	return changed;
}




void encode_key(const uint8_t *b, size_t n, std::string &dst, bool spaces, Key_encoding ke)
{
	std::vector<uint8_t> b1(n + 1);
	memcpy(&b1[0], b, n);
	uint32_t crc = update_crc32(b, n);
	b1[n] = crc & 0xFF;
	switch (ke) {
	case key16:
		write_block(dst, &b1[0], n + 1);
		break;

	case key32:
		base32enc(&b1[0], n + 1, dst, spaces);
		break;

	case key58:
		base58enc(&b1[0], n + 1, dst);
		break;

	case key64:
		base64enc(&b1[0], n, dst, false, false);
		break;
	}
}


int decode_key(const char *s, std::vector<uint8_t> &dst, Key_encoding ke)
{
	const char *tmp;
	size_t len = strlen(s);
	switch (ke) {
	case key16:
		read_block(s, &tmp, dst);
		break;

	case key32:
		base32dec(s, dst, len);
		break;

	case key58:
		base58dec(s, dst, len);
		break;

	case key64:
		base64dec(s, dst, len);
	}

	if (dst.size() != 33) return -1;
	uint32_t crc = update_crc32(&dst[0], 32);
	if (dst[32] != (crc & 0xFF)) return -1;
	dst.resize(32);              
	return 0;
}


}}

