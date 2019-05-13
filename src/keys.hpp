#ifndef AMBER_KEYS_HPP
#define AMBER_KEYS_HPP

/* Copyright (c) 2015-2017, Pelayo Bernedo.
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



#include "group25519.hpp"
#include <iostream>
#include <vector>


namespace amber {   namespace AMBER_SONAME {

// A signature information. Signer is the public key of the signer. Signature
// is the actual signature.
struct Signature {
	Cu25519Ris   signer;
	uint8_t      signature[64];
};


// The information of a key.
struct Key {
	// Public and secret parts.
	Cu25519Pair          pair;

	// This is true if xsec is valid.
	bool            secret_avail;

	// Name of the owner of the key and alias(es) of the owner.
	std::string     name, alias;
	time_t          creation_time;

	// Is this key a master key? If not it is a work key.
	bool master;

	// This came from a signature containing only xpub. Other members are not
	// valid.
	bool only_xpub;

	// Should we write the key when the program ends?
	enum { discard, write_pub, write_all }  write_what;

	// Human readable encoding of the public key.
	std::string     enc;

	// Signature like below but signed by myself. This must be present.
	uint8_t         self_signature[64];


	// The signatures of other people who endorse this key. The signatures
	// sign only the name, the public key, the creation date and whether the
	// key is a master. They do not sign the alias. The intent is that the
	// name  is the only formal part that identifies the key but users can
	// add and  modify aliases without needing to sign them.
	std::vector<Signature> sigs;
	Key() : secret_avail(false), creation_time(-1), master(false), only_xpub(false), write_what(write_all) {}
	void clear() {
		secret_avail = false;
		name.clear();
		alias.clear();
		creation_time = -1;
		master = only_xpub = false;
		write_what = write_all;
		enc.clear();
		sigs.clear();
	}
};


// How to show the keys to the user. This is also the format in which raw
// keys will be read. key16 will encode the key as an hexadecimal listing.
// key32 will use letters and digits and is insensitive to the case of the
// letters. key58 uses base 58 encoding: this encoding uses digits and upper
// and lower case letters. Most programs will interpret a base 58 key as if
// it were a single word within a text. key64 uses standard base 64 encoding.
typedef std::vector<Key> Key_list;
enum Key_encoding { key16, key32, key58, key64 };



// Show the contents of a key or a key list. If pubonly is not true the
// secret key information will be shown too. If sigs is true then the
// signatures for this key will also be shown. kl1 and kl2 will be used to
// look up the names of the signers of the key. Set kenc to the preferred
// encoding for showing the keys.
EXPORTFN
void list_key(const Key &k, std::ostream &os, bool pubonly, bool sigs,
              const Key_list *kl1=NULL, const Key_list *kl2=NULL,
              Key_encoding kenc=key58);

// Show all the keys in the list kl. If a signer is not present in the list
// kl then it will be looked up in the list names, if given. Set pubonly if
// you do not want to show the private keys. Set sigs to show the signers of
// the keys.
EXPORTFN
void list_keys(const Key_list &kl, std::ostream &os, bool pubonly, bool sigs,
               const Key_list *names=NULL, Key_encoding kenc=key58);

// Insert the key in the list if not already present. Return true if the key
// was not in the list and we could insert it. If force is true then the key
// k will replace a previous existing copy.
EXPORTFN bool insert_key(Key_list &kl, const Key &k, bool force);


// Read the keys from the input file into the key list. Return the number of
// keys read or -1 if there was an error. If you pass a non NULL errinfo
// then *errinfo will contain error information. If recalc is true it will
// recompute the public key from other information. If force is true then the
// read keys will replace keys already existing in kl.
EXPORTFN
int read_keys(std::istream &is, Key_list &kl, bool recalc, bool force);

// Read the keys from an encrypted file.
EXPORTFN
int read_keys(const std::string &name, Key_list &kl, std::string &password,
              bool recals, bool force, std::string *errinfo);


// Write a single key or a list in binary format. If pubonly is selected only the public
// part will be written.
EXPORTFN void write_key(std::ostream &os, const Key &key, bool pubonly);
EXPORTFN void write_keys(std::ostream &os, const Key_list &kl, bool pubonly);

// Generate a new master key with the given name. priv[] contains the random
// bytes to be used to generate the key. It correctly fills all the fields
// of key and self signs the key.
EXPORTFN void generate_master_key(const uint8_t priv[32], const char *name, Key *key);

// Generate a master key from the value of the private key.
EXPORTFN
void generate_master_from_secret(const uint8_t priv[32], const char *name, Key *key);

// Generate a working key signed by the master.
EXPORTFN
void generate_work_key(const uint8_t priv[32], const char *name, Key *key, const Key &master);



// Given a list of names, select from the list kl those keys that match any of the names
// and store the matching keys into dst. A key matches a name when either some part of
// its name matches the name or when the name is a prefix of the key itself.
EXPORTFN void select_keys(const Key_list &kl, const std::vector<std::string> &names,
                 Key_list &dst);

// Same as above but only select working keys, skipping the master keys.
// Within the working keys select only the most recent one.
EXPORTFN
void select_last_keys(const Key_list &kl, const std::vector<std::string> &names,
                      Key_list &dst);

// Just a single name.
EXPORTFN
void select_keys(const Key_list &kl, const std::string &name, Key_list &dst);

// Select all the secret keys present in the list.
EXPORTFN void select_secret_keys(const Key_list &kl, Key_list &dst);

// Select either the key with the given name or select the secret key in the
// ring. If there are more than one key that match the above criteria throw
// an exception.
EXPORTFN void select_one(const Key_list &kl, const std::string &name, Key &key);

// Select either the key with the given name or select the secret key in the
// ring. If there are more than one key that match the above criteria
// then select the most recent key. If master is true then select only the
// most recent master key.
EXPORTFN
void select_recent_one (const Key_list &kl, const std::string &name, 
						Key &key, bool master);


// Modify the name of selected keys. selected contains a list of strings.
// Those keys that match these strings will get the name new_name.
EXPORTFN
void change_name(Key_list &kl, const std::vector<std::string> &selected,
                 const char *new_name);

// Modify the alias of selected keys. selected contains a list of strings.
// Those keys that match these strings will have their alias set to new_alias.
EXPORTFN
void change_alias(Key_list &kl, const std::vector<std::string> &selected,
                 const char *new_alias);

// Same as change_alias but it keeps the existing aliases and adds a new one.
EXPORTFN
void append_alias (Key_list &kl, const std::vector<std::string> &selected, 
				   const char *new_alias);


// Return true if at least one of the selected keys was found in the key
// list kl. The found key is deleted.
EXPORTFN bool delete_keys(Key_list &kl, const Key_list &selected);

// Sign the keys selected using the names in selnames. The signer can be
// specified by name or by providing the key.
EXPORTFN
int sign_keys (Key_list &kl, const char *signer, 
			   const std::vector<std::string> &selnames);

EXPORTFN
int sign_keys (Key_list &kl, const Key &signer, 
			   const std::vector<std::string> &selnames);

// Sign all keys.
EXPORTFN int sign_keys(Key_list &kl, const Key &signer);

// Remove the signature by signer from all the keys that match the names in
// selnames.
EXPORTFN
int remove_signature (Key_list &kl, const char *signer, 
					  const std::vector<std::string> &selnames);

// Return the key if found. NULL otherwise.
EXPORTFN const Key * find_key(const Key_list &kl, const Cu25519Ris &pub);

// Provide the name corresponding to the key. If the pub key can be found in
// the list kl then set name to the name of the key. In addition always
// append to the resulting name the raw value of pub encoded using the
// encoding kenc.
EXPORTFN
void find_key_name (const Key_list &kl, const Cu25519Ris &pub, 
					std::string &name, Key_encoding kenc=key58);

EXPORTFN
void show_sig_key (const Key_list &kl, const Key &key, Key_encoding kenc);


// Encode the key into a string that is readable by humans. If spaces is true
// then for key16 and key32 spaces will be used to create more readable
// blocks. The encoded keys include a check digit to detect typing errors.
EXPORTFN
void encode_key (const uint8_t *b, size_t n, std::string &dst, bool spaces, 
				 Key_encoding ke=key58);

EXPORTFN
int decode_key (const char *s, std::vector<uint8_t> &dst, 
				Key_encoding ke=key58);


// Return true if the signatures are valid. If some signature is not valid
// the set the corresponding valid[i] to false.
EXPORTFN
bool verify_key_sigs_ok(const Key &k, std::vector<bool> &valid);

// Show everything for debugging purposes.
EXPORTFN void dump_key(std::ostream &os, const Key &k);

EXPORTFN void hash_key (const Key &k, uint8_t hash[64]);
EXPORTFN const char * get_sig_prefix();

}}

#endif


