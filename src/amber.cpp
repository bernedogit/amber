/*
 * Copyright (C) 2015-2019, Pelayo Bernedo.
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




#include "hasopt.hpp"
#include "symmetric.hpp"
#include "group25519.hpp"
#include "misc.hpp"
#include "blockbuf.hpp"
#include "keys.hpp"
#include "combined.hpp"
#include "pack.hpp"
#include "blake2.hpp"
#include "inplace.hpp"
#include <iostream>
#include <algorithm>
#include <string.h>
#include <fstream>
#include <stdlib.h>
#include <time.h>

using  namespace amber;


bool ends_with(const std::string &s, const std::string &sfx)
{
	if (s.size() < sfx.size()) return false;
	return s.compare(s.size() - sfx.size(), sfx.size(), sfx) == 0;
}

void usage(std::ostream &os)
{
	os << _("usage is amber [options]\n");
	os << _("--ringless               do not use a key ring, but derive our key from the\n"
			"                         password.\n");
	os << _("--keyring <file>         specify the key ring file\n");
	os << _("--master <file>          read and write the master key from the file.\n");
	os << _("--keyfile <file>         read additional keys from the given file. This\n"
			"                         can be repeated as many times as necessary\n");
	os << _("--gen-master <name>      generate a new master key and padlock pair for the\n"
			"                         given name\n");
	os << _("--gen-work               generate a new working key and padlock pair.\n"
			"                         If more than one master key exists then select the\n"
			"                         desired one with the -u option\n");
	os << _("--export <file>          export the selected padlocks to the file\n");
	os << _("--export-sec <file>      export the selected padlocks and keys to the file\n");
	os << _("--import <file>          import padlocks and keys from the file\n");
	os << _("-p <name>                select padlocks or keys matching name. Can be given\n"
			"                         multiple times.\n");
	os << _("-r <name>\n");
	os << _("--recipient <name>       select padlocks or keys matching name. For each name select the most\n"
			"                         recent padlock. This option can be given multiple times.\n");
			
	os << _("--lockid <padlock>       interpret the <padlock> as the raw encoding.\n");
	os << _("--all                    select all padlocks and keys.\n");
	os << _("--delete                 remove the selected keys or padlocks from the ring.\n");
	os << _("--rename <name>          change the name of the selected keys or padlocks to\n"
			"                         name.\n");
	os << _("--alias <name>           change the alias of the selected keys or padlocks to\n"
			"                         alias.\n");
	os << _("--app-alias <name>       append the alias to the selected keys or padlocks.\n");
	os << _("--add-raw                add a padlock. First argument is the name. The second\n"
			"                         argument is the padlock.\n");
	os << _("--add-raw-sec            add a secret key. First argument is the name. The\n"
			"                         second argument is the file containing the private\n"
			"                         key.\n");
	os << _("-k                       show the padlocks\n");
	os << _("--list                   show the padlocks with certificates\n");
	os << _("--list-sec               show even the secret keys\n");
	os << _("--list-file <file>       show the padlocks and keys in the file\n");
	os << _("--certify-by <certifier> certify the selected padlocks.\n");
	os << _("--certify-raw            certify with a key in raw format.\n");
	os << _("--rm-cert <certifier>    remove the certificate from the selected padlocks.\n");
	os << _("--certify-lockfile-by <certifier>  certify all the padlocks present in the\n"
			"                         first argument.\n");
	os << _("--passfile <file>        read the password from the file.\n");
	os << _("-o outname               write the output to outname\n");
	os << _("--output outname         write the output to outname\n");
	os << _("-u <name>                specify the name of the encrypter, decrypter or\n"
			"                         signer. If there are several keys select the most\n"
			"                         recent one.\n");
	os << _("--uraw-file <raw_key_file> same as above but specify the file contains the\n"
			"                         private key in raw form\n");
	os << _("--uraw                   ask for the raw key\n");
	os << _("-a                       anonymous sender.\n");
	os << _("-e                       encrypt using locks\n");
	os << _("-c                       encrypt using a password.\n");
	os << _("-E                       decrypt using a key\n");
	os << _("--de                     decrypt using a key\n");
	os << _("-C                       decrypt using a password.\n");
	os << _("--dc                     decrypt using a password.\n");
	os << _("-s  --sign               sign first file and put the signature in the second\n"
			"                         file. Use the optional third argument as comments\n");
	os << _("-v                       verify the first file using the second file as\n"
			"                         signature.\n");
	os << _("--verify                 verify the first file using the second file as\n"
			"                         signature.\n");
	os << _("--armor                  input and output b64 encoded signatures\n");
	os << _("--clearsign              clearsign the file\n");
	os << _("--clearverify            clearverify the input file\n");
	os << _("--clearresign            clearsign the file again\n");
	os << _("--add-certs              add the certificates of the signing key to the signature\n");
	os << _("--check                  check the consistency of the key ring.\n");
	os << _("--correct                check the consistency of the key ring and remove the\n"
			"                         wrong entries.\n");
	os << _("-f                       force replacement of existing keys with imported\n"
			"                         ones.\n");
	os << _("--wipe                   wipe input file with random bytes after encrypting.\n");
	os << _("--block-size <bytes>     set the size of the output blocks in bytes.\n");
	os << _("--block-filler <bytes>   set the amount of filler bytes per block.\n");
	os << _("--shifts <value>         set the shifts parameter of Scrypt when encrypting\n"
			"                         or the maximum value of shifts when decrypting.\n");
	os << _("--no-expand              do not expand the file. Same as block-filler=0.\n");
	os << _("--verbose                verbose output.\n");
	os << _("--hex                    keys in hexadecimal\n");
	os << _("--icao                   keys in base 32\n");
	os << _("--pack                   encrypt and pack all files into the output file\n"
			"                         Without -e or -c it will just create the archive but\n"
			"                         not encrypt it. If you want encryption use it together\n"
			"                         with -e or -c\n");
	os << _("--noz                    Do not compress the archive.\n");
	os << _("--pack-list              list the files contained in the input file.\n"
			"                         This may be used together with --de or --dc\n");
	os << _("--unpack <packed>        unpack from the packed file the other files\n"
			"                         This may be used together with --de or --dc\n");
	os << _("--unpack-all <packed>    unpack all the files\n"
			"                         This may be used together with --de or --dc\n");
	os << _("--spoof                  encryption pretending that the recipient wrote the\n"
			"                         file to the sender\n");
	os << _("--hide                   encrypt two files into one with different passwords\n");
	os << _("--reveal                 decrypt the second, hidden, file\n");
	os << _("--hidek <rx2>            encrypt two files into one with different padlocks\n");
	os << _("--revealk <rx2>          decrypt the second, hidden, file encrypted with\n"
			"                         padlocks\n");
	os << _("--inplace-enc            encrypt the given files in place. No temporary files\n"
			"                         will be created\n");
	os << _("--inplace-dec            decrypt the given files in place. No temporary files\n"
			"                         will be created\n");
	os << _("--incpack                incremental pack\n");
	os << _("-h or --help             show this help.\n");
	os << _("If you do not specify a key ring file then the environment variable\n"
			"AMBER_KEYRING will be read and if present it defines the name of the key\n"
			"ring. If the variable is not set then the default is amber.keys.cha\n");

	os << '\n';
	os << _("Read the file amber.md for more information about how to use this program.\n");
}

static
void save_key_file(const Key_list &kl, const std::string &file_name,
                   std::string &password, bool confirm)
{
	amber::ofstream osc;
	std::ofstream osp;
	std::ostream *os;
	if (file_name.size() > 4 && file_name.compare(file_name.size() - 4, 4, ".cha") == 0) {
		if (confirm) {
			std::string p2;
			get_password(_("Repeat the password for the key file: "), p2);
			if (password != p2) {
				throw_rte(_("The supplied passwords do not match!\n"));
			}
		}

		osc.open(file_name.c_str(), password.c_str());
		os = &osc;
	} else {
		osp.open(file_name.c_str(), osp.binary);
		os = &osp;
	}

	if (!*os) {
		format(std::cerr, _("Cannot write the keys to the file %s\n"), file_name);
	}
	write_keys(*os, kl, false);
}

static
int read_private_from_file(const char *file, Key *key)
{
	std::ifstream is(file);
	if (!is) return -1;
	std::string ln;
	getline(is, ln);
	std::vector<uint8_t> pk;
	if (0 != decode_key(ln.c_str(), pk) || pk.size() != 32) {
		format(std::cerr, _("There is an error in the given key %s. Check the input.\n"), ln);
		return -1;
	}
	generate_master_from_secret(&pk[0], "raw secret key", key);
	return 0;
}

static
int make_private_from_raw(Key *key)
{
	format(std::cout, _("Enter the raw private key: "));
	std::string ln;
	getline(std::cin, ln);
	std::vector<uint8_t> pk;
	if (0 != decode_key(ln.c_str(), pk) || pk.size() != 32) {
		format(std::cerr, _("There is an error in the given key %s. Check the input.\n"), ln);
		return -1;
	}
	generate_master_from_secret(&pk[0], _("raw secret key"), key);
	return 0;
}


int real_main(int argc, char **argv)
{
	const char *val;
	bool gen_master = false, gen_work = false, export_keys = false;
	bool import_keys = false, show_list = false;
	bool delete_key = false, add_raw = false, add_raw_sec = false;
	bool rename_key = false, alias_key = false, app_alias_key = false;
	bool show_sec = false, export_sec = false, all_keys = false, show_sigs = false;
	std::string key_ring;
	std::string key_name, export_name, import_name;
	std::vector<std::string> selected_names, selected_work_names;
	std::string password, errinfo;
	bool symencrypt = false, symdecrypt = false, pubencrypt = false, pubdecrypt = false;
	bool sign = false, verify = false, clearsign = false, clearverify = false, clearresig = false;
	bool sign_key = false, rm_signature = false, force = false;
	bool add_certs = false;
	bool sign_all_keys = false, check_ring = false, correct_ring = false;
	bool list_key_file = false, spoof = false;
	std::string key_file_name, master_file_name;
	bool ringless = false;
	bool armor = false, wipe_input = false, anonymous = false, dohide = false, doreveal = false;
	bool pack = false, pack_list = false, unpack = false, unpack_all = false;
	bool compress = true;
	bool dohidek = false, dorevealk = false;
	std::string txname, outname, packname, rx2name;
	int block_size = -1, block_filler = -1;
	bool verbose = false, something_done = false;
	Key_encoding kenc = key58;
	Key uraw;
	bool use_uraw = false;
	int shifts = 14, shifts_max = 0;


	Key_list selected_list;
	Key_list kl, master_key_list;
	bool key_list_changed = false;
	bool key_file_read = false;
	Key ringless_key;
	std::string master_pass;
	bool inplace_enc = false, inplace_dec = false;
	bool incpack = false;

	if (hasopt_long(&argc, argv, "--help")) {
		usage(std::cout);
		return 0;
	}

	if (hasopt_long(&argc, argv, "--verbose")) {
		verbose = true;
	}
	if (hasopt_long(&argc, argv, "--block-size", &val)) {
		char *strend;
		block_size = strtoul(val, &strend, 0);
		if (strend == val) {
			block_size = -1;
		}
	}
	if (hasopt_long(&argc, argv, "--block-filler", &val)) {
		char *strend;
		block_filler = strtoul(val, &strend, 0);
		if (strend == val) {
			block_filler = -1;
		}
	}
	if (hasopt_long(&argc, argv, "--shifts", &val)) {
		char *strend;
		shifts_max = shifts = strtoul(val, &strend, 0);
		if (strend == val) {
			shifts = 14;
		}
	}
	if (hasopt_long(&argc, argv, "--no-expand")) {
		block_filler = 0;
	}

	if (hasopt_long(&argc, argv, "--ringless")) {
		ringless = true;
	}
	if (hasopt_long(&argc, argv, "--keyring", &val)) {
		key_ring = val;
	}
	while (hasopt_long(&argc, argv, "--master", &val)) {
		master_file_name = val;
		master_pass.clear();
		master_key_list.clear();
		try {
			int count = read_keys(master_file_name, master_key_list, master_pass, false, false, &errinfo);
			if (count < 0 || !errinfo.empty()) {
				format(std::cerr, _("Error reading keys from %s. %s\n"), master_file_name, errinfo);
			} else {
				if (verbose) {
					format(std::cout, _("Read %d keys from the master file %s.\n"), count, master_file_name);
				}
			}
			for (unsigned i = 0; i < master_key_list.size(); ++i) {
				insert_key(kl, master_key_list[i], false);
			}
		} catch (...) {
		}
	}
	while (hasopt_long(&argc, argv, "--keyfile", &val)) {
		std::string pass;
		size_t start = kl.size();
		try {
			int count = read_keys(val, kl, pass, false, false, &errinfo);
			if (count < 0 || !errinfo.empty()) {
				format(std::cerr, _("Error reading keys from %s. %s\n"), val, errinfo);
			} else {
				if (verbose) {
					format(std::cout, _("Read %d keys from the master file %s.\n"), count, val);
				}
			}
		} catch (...) {
		}
		for (size_t i = start; i < kl.size(); ++i) {
			kl[i].write_what = Key::discard;
		}
	}

	if (hasopt_long(&argc, argv, "--gen-master", &val)) {
		gen_master = true;
		key_name = val;
	}
	if (hasopt_long(&argc, argv, "--gen-work")) {
		gen_work = true;
	}
	if (hasopt_long(&argc, argv, "--export", &val)) {
		export_keys = true;
		export_name = val;
	}
	if (hasopt_long(&argc, argv, "--export-sec", &val)) {
		export_sec = true;
		export_name = val;
	}
	if (hasopt_long(&argc, argv, "--import", &val)) {
		import_keys = true;
		import_name = val;
	}
	while (hasopt_long(&argc, argv, "--lockid", &val)) {
		std::vector<uint8_t> pk;
		if (0 != decode_key(val, pk) || pk.size() != 32) {
			format(std::cerr, _("There is an error in the given key %s. Check the input.\n"), val);
			return -1;
		}
		Key k;
		memcpy(k.pair.xp.b, &pk[0], 32);
		k.secret_avail = false;
		encode_key(k.pair.xp.b, 32, k.enc, false);
		insert_key(selected_list, k, false);
	}

	if (hasopt_long(&argc, argv, "--all")) {
		all_keys = true;
	}
	if (hasopt_long(&argc, argv, "--delete")) {
		delete_key = true;
	}
	if (hasopt_long(&argc, argv, "--add-raw")) {
		add_raw = true;
	}

	if (hasopt_long(&argc, argv, "--uraw-file", &val)) {
		if (read_private_from_file(val, &uraw) != 0) {
			format(std::cerr, _("Could not read the raw secret key from the file %s\n"), val);
			return -1;
		}
		use_uraw = true;
	}

	if (hasopt_long(&argc, argv, "--uraw")) {
		if (make_private_from_raw(&uraw) != 0) {
			format(std::cerr, _("Could not create a key from the raw secret key\n"));
			return -1;
		}
		use_uraw = true;
	}

	if (hasopt_long(&argc, argv, "--rename", &val)) {
		rename_key = true;
		key_name = val;
	}
	if (hasopt_long(&argc, argv, "--alias", &val)) {
		alias_key = true;
		key_name = val;
	}
	if (hasopt_long(&argc, argv, "--app-alias", &val)) {
		app_alias_key = true;
		key_name = val;
	}
	if (hasopt_long(&argc, argv, "--add-raw")) {
		add_raw = true;
	}
	if (hasopt_long(&argc, argv, "--add-raw-sec")) {
		add_raw_sec = true;
	}
	if (hasopt_long(&argc, argv, "--list")) {
		show_list = true;
		show_sigs = true;
	}
	if (hasopt_long(&argc, argv, "--list-sec")) {
		show_sec = true;
		show_sigs = true;
	}
	if (hasopt_long(&argc, argv, "--list-file", &val)) {
		list_key_file = true;
		key_file_name = val;
	}
	if (hasopt_long(&argc, argv, "--passfile", &val)) {
		std::ifstream is(val);
		getline(is, password);
	}
	if (hasopt_long(&argc, argv, "--certify-by", &val)) {
		sign_key = true;
		txname = val;
	}
	if (hasopt_long(&argc, argv, "--certify-raw")) {
		sign_key = true;
		if (make_private_from_raw(&uraw) != 0) {
			return -1;
		}
		use_uraw = true;
	}
	if (hasopt_long(&argc, argv, "--rm-cert", &val)) {
		rm_signature = true;
		txname = val;
	}
	if (hasopt_long(&argc, argv, "--certify-lockfile-by", &val)) {
		sign_all_keys = true;
		txname = val;
	}
	if (hasopt_long(&argc, argv, "--sign")) {
		sign = true;
	}
	if (hasopt_long(&argc, argv, "--add-certs")) {
		add_certs = true;
	}
	if (hasopt_long(&argc, argv, "--clearsign")) {
		clearsign = true;
	}
	if (hasopt_long(&argc, argv, "--clearresign")) {
		clearresig = true;
	}
	if (hasopt_long(&argc, argv, "--clearverify")) {
		clearverify = true;
	}
	if (hasopt_long(&argc, argv, "--verify")) {
		verify = true;
	}
	if (hasopt_long(&argc, argv, "--armor")) {
		armor = true;
	}
	if (hasopt_long(&argc, argv, "--check")) {
		check_ring = true;
	}
	if (hasopt_long(&argc, argv, "--correct")) {
		check_ring = true;
		correct_ring = true;
	}
	if (hasopt_long(&argc, argv, "--wipe")) {
		wipe_input = true;
	}
	if (hasopt_long(&argc, argv, "--hex")) {
		kenc = key16;
	}
	if (hasopt_long(&argc, argv, "--icao")) {
		kenc = key32;
	}
	if (hasopt_long(&argc, argv, "--pack")) {
		pack = true;
	}
	if (hasopt_long(&argc, argv, "--noz")) {
		compress = false;
	}
	if (hasopt_long(&argc, argv, "--pack-list")) {
		pack_list = true;
	}
	if (hasopt_long(&argc, argv, "--output", &val)) {
		outname = val;
	}
	if (hasopt_long(&argc, argv, "--unpack", &val)) {
		unpack = true;
		packname = val;
	}
	if (hasopt_long(&argc, argv, "--unpack-all", &val)) {
		unpack_all = true;
		packname = val;
	}
	if (hasopt_long(&argc, argv, "--spoof")) {
		spoof = true;
	}
	if (hasopt_long(&argc, argv, "--hide")) {
		dohide = true;
	}
	if (hasopt_long(&argc, argv, "--reveal")) {
		doreveal = true;
	}
	if (hasopt_long(&argc, argv, "--hidek", &val)) {
		rx2name = val;
		dohidek = true;
	}
	if (hasopt_long(&argc, argv, "--revealk", &val)) {
		rx2name = val;
		dorevealk = true;
	}
	if (hasopt_long(&argc, argv, "--de")) {
		pubdecrypt = true;
	}
	if (hasopt_long(&argc, argv,"--dc")) {
		symdecrypt = true;
	}
	if (hasopt_long (&argc, argv, "--inplace-enc")) {
		inplace_enc = true;
	}
	if (hasopt_long (&argc, argv, "--inplace-dec")) {
		inplace_dec = true;
	}
	if (hasopt_long (&argc, argv, "--incpack")) {
		incpack = true;
	}
	while (hasopt_long(&argc, argv, "--recipient", &val)) {
		selected_work_names.push_back(val);
	}


	int opt;
	while ((opt = hasopt(&argc, argv, "hveEr:fscCu:o:kKp:a", &val)) > 0) {
		switch (opt) {
		case 'v':
			verify = true;
			break;

		case 'h':
			usage(std::cout);
			return 0;

		case 'e':
			pubencrypt = true;
			break;

		case 'E':
			pubdecrypt = true;
			break;

		case 's':
			sign = true;
			break;

		case 'p':
			selected_names.push_back(val);
			break;

		case 'r':
			selected_work_names.push_back(val);
			break;

		case 'f':
			force = true;
			break;

		case 'c':
			symencrypt = true;
			break;

		case 'C':
			symdecrypt = true;
			break;

		case 'u':
			txname = val;
			break;

		case 'o':
			outname = val;
			break;

		case 'k':
			show_list = true;
			break;

		case 'K':
			show_sec = true;
			break;

		case 'a':
			anonymous = true;
			break;

		default:
			format(std::cerr, _("Unknown option %c\n"), char(opt));
		}
	}

	if (verbose) {
		if (block_filler != -1) {
			std::cout << "block_filler=" << block_filler << '\n';
		}
		if (block_size != -1) {
			std::cout << "block_size=" << block_size << '\n';
		}
	}

	if (dohide) {
		if (outname.empty()) {
			format(std::cerr, _("I need the name of the output file."));
			return -1;
		}
		if (argc != 3) {
			format(std::cerr, _("Usage is amber --hide bogusfilename realfilename\n"));
			return -1;
		}
		std::string bogus_pass, real_pass;
		get_password(_("Password for bogus file? "), bogus_pass);
		get_password(_("Password for real file? "), real_pass);
		hide(outname.c_str(), argv[1], argv[2], bogus_pass.c_str(),
		     real_pass.c_str(), block_size, block_filler, shifts);
		return 0;
	}

	if (doreveal) {
		if (outname.empty()) {
			format(std::cerr, _("I need the name of the output file."));
			return -1;
		}
		if (argc != 2) {
			format(std::cerr, _("Usage is --reveal encrypted_file_name"));
			return -1;
		}
		std::string bogus_pass, real_pass;
		get_password(_("Password for bogus file? "), bogus_pass);
		get_password(_("Password for real file? "), real_pass);
		reveal(outname.c_str(), argv[1], bogus_pass.c_str(),
		       real_pass.c_str());
		return 0;
	}


	if (key_ring.empty()) {
		const char *krn = getenv("AMBER_KEYRING");
		if (krn && strstr(krn, ".cha") != NULL) {
			key_ring = krn;
		} else {
			for (auto s: { "amber.keys.cha", "amber.keys" }) {
				std::ifstream test(s);
				if (test) {
					key_ring = s;
					break;
				}
			}
		}
		if (key_ring.empty()) {
			key_ring = "amber.keys.cha";
		}
	}

	if (inplace_enc) {
		if (password.empty()) {
			get_password (_("Password for output file: "), password);
			std::string p2;
			get_password (_("Repeat the password: "), p2);
			if (password != p2) {
				throw_rte (_("The supplied passwords do not match!\n"));
			}
		}
		for (int i = 1; i < argc; ++i) {
			inplace_encrypt (argv[i], password.c_str(), shifts);
		}
		return 0;
	}

	if (inplace_dec) {
		if (password.empty()) {
			get_password (_("Password for input file: "), password);
		}
		for (int i = 1; i < argc; ++i) {
			inplace_decrypt (argv[i], password.c_str(), shifts_max);
		}
		return 0;
	}

	if (pack && !symencrypt && !pubencrypt) {
		if (outname.empty()) {
			format(std::cout, _("In need the name of the output file\n"));
			return -1;
		}
		plain_pack(outname.c_str(), argc - 1, argv + 1, compress, verbose);
		return 0;
	}
	if (incpack && !symencrypt && !pubencrypt) {
		if (outname.empty()) {
			format(std::cout, _("In need the name of the output file\n"));
			return -1;
		}
		plain_incremental_pack(outname.c_str(), argc - 1, argv + 1, verbose);
		return 0;
	}

	if (symencrypt) {
		if (pack) {
			if (outname.empty()) {
				format(std::cout, _("In need the name of the output file\n"));
				return -1;
			}
			sym_pack(outname.c_str(), argc - 1, argv + 1, password,
			         block_size, block_filler, shifts, compress, verbose);
		} else if (argc == 2 && !outname.empty()) {
			sym_encrypt(argv[1], outname.c_str(), password, block_size, block_filler, shifts, wipe_input);
		} else {
			std::string enc;
			for (int i = 1; i < argc; ++i) {
				enc = argv[i];
				enc.append(".cha");
				if (verbose) {
					format(std::cout, _("Encrypting %s to %s\n"), argv[i], enc);
				}
				sym_encrypt(argv[i], enc.c_str(), password, block_size, block_filler, shifts, wipe_input);
			}
		}
		return 0;
	}

	if (!symdecrypt && !pubdecrypt) {
		if (pack_list) {
			for (int i = 1; i < argc; ++i) {
				plain_pack_list (argv[i]);
			}
			return 0;
		} else if (unpack) {
			plain_unpack (packname.c_str(), argc - 1, argv + 1, verbose, outname == "-");
			return 0;
		} else if (unpack_all) {
			plain_unpack_all (packname.c_str(), verbose, outname == "-");
			return 0;
		}
	}

	if (symdecrypt) {
		if (pack_list) {
			for (int i = 1; i < argc; ++i) {
				sym_pack_list(argv[i], password, shifts_max);
			}
		} else if (unpack) {
			sym_unpack (packname.c_str(), argc - 1, argv + 1, password, verbose, outname == "-", shifts_max);
		} else if (unpack_all) {
			sym_unpack_all (packname.c_str(), password, verbose, outname == "-", shifts_max);
		} else if (argc == 2 && !outname.empty()) {
			sym_decrypt(argv[1], outname.c_str(), password, verbose, shifts_max);
		} else {
			std::string enc;
			for (int i = 1; i < argc; ++i) {
				enc = argv[i];
				if (ends_with(enc, ".cha")) {
					enc.resize(enc.size() - 4);
				} else {
					enc.append(".pt");
				}
				if (verbose) {
					format(std::cout, _("Decrypting %s to %s\n"), argv[i], enc);
				}
				sym_decrypt(argv[i], enc.c_str(), password, verbose, shifts_max);
			}
		}

		return 0;
	}


	if (!master_file_name.empty() && !gen_master) {
		for (size_t i = 0; i < kl.size(); ++i) {
			kl[i].write_what = Key::write_pub;
		}
	}


	if (ringless) {
		if (!verify && !clearverify) {
			if (password.empty()) {
				get_password(_("Password: "), password);
			}
			blake2b (ringless_key.pair.xs.b, 32, NULL, 0, password.c_str(), password.size());
show_block (std::cout, "seed", ringless_key.pair.xs.b, 32);			
			cu25519_generate (&ringless_key.pair);
			encode_key(ringless_key.pair.xp.b, 32, ringless_key.enc, false);
			ringless_key.name = _("Password based key");
			ringless_key.secret_avail = true;
			list_key(ringless_key, std::cout, true, show_sigs, NULL, NULL, kenc);
			kl.push_back(ringless_key);
		}
	}

	try {
		int count = read_keys(key_ring, kl, password, check_ring, false, &errinfo);
		if (count < 0 || !errinfo.empty()) {
			format(std::cerr, _("Error reading keys from %s. %s\n"), key_ring, errinfo);
			if (correct_ring) key_list_changed = true;
		} else {
			key_file_read = true;
			if (verbose) {
				format(std::cout, _("Read %d keys.\n"), count);
			}
		}
	} catch (...) {
		if (!gen_master && !gen_work) throw;
		// If it is a new ring then it is ok that we can't read.
	}


	// We use the random generator to generate the keys. We add the provided
	// password as a source of additional entropy. However the security of
	// Curve25519 relies on having keys with 251 bits of entropy. No
	// reasonable password can provide this amount of entropy. Therefore the
	// quality of the generated keys depends almost exclusively on the
	// quality of the system's random number generator.
	Keyed_random kr(password.c_str(), password.size());

	if (gen_master) {
		uint8_t random[32];
		kr.get_bytes(random, 32);
		Key k;
		generate_master_key(random, key_name.c_str(), &k);
		list_key(k, std::cout, true, false, NULL, NULL, kenc);
		master_key_list.push_back(k);
		if (!master_file_name.empty()) {
			save_key_file(master_key_list, master_file_name, master_pass, false);
			k.secret_avail = false;
		}
		kl.push_back(k);
		key_list_changed = true;
		something_done = true;
	}

	if (gen_work) {
		uint8_t random[32];
		kr.get_bytes(random, 32);
		Key k, master;
		if (use_uraw) {
			const Key *pm = find_key(kl, uraw.pair.xp);
			if (!pm) {
				throw_rte(_("The given raw key has no entry in the key ring."));
			}
			master = *pm;
			memcpy(master.pair.xs.b, uraw.pair.xs.b, 32);
			master.secret_avail = true;
		} else {
			select_recent_one(kl, txname, master, true);
		}
		generate_work_key(random, master.name.c_str(), &k, master);
		list_key(k, std::cout, true, false, NULL, NULL, kenc);
		kl.push_back(k);
		key_list_changed = true;
		something_done = true;
	}


	if (import_keys) {
		std::ifstream is(import_name.c_str(), is.binary);
		int count = read_keys(is, kl, true, force);
		if (count < 0) {
			format(std::cerr, _("Error reading keys. %s\n"), errinfo);
			return -1;
		} else {
			format(std::cerr, _("Read %d keys from file %s\n"), count, import_name);
		}
		key_list_changed = true;
		something_done = true;
	}

	if (list_key_file) {
		Key_list kf;
		errinfo.clear();
		int count = read_keys(key_file_name, kf, password, check_ring, false, &errinfo);
		if (count < 0 || !errinfo.empty()) {
			format(std::cerr, _("Error reading keys from the file %s. %s\n"), key_file_name, errinfo);
		}
		list_keys(kf, std::cout, false, true, &kl, kenc);
		something_done = true;
	}

	if (all_keys) {
		selected_list = kl;
	} else {
		if (!selected_work_names.empty()) {
			select_last_keys(kl, selected_work_names, selected_list);
		}
		if (!selected_names.empty()) {
			select_keys(kl, selected_names, selected_list);
		}
	}
	list_keys(selected_list, std::cout, true, show_sigs, &kl, kenc);
	selected_names.insert(selected_names.end(), selected_work_names.begin(), 
						  selected_work_names.end());

	if (delete_key) {
		if (delete_keys(kl, selected_list)) {
			key_list_changed = true;
		}
		something_done = true;
	}

	if (rename_key) {
		change_name(kl, selected_names, key_name.c_str());
		key_list_changed = true;
		something_done = true;
	}
	if (alias_key) {
		change_alias(kl, selected_names, key_name.c_str());
		key_list_changed = true;
		something_done = true;
	}
	if (app_alias_key) {
		append_alias(kl, selected_names, key_name.c_str());
		key_list_changed = true;
		something_done = true;
	}

	if (add_raw) {
		if (argc != 3) {
			std::cerr << _("usage is amber --add-raw <name> <key>\n");
			return -1;
		}
		std::vector<uint8_t> pk;
		if (0 != decode_key(argv[2], pk, kenc) || pk.size() != 32) {
			std::cerr << _("There is an error in the given key. Check the input.\n");
			return -1;
		}
		Key k;
		memcpy(k.pair.xp.b, &pk[0], 32);
		encode_key(k.pair.xp.b, 32, k.enc, false);
		k.name = argv[1];
		if (!insert_key(kl, k, force)) {
			std::cerr << _("Could not insert the key because it already exists.\n");
			return -1;
		} else {
			key_list_changed = true;
		}
		something_done = true;
	}

	if (add_raw_sec) {
		if (argc != 3) {
			std::cerr << _("usage is amber --add-raw-sec <name> <keyfile>\n");
			return -1;
		}
		Key k;
		if (read_private_from_file(argv[2], &k) != 0) {
			return -1;
		}
		k.master = false;
		k.name = argv[1];
		if (!insert_key(kl, k, force)) {
			std::cerr << _("Could not insert the key because it is already present.\n");
			return -1;
		}
		key_list_changed = true;
		something_done = true;
	}

	if (sign_key) {
		if (use_uraw) {
			if (0 != sign_keys(kl, uraw, selected_names)) {
				std::cerr << _("Could not certify the key.\n");
			}
		} else {
			if (0 != sign_keys(kl, txname.c_str(), selected_names)) {
				std::cerr << _("Could not certify the key.\n");
			}
		}
		key_list_changed = true;
		something_done = true;
	}

	if (sign_all_keys) {
		Key signer;
		if (use_uraw) {
			signer = uraw;
		} else {
			select_recent_one(kl, txname, signer, true);
		}
		std::ifstream is(argv[1], is.binary);
		if (!is) {
			format(std::cerr, _("Cannot open the file %s for reading.\n"), argv[1]);
			return -1;
		}
		std::string info;
		Key_list tosign;
		int count = read_keys(is, tosign, true, force);
		is.close();
		if (count < 0) {
			std::cerr << _("Could not read the keys to certify.\n");
			return -1;
		}
		sign_keys(tosign, signer);
		std::ofstream os(argv[1], os.binary);
		write_keys(os, tosign, true);
		something_done = true;
	}


	if (rm_signature) {
		remove_signature(kl, txname.c_str(), selected_names);
		key_list_changed = true;
		something_done = true;
	}

	std::sort(kl.begin(), kl.end(), [](const Key &k1, const Key &k2) {
			int cmp = strcmp(k1.name.c_str(), k2.name.c_str());
			// Primary order: name
			if (cmp < 0) return true;
			if (cmp > 0) return false;
			// for same name sort the master keys first.
			if (k1.master && !k2.master) return true;
			if (!k1.master && k2.master) return false;
			// Both keys have the same name and both are master or both are
			// working keys. Sort by creation time in reverse order.
			if (k1.creation_time > k2.creation_time) return true;
			return false;
		});

	if (show_sec) {
		list_keys(kl, std::cout, false, show_sigs, NULL, kenc);
		something_done = true;
	} else if (show_list) {
		list_keys(kl, std::cout, true, show_sigs, NULL, kenc);
		something_done = true;
	}

	if (export_keys) {
		std::ofstream os(export_name.c_str(), os.binary);
		write_keys(os, selected_list, true);
		something_done = true;
	}
	if (export_sec) {
		std::ofstream os(export_name.c_str(), os.binary);
		write_keys(os, selected_list, false);
		something_done = true;
	}

	if (check_ring) {
		std::vector<bool> sigok;
		for (unsigned i = 0; i < kl.size(); ++i) {
			if (!verify_key_sigs_ok(kl[i], sigok)) {
				format(std::cerr, _("Error in signatures of %s [%s]\n"), kl[i].name, kl[i].enc);
			}
		}
		something_done = true;
	}


	if (key_list_changed) {
		save_key_file(kl, key_ring, password, !key_file_read);
	}

	if (pubencrypt || spoof || dohidek) {
		Key sender;
		if (anonymous) {
			memset(sender.pair.xs.b, 0, 32);
			memset(sender.pair.xp.b, 0, 32);
			sender.secret_avail = true;
		} else if (ringless) {
			sender = ringless_key;
		} else if (use_uraw) {
			sender = uraw;
		} else {
			select_recent_one(kl, txname, sender, false);
			format(std::cerr, _("Sender key:\n"));
			list_key(sender, std::cerr, true, false, &kl, NULL, kenc);
			if (!sender.secret_avail) {
				format(std::cerr, _("Sorry but the selected sender key is not available. Only the padlock is present.\n"));
				return -1;
			}
		}

		size_t nrx = selected_list.size();
		if (nrx == 0) {
			format(std::cout, _("No recipients have been selected.\n"));
			return -1;
		}

		if (pack) {
			if (outname.empty()) {
				format(std::cout, _("In need the name of the output file\n"));
				return -1;
			}
			pub_pack(outname.c_str(), argc - 1, argv + 1, sender, 
					 selected_list, block_size, block_filler, compress, 
					 verbose, spoof);
		} else if (argc == 2 && !outname.empty()) {
			if (spoof) {
				pub_spoof(argv[1], outname.c_str(), sender, selected_list,
				          block_size, block_filler);
			} else {
				pub_encrypt(argv[1], outname.c_str(), sender, selected_list,
				            block_size, block_filler, wipe_input);
			}
		} else if (dohidek) {
			if (argc != 3) {
				throw_rte(_("Usage is --dohidek <rx2> bogus real"));
			}
			std::vector<Cu25519Ris> rx(selected_list.size());
			for (unsigned i = 0; i < selected_list.size(); ++i) {
				rx[i] = selected_list[i].pair.xp;
			}
			Key key2;
			select_recent_one(kl, rx2name, key2, false);
			hide(outname.c_str(), argv[1], argv[2], sender.pair,
			     rx, key2.pair.xp, block_size, block_filler);

		} else {
			std::string enc;
			for (int i = 1; i < argc; ++i) {
				enc = argv[i];
				enc.append(".cha");
				if (verbose) {
					format(std::cout, _("Encrypting %s to %s\n"), argv[i], enc);
				}
				if (spoof) {
					pub_spoof(argv[1], enc.c_str(), sender, selected_list,
					          block_size, block_filler);
				} else {
					pub_encrypt(argv[1], enc.c_str(), sender, selected_list,
					            block_size, block_filler, wipe_input);
				}
			}
		}
		return 0;
	}

	if (pubdecrypt || dorevealk) {
		Key rx;
		if (ringless) {
			rx = ringless_key;
		} else if (use_uraw) {
			rx = uraw;
		} else {
			select_recent_one(kl, txname, rx, false);
		}
		if (!rx.secret_avail) {
			format(std::cerr, _("Sorry but the selected padlock has no private key available.\n"));
			return -1;
		}
		std::string info;
		Cu25519Ris sender;

		if (pack_list) {
			for (int i = 1; i < argc; ++i) {
				int nrx;
				pub_pack_list(argv[i], rx, &sender, &nrx);
				find_key_name(kl, sender, info, kenc);
				format (std::cerr, _("Pack encrypted by %s\n"), info);
				format (std::cerr, _("There are %d recipients.\n"), nrx);
			}
		} else if (unpack) {
			int nrx;
			pub_unpack (packname.c_str(), argc - 1, argv + 1, rx, &sender, &nrx, verbose, outname == "-");
			find_key_name(kl, sender, info, kenc);
			format (std::cerr, _("Pack encrypted by %s\n"), info);
			format (std::cerr, _("There are %d recipients.\n"), nrx);
		} else if (unpack_all) {
			int nrx;
			pub_unpack_all (packname.c_str(), rx, &sender, &nrx, verbose, outname == "-");
			find_key_name(kl, sender, info, kenc);
			format (std::cerr, _("Pack encrypted by %s\n"), info);
			format (std::cerr, _("There are %d recipients.\n"), nrx);
		} else if (dorevealk) {
			if (argc != 2) {
				throw_rte(_("Usage is --revealk <rx2> input_file"));
			}
			Key key2;
			select_one(kl, rx2name, key2);
			int nrx;
			reveal(outname.c_str(), argv[1], rx.pair, key2.pair.xs, &sender, &nrx);
			find_key_name(kl, sender, info, kenc);
			format (std::cerr, _("Message encrypted by %s\n"), info);
			format (std::cerr, _("There are %d recipients.\n"), nrx);
		} else if (argc == 2 && !outname.empty()) {
			int nrx;
			pub_decrypt(argv[1], outname.c_str(), rx, sender, &nrx, verbose);
			find_key_name(kl, sender, info, kenc);
			format (std::cerr, _("Message encrypted by %s\n"), info);
			format (std::cerr, _("There are %d recipients.\n"), nrx);
		} else {
			std::string enc;
			for (int i = 1; i < argc; ++i) {
				enc = argv[i];
				if (ends_with(enc, ".cha")) {
					enc.resize(enc.size() - 4);
				} else {
					enc.append(".pt");
				}
				if (verbose) {
					format(std::cout, _("Decrypting file %s to %s\n"), argv[i], enc);
				}
				int nrx;
				pub_decrypt(argv[i], enc.c_str(), rx, sender, &nrx, verbose);
				find_key_name(kl, sender, info, kenc);
				format (std::cerr, _("Message encrypted by %s\n"), info);
				format (std::cerr, _("There are %d recipients.\n"), nrx);
			}
		}
		return 0;
	}

	if (sign) {
		if (argc != 3 && argc != 4) {
			std::cerr << _("usage is amber --s infile outfile [comment]\n");
			return -1;
		}
		Key signer;
		if (ringless) {
			signer = ringless_key;
		} else if (use_uraw) {
			signer = uraw;
		} else {
			select_recent_one(kl, txname, signer, false);
		}
		sign_file(argv[1], argv[2], signer, argc == 4 ? argv[3] : "", armor, add_certs);
		return 0;
	}

	if (clearsign) {
		if (argc != 3 && argc != 4) {
			std::cerr << _("usage is amber --clearsign infile outfile [comment]\n");
			return -1;
		}
		Key signer;
		if (ringless) {
			signer = ringless_key;
		} else if (use_uraw) {
			signer = uraw;
		} else {
			select_recent_one(kl, txname, signer, false);
		}
		std::string info;
		clear_sign(argv[1], argv[2], signer, argc == 4 ? argv[3] : NULL, add_certs);
		return 0;
	}

	if (clearresig) {
		if (argc != 2 && argc != 3) {
			std::cerr << _("usage is amber --clearresig file [comment]\n");
			return -1;
		}
		Key signer;
		if (ringless) {
			signer = ringless_key;
		} else if (use_uraw) {
			signer = uraw;
		} else {
			select_recent_one(kl, txname, signer, false);
		}
		std::string info;
		clear_sign_again(argv[1], signer, argc == 3 ? argv[2] : NULL, add_certs);
		return 0;
	}

	if (verify) {
		if (argc != 3) {
			std::cerr << _("usage is amber -v file sigfile\n");
			return -1;
		}
		Key signer;
		std::string comment;
		time_t date;
		int res = verify_file(argv[1], argv[2], signer, &comment, &date, armor);
		if (res != 0) {
			format(std::cout, _("The signature for the file %s is wrong.\n"), argv[1]);
		} else {
			format(std::cout, _("The file was correctly signed by\n"));
			show_sig_key (kl, signer, kenc);
			if (!comment.empty()) {
				format(std::cout, _("Signed comment: '%s'\n"), comment);
			}
			char s[100];
			strftime (s, sizeof s, "Signed on %F %T UTC", gmtime(&date));
			std::cout << s;
			strftime (s, sizeof s, " = %F %T %z", localtime(&date));
			std::cout << s << '\n';
		}
		return res;
	}

	if (clearverify) {
		if (argc != 2) {
			std::cerr << _("usage is amber --clearverify file\n");
			return -1;
		}
		Key signer;
		std::string comment;
		time_t date;
		int res = clear_verify(argv[1], signer, &comment, &date);
		if (res != 0) {
			format(std::cout, _("The signature for the file %s is wrong.\n"), argv[1]);
		} else {
			format (std::cout, _("The file was correctly signed by\n"));
			show_sig_key (kl, signer, kenc);
			if (!comment.empty()) {
				format (std::cout, _("Comment: %s\n"), comment);
			}
			char s[100];
			strftime (s, sizeof s, "Signed on %F %T UTC", gmtime(&date));
			std::cout << s;
			strftime (s, sizeof s, " = %F %T %z", localtime(&date));
			std::cout << s << '\n';
		}
		return res;
	}

	if (!something_done) {
		format(std::cerr, _("Nothing was perfomed. Did you forget to specify a command?"));
	}
	return 0;
}


int main(int argc, char **argv)
{
	return run_main(argc, argv, real_main);
}


