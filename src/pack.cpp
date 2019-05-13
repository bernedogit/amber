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



#include "soname.hpp"
#include <vector>
#include <string.h>
#include "misc.hpp"
#include "blockbuf.hpp"
#include "hasopt.hpp"
#include "blake2.hpp"
#include "keys.hpp"
#include "protobuf.hpp"
#include <iomanip>
#include <memory>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/time.h>

#include "zwrap.hpp"


namespace amber {   namespace AMBER_SONAME {


// Expand directory names into their contents.
static void expand_file (const char *name, std::vector<std::string> *expanded)
{
	struct stat st;
	if (stat(name, &st) != 0) {
		return;
	}

	if (S_ISDIR(st.st_mode)) {
		// Ensure we close the directory in the presence of exceptions.
		std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir(name), closedir);
		if (!dir) return;
		dirent *de;
		std::string root, comp;
		root = name;
		if (!root.empty() || root[root.size() - 1] != '/') {
			root += "/";
		}
		while ((de = readdir(dir.get())) != NULL) {
			if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
			comp = root + de->d_name;
			expand_file(comp.c_str(), expanded);
		}
		expanded->push_back (name);
	} else if (S_ISREG(st.st_mode)) {
		expanded->push_back(name);
	}
}

static void expand_files(int nf, char **files, std::vector<std::string> *expanded)
{
	for (int i = 0; i < nf; ++i) {
		expand_file(files[i], expanded);
	}
}


enum Pack_type { pack_header, pack_file, pack_item, pack_dir, pack_flag, pack_last };
enum Item_type { tag_pos, tag_compsz, tag_expsz, tag_name, tag_mode, tag_content, tag_mtime };

// Each Item is a directory entry in the packed archive's central directory.
// It contains the information about the file's properties and also its
// position within the packed archive.
struct Item {
	std::streamoff pos, comp_size, exp_size;
	uint32_t       mode;
	std::string    name;
	uint64_t       mtime_us;                // mtime in μs
	void write (Protobuf_writer &pw) const;
	void read (Protobuf_reader &pr);
};


void Item::write (Protobuf_writer &pw) const
{
	buffer<char, 300> b;

	pw.start_group (pack_item);

	pw.write_uint (tag_pos, pos);
	pw.write_uint (tag_compsz, comp_size);
	pw.write_uint (tag_expsz, exp_size);
	pw.write_uint (tag_mode, mode);
	pw.write_uint (tag_mtime, mtime_us);

	// Remove leading dotdots from the written path.
	const char *cp = name.c_str();
	while (cp[0] == '.' && cp[1] == '.' && cp[2] == '/') cp += 3;

	if (strstr (cp, "../") != 0) {
		throw_rte (_("Path with .. embedded. This can be a security problem! %s"), name);
	}

	pw.write_string (tag_name, cp);

	pw.end_group();
}

void Item::read (Protobuf_reader &pr)
{
	pos = comp_size = exp_size = 0;
	mode = 0;
	name.clear();

	uint32_t tagwt;
	uint64_t val;

	pr.add_requirement (tag_pos, pr.needed_once,
	                    tag_compsz, pr.optional_once,
	                    tag_expsz, pr.needed_once,
	                    tag_mode, pr.needed_once,
	                    tag_name, pr.needed_once,
	                    tag_mtime, pr.needed_once);

	while (pr.read_tagval (&tagwt, &val)) {
		switch (tagwt) {
		case maketag (tag_pos, varint):
			pos = val;
			break;

		case maketag (tag_compsz, varint):
			comp_size = val;
			break;

		case maketag (tag_expsz, varint):
			exp_size = val;
			break;

		case maketag (tag_mode, varint):
			mode = val;
			break;

		case maketag (tag_mtime, varint):
			mtime_us = val;
			break;

		case maketag (tag_name, length_val):
			name.resize (val);
			pr.get_bytes (&name[0], val);
			if (strstr (name.c_str(), "../") != 0) {
				throw_rte (_("Path with .. embedded. This can be a security problem! %s"), name);
			}
			break;

		default:
			pr.skip (tagwt, val);
		}
	}
}


// The packing and unpacking functions know nothing about encryption. They
// just read and write using a std::istream or std::ostream.
static
void pack (std::ostream &os, int nf, char **files, bool compress, bool verbose)
{
	std::vector<Item> pos;
	uint64_t count = 0;
	char buf[100000];

	Protobuf_writer pw (&os, pw.seek, 100000);

	// If the user just decrypts a packed archive then make sure that the
	// first line shows that it is a binary packed archive
	static const char header[] = "PACKED ARCHIVE\n\n";
	pw.write_string (pack_header, header);
	pw.write_uint (pack_flag, compress);


	std::vector<std::string> expanded;
	expand_files(nf, files, &expanded);

	for (unsigned i = 0; i < expanded.size(); ++i) {
		Item x;
		x.name = expanded[i];
		size_t exp_size = 0;
		struct stat st;
		if (stat(x.name.c_str(), &st) == 0) {
			x.mode = st.st_mode;
#ifdef _WIN32
			x.mtime_us = st.st_mtime * 1000000;
#else
			x.mtime_us = st.st_mtim.tv_sec * 1000000 + st.st_mtim.tv_nsec/1000;
#endif
		} else {
			x.mode = 0;
			x.mtime_us = 0;
		}
		std::ifstream is;
		if (S_ISREG(st.st_mode)) {
			is.open (expanded[i].c_str(), is.binary);
			if (!is) {
				throw_rte (_("Error while opening input file %s"), expanded[i]);
			}
		}

		buffer<char, sizeof buf> outbuf;
		ZWrapper zw;

		if (verbose) {
			std::cout << x.name << '\n';
		}

		pw.start_group (pack_file);
		pw.write_string (tag_name, &x.name[0]);
		pw.write_uint (tag_mode, x.mode);

		size_t start_size = count;

		if (S_ISREG(st.st_mode)) {
			pw.start_group (tag_content);
			pw.flush();
			x.pos = os.tellp();

			while (is) {
				is.read(buf, sizeof buf);
				exp_size += is.gcount();
				if (compress) {
					zw.compress (buf, is.gcount(), &outbuf);
					pw.add_bytes (&outbuf[0], outbuf.size());
					count += outbuf.size();
					outbuf.clear();
				} else {
					pw.add_bytes (buf, is.gcount());
					count += is.gcount();
				}
			}
			if (compress) {
				zw.flush(&outbuf);
				pw.add_bytes (&outbuf[0], outbuf.size());
				count += outbuf.size();
			}
			pw.end_group (true);
		}

		pw.end_group();
		pw.flush();

		x.comp_size = count - start_size;
		x.exp_size = exp_size;
		pos.push_back(x);
	}
	count = os.tellp();

	// Now write the central directory
	int flag = compress ? 1 : 0;
	pw.write_uint (pack_flag, flag);

	pw.start_group (pack_dir);
	for (unsigned i = 0; i < pos.size(); ++i) {
		pos[i].write(pw);
	}
	pw.end_group();
	pw.write_uint64 (pack_last, count);
}



void plain_pack (const char *oname, int nf, char **files, bool compress, bool verbose)
{
	std::ofstream os (oname, os.binary);
	if (!os) {
		throw_rte (_("Error while opening output file %s"), oname);
	}
	pack (os, nf, files, compress, verbose);
}


void sym_pack (const char *oname, int nf, char **files, std::string &password,
               int bs, int bf, int shifts, bool compress, bool verbose)
{
	if (password.empty()) {
		get_password(_("Password for output file: "), password);
		std::string p2;
		get_password(_("Repeat the password: "), p2);
		if (password != p2) {
			throw_rte(_("The supplied passwords do not match!\n"));
			return;
		}
	}
	amber::ofstream os(oname, password.c_str(), bs, bf, shifts);
	if (!os) {
		throw_rte (_("Error while opening output file %s"), oname);
	}
	pack (os, nf, files, compress, verbose);
}


void pub_pack (const char *oname, int nf, char **files, const Key &sender,
               const Key_list &rx, int bs, int bf, bool compress, bool verbose, bool spoof)
{
	std::vector<Cu25519Ris> curx(rx.size());
	for (unsigned i = 0; i < rx.size(); ++i) curx[i] = rx[i].pair.xp;
	amber::ofstream os;
	if (spoof) {
		os.open_spoof(oname, sender.pair, curx[0], curx.size() - 1, bs, bf);
	} else {
		os.open(oname, sender.pair, curx, bs, bf);
	}
	if (!os) {
		throw_rte (_("Error while opening output file %s"), oname);
	}
	pack (os, nf, files, compress, verbose);
}



static void read_index (std::istream &is, std::vector<Item> &index, bool *compressed,
                        std::streamoff *cendir=NULL)
{
	index.clear();
	is.seekg (-8, is.end);
	char buf[8];
	is.read (buf, 8);
	if (is.gcount() != 8) {
		throw_rte (_("Cannot read the last 8 bytes of the file."));
	}

	std::streamoff pos = leget64 (buf);
	is.seekg(pos, is.beg);
	if (!is) {
		throw_rte (_("Cannot seek in the file."));
	}

	if (cendir) {
		*cendir = pos;
	}

	Protobuf_reader pr (&is);

	Item x;
	uint32_t tagwt;
	uint64_t val;
	bool more = true;

	while (more && pr.read_tagval (&tagwt, &val)) {
		switch (tagwt) {
		case maketag (pack_flag, varint):
			*compressed = val & 1;
			break;

		case maketag (pack_dir, group_len):
			while (pr.read_tagval (&tagwt, &val)) {
				switch (tagwt) {
				case maketag (pack_item, group_len):
					x.read (pr);
					index.push_back (x);
					break;

				default:
					pr.skip (tagwt, val);
				}
			}
			more = false;
			break;

		default:
			pr.skip (tagwt, val);
		}
	}
}

// This is C90/C++98 compliant. The one below is C99/C++11.
static const char time_format[] = "%Y-%m-%d %H:%M:%S %z";
//static const char time_format[] = "%F %T %z";

static void pack_list (std::istream &is)
{
	std::vector<Item> index;
	bool compressed;
	read_index (is, index, &compressed);

	if (compressed) {
		std::cout << _("Compressed packed file\n");
	}
	std::cout << _("Comp. sz   Exp. sz   Mode         MTime              Name\n");
	std::streamoff comp_total = 0, exp_total = 0;
	for (unsigned i = 0; i < index.size(); ++i) {
		char tb[100];
		time_t ts = index[i].mtime_us / 1000000;
		strftime (tb, sizeof tb, time_format , localtime(&ts));
		format (std::cout, "%8u %9u %06o %s  %s\n", index[i].comp_size,
		        index[i].exp_size, index[i].mode, tb, index[i].name);
		comp_total += index[i].comp_size;
		exp_total += index[i].exp_size;
	}
	format(std::cout, _("Compressed size: %d    Expanded size: %d\n"),
	        comp_total, exp_total);
}


void plain_pack_list (const char *iname)
{
	std::ifstream is(iname, is.binary);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), iname);
	}
	pack_list (is);
}


void sym_pack_list (const char *iname, std::string &password, int shifts_max)
{
	if (password.empty()) {
		get_password(_("Password for packed file: "), password);
	}
	amber::ifstream is(iname, password.c_str(), shifts_max);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), iname);
	}
	pack_list (is);
}


void pub_pack_list (const char *iname, const Key &rx, Cu25519Ris *sender, int *nrx)
{
	amber::ifstream is(iname, rx.pair, sender, nrx);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), iname);
	}
	pack_list (is);
}


static void make_paths (const char *name)
{
	if (*name == 0) return;

	const char *beg = name;
	const char *end = name + 1;
	std::string path;

	while (*end) {
		while (*end && *end != '/') ++end;
		if (*end != '/') return;
		path.append (beg, end);
#ifdef _WIN32
		mkdir (path.c_str());
#else
		mkdir (path.c_str(), 0755);
#endif      
		path.append ("/");
		beg = end + 1;
		end = beg;
	}
}

#ifdef _WIN32
#define utimes(n,t)
#endif

static void unpack_file (std::istream &src, const Item &x, bool compressed, bool console)
{
	std::ostream *pos;
	std::ofstream fos;
	if (console) {
		pos = &std::cout;
	} else {
		if (S_ISDIR(x.mode)) {
			std::string ts = x.name + "/.";
			make_paths (ts.c_str());
			chmod(x.name.c_str(), x.mode & 0777);
			timeval tv[2];
			tv[0].tv_sec = x.mtime_us/1000000;
			tv[0].tv_usec = x.mtime_us % 1000000;
			tv[1] = tv[0];
			utimes (x.name.c_str(), tv);
			// These times will be preseved only if no further files are
			// written to the directory.
			return;
		}

		fos.open(x.name.c_str(), fos.binary);
		if (!fos) {
			make_paths(x.name.c_str());
			fos.open(x.name.c_str(), fos.binary);
			if (!fos)
			throw_rte (_("Cannot create the file %s"), x.name);
		}
		pos = &fos;
	}
	src.seekg(x.pos);
	if (!src) {
		throw_rte (_("Cannot seek in the source file."));
	}
	char buf[10000];

	ZWrapper zw;
	buffer<char, sizeof(buf) * 2> outbuf;

	std::streamoff pending = x.comp_size;
	while (src.good() && pending > 0) {
		long toread = pending > std::streamoff(sizeof(buf)) ? sizeof(buf) : pending;
		src.read(buf, toread);
		if (src.gcount() != toread) {
			throw_rte (_("Cannot read from the input file."));
		}

		if (compressed) {
			zw.expand(buf, toread, &outbuf);
			pos->write(&outbuf[0], outbuf.size());
			outbuf.clear();
		} else {
			pos->write(buf, toread);
		}
		pending -= toread;
	}

	if (compressed) {
		zw.flush(&outbuf);
		pos->write(&outbuf[0], outbuf.size());
	}

	if (pos == &fos) {
		fos.close();
		chmod(x.name.c_str(), x.mode & 0777);
		timeval tv[2];
		tv[0].tv_sec = x.mtime_us/1000000;
		tv[0].tv_usec = x.mtime_us % 1000000;
		tv[1] = tv[0];
		utimes (x.name.c_str(), tv);
	}
}


static void unpack (std::istream &is, int nf, char **files, bool verbose, bool console)
{
	std::vector<Item> index;
	bool compressed;
	read_index (is, index, &compressed);

	for (int i = 0; i < nf; ++i) {
		size_t flen = strlen(files[i]);
		for (unsigned j = 0; j < index.size(); ++j) {
			if (index[j].name == files[i]) {
				if (verbose) {
					std::cout << index[j].name << '\n';
				}
				unpack_file (is, index[j], compressed, console);
				break;
			} else if (strncmp(index[j].name.c_str(), files[i], flen) == 0 && index[j].name[flen] == '/') {
				if (verbose) {
					std::cout << index[j].name << '\n';
				}
				unpack_file (is, index[j], compressed, console);
			}
		}
	}
}


void plain_unpack (const char *packed, int nf, char **files,
                   bool verbose, bool console)
{                  
	std::ifstream is(packed, is.binary);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), packed);
	}
	unpack (is, nf, files, verbose, console);
}


void sym_unpack (const char *packed, int nf, char **files,
                 std::string &password, bool verbose, bool console, int shifts_max)
{
	if (password.empty()) {
		get_password(_("Password for packed file: "), password);
	}
	amber::ifstream is(packed, password.c_str(), shifts_max);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), packed);
	}
	unpack (is, nf, files, verbose, console);
}


void pub_unpack (const char *packed, int nf, char **files, const Key &rx,
                 Cu25519Ris *sender, int *nrx, bool verbose, bool console)
{
	amber::ifstream is(packed, rx.pair, sender, nrx);
	if (!is) {
		throw_rte(_("Error while opening input file %s"), packed);
	}
	unpack (is, nf, files, verbose, console);
}


static void unpack_all (std::istream &is, bool verbose, bool console)
{
	std::vector<Item> index;
	bool compressed;
	read_index (is, index, &compressed);

	for (unsigned j = 0; j < index.size(); ++j) {
		if (verbose) {
			format(std::cout, _("unpacking %s  (%d / %d bytes)\n"),
			    index[j].name, index[j].comp_size, index[j].exp_size);
		}
		unpack_file (is, index[j], compressed, console);
	}
}



void plain_unpack_all(const char *packed, bool verbose, bool console)
{
	std::ifstream is(packed, is.binary);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), packed);
	}
	unpack_all (is, verbose, console);
}


void sym_unpack_all(const char *packed, std::string &password, bool verbose,
                    bool console, int shifts_max)
{
	if (password.empty()) {
		get_password(_("Password for packed file: "), password);
	}
	amber::ifstream is(packed, password.c_str(), shifts_max);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), packed);
	}
	unpack_all (is, verbose, console);
}


void pub_unpack_all (const char *packed, const Key &rx,
                 Cu25519Ris *sender, int *nrx, bool verbose, bool console)
{
	amber::ifstream is(packed, rx.pair, sender, nrx);
	if (!is) {
		throw_rte (_("Error while opening input file %s"), packed);
	}
	unpack_all (is, verbose, console);
}

static
void incremental_pack (std::fstream &fs, int nf, char **files, bool verbose)
{
	std::vector<Item> old_index;
	bool compressed;
	std::streamoff cendir;
	read_index (fs, old_index, &compressed, &cendir);


	std::vector<Item> pos;
	uint64_t count = 0;
	char buf[100000];

	fs.seekp (cendir, fs.beg);

	Protobuf_writer pw (&fs, pw.seek, 100000);

	std::vector<std::string> expanded;
	expand_files(nf, files, &expanded);

	for (unsigned i = 0; i < expanded.size(); ++i) {
		Item x;
		x.name = expanded[i];
		size_t exp_size = 0;
		struct stat st;
		if (stat(x.name.c_str(), &st) == 0) {
			x.mode = st.st_mode;
			x.exp_size = st.st_size;
#ifdef _WIN32
			x.mtime_us = st.st_mtime * 1000000;
#else
			x.mtime_us = st.st_mtim.tv_sec * 1000000 + st.st_mtim.tv_nsec/1000;
#endif
		} else {
			x.mode = 0;
			x.exp_size = 0;
			x.mtime_us = 0;
		}

		bool found = false;
		for (unsigned j = 0; j < old_index.size(); ++j) {
			if (old_index[j].name == x.name && old_index[j].mtime_us >= x.mtime_us
					&& old_index[j].mode == x.mode && old_index[j].exp_size == x.exp_size) {
				// Skip existing file.
				x = old_index[j];
				found = true;
				break;
			}
		}

		if (!found) {
			std::ifstream is;
			if (S_ISREG(st.st_mode)) {
				is.open (expanded[i].c_str(), is.binary);
				if (!is) {
					throw_rte (_("Error while opening input file %s"), expanded[i]);
				}
			}

			buffer<char, sizeof buf> outbuf;
			ZWrapper zw;

			if (verbose) {
				std::cout << x.name << '\n';
			}

			pw.start_group (pack_file);
			pw.write_string (tag_name, &x.name[0]);
			pw.write_uint (tag_mode, x.mode);

			size_t start_size = count;

			if (S_ISREG(st.st_mode)) {
				pw.start_group (tag_content);
				pw.flush();
				x.pos = fs.tellp();

				while (is) {
					is.read(buf, sizeof buf);
					exp_size += is.gcount();
					if (compressed) {
						zw.compress (buf, is.gcount(), &outbuf);
						pw.add_bytes (&outbuf[0], outbuf.size());
						count += outbuf.size();
						outbuf.clear();
					} else {
						pw.add_bytes (buf, is.gcount());
						count += is.gcount();
					}
				}
				if (compressed) {
					zw.flush(&outbuf);
					pw.add_bytes (&outbuf[0], outbuf.size());
					count += outbuf.size();
				}
				pw.end_group (true);
			}

			pw.end_group();
			pw.flush();

			x.comp_size = count - start_size;
			x.exp_size = exp_size;
		}
		pos.push_back(x);
	}
	count = fs.tellp();

	// Now write the central directory
	int flag = compressed ? 1 : 0;
	pw.write_uint (pack_flag, flag);

	pw.start_group (pack_dir);
	for (unsigned i = 0; i < pos.size(); ++i) {
		pos[i].write(pw);
	}
	pw.end_group();
	pw.write_uint64 (pack_last, count);
}



void plain_incremental_pack (const char *oname, int nf, char **files,  bool verbose)
{
	std::fstream fs (oname, fs.binary | fs.in | fs.out);
	if (!fs) {
		throw_rte (_("Error while opening input/output file %s"), oname);
	}
	incremental_pack (fs, nf, files, verbose);
}

}}


