#ifndef AMBER_PACK_HPP
#define AMBER_PACK_HPP

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



#include <string>

#include "soname.hpp"
#include "keys.hpp"


// Packed archives.

namespace amber {   namespace AMBER_SONAME {


// Pack files without encryption.
EXPORTFN
void plain_pack (const char *oname, int nf, char **files, bool compress, bool verbose);

// List all the files in iname.
EXPORTFN void plain_pack_list (const char *iname);

// Extract the given files.
EXPORTFN
void plain_unpack (const char *packed, int nf, char **files, bool verbose,
                   bool console);

EXPORTFN
void plain_unpack_all (const char *packed, bool verbose, bool console);


// Pack the files files[0..nf[ into the file oname. Pass the password, the
// block size and block filler size. Shifts is the shifts parameter for
// scrypt_blake2s. Set verbose to true to output information while packing.
// If the password is empty then the program will prompt the user.
EXPORTFN
void sym_pack(const char *oname, int nf, char **files, std::string &password,
              int bs, int bf, int shifts, bool compress, bool verbose);

// List the files that are stored in the archive iname. If the password is
// empty then the program will prompt the user.
EXPORTFN
void sym_pack_list (const char *iname, std::string &password, int shifts_max);

// Unpack from the archive packed the files named files[0] to files[nf-1]. If
// the name of one of the files to unpack is a directory within the packed
// file then it will unpack the whole directory. If the password is empty
// then the program will prompt the user. Set verbose if you want more
// information to be displayed while unpacking. Set console if you want to
// show the contents of the packed files without unpacking them.
EXPORTFN void sym_unpack (const char *packed, int nf, char **files,
                 std::string &password, bool verbose, bool console, int shifts_max);

// Extract all the files from the archive. If the password is empty
// then the program will prompt the user. Set verbose if you want more
// information to be displayed while unpacking. Set console if you want to
// show the contents of the packed files without unpacking them.
EXPORTFN
void sym_unpack_all (const char *packed, std::string &password, bool verbose,
                     bool console, int shifts_max);


// Same with lock/key based encryption.

// Pack into the output archive oname the files files[0..nf[. The sender's
// key is passed in sender. The list of the recipients is in rx. bs is the
// block size to be used for the encryption. bf is the block filler size to
// be used. Set verbose to display additional information while packing. Set
// spoof to create an archive that looks like if it was encrypted by the
// first recipient for the sender.
EXPORTFN
void pub_pack(const char *oname, int nf, char **files, const Key &sender,
              const Key_list &rx, int bs, int bf, bool compress,
              bool verbose, bool spoof);

// Pass the decryption key in rx. It will list the contents of the archive
// and put in sender the public key of the sender.
EXPORTFN
void pub_pack_list (const char *iname, const Key &rx, Cu25519Ris *sender, int *nrx);

// Unpack the files whose names are stored in files[0..nf[. Pass the
// decryption key in rx. The public key of the sender will be stored in
// sender. Set verbose for additional information while unpacking. Set
// console if you want to display the contents of the packed files to the
// console without unpacking them.
EXPORTFN
void pub_unpack (const char *packed, int nf, char **files, const Key &rx,
                 Cu25519Ris *sender, int *nrx, bool verbose, bool console);
EXPORTFN
void pub_unpack_all (const char *packed, const Key &rx,
                 Cu25519Ris *sender, int *nrx, bool verbose, bool console);


EXPORTFN
void plain_incremental_pack (const char *oname, int nf, char **files,  bool verbose);

}}

#endif


