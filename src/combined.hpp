#ifndef AMBER_COMBINED_HPP
#define AMBER_COMBINED_HPP

/* Copyright (c) 2015-2019, Pelayo Bernedo.
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
#include "keys.hpp"


// High level interfaces which combine other primitives. They support
// encryption/decryption and signatures for whole files.

namespace amber {   namespace AMBER_SONAME {

// Encrypt or decrypt the input file iname to the output file oname, based on the given
// password. If password is empty it will prompt for one. If wipe is true it
// will fill the source file with random data. This is better than just
// deleting the file. We have no portable way to ensure that the file's data
// is removed and not just marked for deletion. By rewriting the file's
// contents we just increase the likelihood that the data is actually
// overwritten. These functions throw exceptions on failure. bs is the block
// size to be used and bf is the block filler size. Passing -1 means that the
// program should select random values. Shifts is the number of shifts to
// pass to the scrypt function.
EXPORTFN
void sym_encrypt(const char *iname, const char *oname, std::string &password,
                 int bs=-1, int bf=-1, int shifts=14, bool wipe=false);
EXPORTFN
void sym_decrypt(const char *iname, const char *oname, std::string &password,
                 bool verbose=false, int shifts_max=0);



// Encrypt or decrypt the input file iname to the output file oname, based on the given
// public key parameters.

// Pass the key of the sender and the list of keys of the receivers.
EXPORTFN
void pub_encrypt(const char *iname, const char *oname, const Key &sender,
                 const Key_list &rx, int bs=-1, int bf=-1, bool wipe=false);

// Pass the key of the receiver and it will return the public key of the sender.
EXPORTFN
void pub_decrypt(const char *iname, const char *oname, const Key &rx,
                 Cu25519Ris &sender, int *nrx, bool verbose);

// Create an encrypted file that looks like it was sent by the first key in
// sender_dummies to the key of rx. Rx must have the private key available.
// The keys in sender_dummies need only the public part. The keys other than
// the first one of sender_dummies are used as dummy receivers.
EXPORTFN
void pub_spoof(const char *iname, const char *oname, const Key &rx,
               const Key_list &sender_dummies, int bs, int bf);


// Sign the contents of the file iname and put the signature in the file
// oname. The comment will be included in the signature and is part of the
// signed text. If b64 is true then the signature will be base64 encoded.
EXPORTFN
void sign_file(const char *iname, const char *oname, const Key &signer,
               const char *comment, bool b64, bool add_certs=false);

// Check the contents of the file iname against the signature in the file
// sname. The comment will be set to contain the signed comment present in
// the signature, if any. Set b64 to true is the signature is the file sname
// is encoded in base 64. Store in signer the public key of the signer.
// Return zero if the signature is valid.
EXPORTFN
int verify_file(const char *iname, const char *sname, Key &signer,
                std::string *comment, time_t *date, bool b64);

// Copy the text from the file iname to the file oname and append the
// signature to the text of oname. The signature is encoded in base 64.
EXPORTFN
void clear_sign(const char *iname, const char *oname, const Key &signer, const char *comment, bool add_certs);

// Verify the signature which has been appended to the text in name. Store in
// signer the public key of the signer. Return zero if the signature is valid.
EXPORTFN
int clear_verify(const char *name, Key &signer, std::string *comment, time_t *date);

// Modify the signature of the existing signed file so that is is correct with the
// current contents of the signed text. In this way you may directly modify the clear
// signed file and obtain a new signature.
EXPORTFN
void clear_sign_again(const char *name, const Key &signer, const char *comment, bool add_certs);

}}

#endif


