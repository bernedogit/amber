/*
 * Copyright (c) 2017-2018, Pelayo Bernedo
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

#include "noise.hpp"
#include "hkdf.hpp"
#include "hasopt.hpp"
#include "poly1305.hpp"


//debug
#include "misc.hpp"

namespace amber {   inline namespace AMBER_SONAME {


void hkdf2s (const uint8_t ck[32], const uint8_t *ikm, size_t ilen,
             uint8_t *v1, uint8_t *v2, uint8_t *v3)
{
	Hmac<Blake2s> hm (ck, 32);
	hm.update (ikm, ilen);
	uint8_t tmp[32];
	hm.final (tmp, 32);

	uint8_t b = 1;
	hm.reset (tmp, 32);
	hm.update (&b, 1);
	hm.final (v1, 32);

	if (v2) {
		b = 2;
		hm.reset (tmp, 32);
		hm.update (v1, 32);
		hm.update (&b, 1);
		hm.final (v2, 32);
		if (v3) {
			b = 3;
			hm.reset (tmp, 32);
			hm.update (v3, 32);
			hm.update (&b, 1);
			hm.final (v3, 32);
		}
	} else if (v3 != 0) {
		throw std::logic_error (_("You cannot ask for v3 when v2 is NULL."));
	}
}




void Cipher::encrypt_padded (const uint8_t *ad, size_t alen,
        const uint8_t *pt, size_t plen,
        size_t padlen, uint8_t *ct)
{
	size_t tot = plen + padlen + 2;
	if (tot + 16 >= 0x10000) {
		// Noise allows only 64 KB as maximum length.
		throw std::logic_error (_("The total length of the padded encrypted packet exceeeds 64 KB."));
	}
	Chacha cha (key, n);
	uint8_t two[2];
	be16enc (two, plen);
	cha.doxor (ct, two, 2);
	cha.doxor (ct + 2, pt, plen);
	cha.copy (ct + 2 + plen, padlen);

	poly1305_context poc;
	uint8_t stream[64];
	chacha20 (stream, key, n, 0);
	poly1305_init (&poc, stream);
	if (alen != 0) {
		poly1305_update (&poc, ad, alen);
		poly1305_pad16 (&poc, alen);
	}
	poly1305_update (&poc,ct, tot);
	poly1305_pad16 (&poc, tot);
	poly1305_update (&poc, alen);
	poly1305_update (&poc, plen + padlen + 2);
	poly1305_finish (&poc, ct + tot);
}


int Cipher::decrypt_padded (const uint8_t *ad, size_t alen,
        const uint8_t *ct, size_t clen,
        std::vector<uint8_t> &pt)
{
	if (clen < 16) return -1;
	poly1305_context poc;
	uint8_t stream[64];
	chacha20 (stream, key, n, 0);
	poly1305_init (&poc, stream);
	if (alen != 0) {
		poly1305_update (&poc, ad, alen);
		poly1305_pad16 (&poc, alen);
	}
	poly1305_update (&poc, ct, clen - 16);
	poly1305_pad16 (&poc, clen - 16);
	poly1305_update (&poc, alen);
	poly1305_update (&poc, clen - 16);
	uint8_t tag[16];
	poly1305_finish (&poc, tag);

	if (crypto_neq (tag, ct + clen - 16, 16)) {
		return -1;
	}
	Chacha cha (key, n);
	uint8_t two[2];
	cha.doxor (two, ct, 2);
	size_t plen = be16dec (two);
	pt.clear();
	pt.resize (plen);
	cha.doxor (&pt[0], ct + 2, plen);
	return 0;
}

void Cipher::rekey()
{
	uint8_t stream[64];
	chacha20 (stream, key, uint64_t(-1), 1);
	load (&key, stream);
}



void Symmetric::initialize (const char *proto)
{
	size_t n = strlen (proto);
	if (n > 32) {
		Blake2s b;
		b.update (proto, n);
		b.final (h);
	} else {
		memcpy (h, proto, n);
		memset (h + n, 0, 32 - n);
	}
	memcpy (ck, h, 32);
	with_key = false;
}

void Symmetric::mix_key (const uint8_t *ikm, size_t ilen)
{
	uint8_t tmpk[32];
	amber::mix_key (ck, tmpk, ikm, ilen);
	initialize_key (tmpk);
	with_key = true;
}


void Symmetric::mix_key_and_hash (const uint8_t *ikm, size_t ilen)
{
	uint8_t tmpk[32], tmph[32];
	hkdf2s (ck, ikm, ilen, ck, tmph, tmpk);
	mix_hash (tmph, 32);
	initialize_key (tmpk);
	with_key = true;
}


void Symmetric::encrypt_and_hash (const uint8_t *pt, size_t plen,
                                  std::vector<uint8_t> &out)
{
	size_t orig = out.size();
	if (with_key) {
		out.resize (orig + plen + 16);
		encrypt_with_ad (h, sizeof h, pt, plen, &out[orig]);
		mix_hash (&out[orig], plen + 16);
	} else {
		out.resize (orig + plen);
		memcpy (&out[orig], pt, plen);
		mix_hash (&out[orig], plen);
	}
}


ptrdiff_t Symmetric::decrypt_and_hash (const uint8_t *ct, size_t plen,
                                    uint8_t *pt)
{
	if (with_key) {
		if (decrypt_with_ad (h, sizeof h, ct, plen + 16, pt) != 0) {
			return -1;
		}
		mix_hash (ct, plen + 16);
		return plen + 16;
	} else {
		memcpy (pt, ct, plen);
		mix_hash (ct, plen);
		return plen;
	}
}

int Symmetric::decrypt_and_hash (const uint8_t *ct, size_t plen,
                                 std::vector<uint8_t> &out)
{
	size_t orig = out.size();
	out.resize (orig + plen);
	return decrypt_and_hash (ct, plen, &out[orig]) < 0;
}

void Symmetric::split (Cipher *cs1, Cipher *cs2)
{
	uint8_t t1[32], t2[32];
	hkdf2s (ck, NULL, 0, t1, t2);
	cs1->initialize_key (t1);
	if (cs2) {
		cs2->initialize_key (t2);
	}
}

void Symmetric::split (Chakey *k1, Chakey *k2)
{
	uint8_t t1[32], t2[32];
	hkdf2s (ck, NULL, 0, t1, t2);
	load (k1, t1);
	if (k2) {
		load (k2, t2);
	}
}

inline void append (std::vector<uint8_t> &out, const uint8_t *data, size_t ndata)
{
	size_t orig = out.size();
	out.resize (orig + ndata);
	memcpy (&out[orig], data, ndata);
}


void Handshake::initialize (const char *protolet, const Pattern *pattern,
                            size_t npat, const uint8_t *prologue,
                            size_t plen, bool elligated, bool fallback)
{
	char protocol[100];
	snprintf (protocol, sizeof protocol, "Noise_%s_25519_ChaChaPoly_BLAKE2s", protolet);
	Symmetric::initialize (protocol);
	pat.clear();
	pat.insert (pat.begin(), pattern, pattern + npat);
	mix_hash (prologue, plen);
	patidx = 0;
	s_set = re_set = rs_set = false;
	e_state = e_not_set;
	initiator = false;
	s_known = false;
	psk_set = false;
	this->elligated = elligated;
	this->fallback = fallback;
}

void Handshake::setup (bool ini)
{
	initiator = fallback ? !ini : ini;
	if (s_known && rs_set) {
		if (initiator) {
			mix_hash (s_pub.b, 32);
			mix_hash (rs_pub.b, 32);
		} else {
			mix_hash (rs_pub.b, 32);
			mix_hash (s_pub.b, 32);
		}
	} else if (s_known) {
		mix_hash (s_pub.b, 32);
	} else if (rs_set) {
		mix_hash (rs_pub.b, 32);
	}
}

void Handshake::set_s (const Cu25519Pair &pair, bool known)
{
	s_sec = pair.xs;
	s_pub = pair.xp;
	s_set = true;
	s_known = known;
}

void Handshake::set_known_rs (const Cu25519Ris &xp)
{
	rs_pub = xp;
	rs_set = true;
}

void Handshake::set_known_re (const Cu25519Mon &xp)
{
	re_pub = xp;
	re_set = true;
}

void Handshake::set_e_sec (const uint8_t xs[32])
{
	memcpy (e_sec.b, xs, 32);
	e_state = e_sec_set;
}

void Handshake::set_psk (const uint8_t ps[32])
{
	memcpy (pskv, ps, 32);
	psk_set = true;
}



void Handshake::write_message (const uint8_t *pay, size_t npay, std::vector<uint8_t> &out)
{
	uint8_t sh[32];

	if (patidx == 0) {
		setup (true);
	}

	out.clear();
	while (patidx < pat.size()) {
		switch (pat[patidx++]) {
		case e:
			if (e_state == e_all_set) {
				throw std::logic_error (_("Pattern e is present more than once."));
			} else if (e_state == e_not_set) {
				randombytes_buf (e_sec.b, 32);
			}
			if (elligated) {
				Cu25519Ell rep;
				cu25519_elligator2_gen (&e_sec, &e_pub, &rep);
				append (out, rep.b, 32);
				mix_hash (rep.b, 32);
			} else {
				cu25519_generate (&e_sec, &e_pub);
				if (e_state == e_sec_set) {
					// Make it compatible with the test cases.
					e_pub.b[31] &= 0x7f;
				}
				append (out, e_pub.b, 32);
				mix_hash (e_pub.b, 32);
			}
			e_state = e_all_set;
			if (psk_set) {
				mix_key (&out[out.size() - 32], 32);
			}
			break;

		case s:
			if (!s_set) {
				throw std::logic_error (_("Pattern s found, but the local s has not been set."));
			}
			encrypt_and_hash (s_pub.b, 32, out);
			break;

		case ee:
			if (e_state != e_all_set) {
				throw std::logic_error (_("The local ephemeral key must precede an ee pattern."));
			}
			if (!re_set) {
				throw std::logic_error (_("The remote ephemeral key must precede an ee pattern."));
			}
			cu25519_shared_secret (sh, re_pub, e_sec);
			mix_key (sh, 32);
			break;

		case ss:
			if (!s_set) {
				throw std::logic_error (_("The local static key must be set before an ss pattern."));
			}
			if (!rs_set) {
				throw std::logic_error (_("The remote static key must be received before an ss pattern."));
			}
			cu25519_shared_secret (sh, rs_pub, s_sec);
			mix_key (sh, 32);
			break;

		case es:
			if (initiator) {
				if (!rs_set) {
					throw std::logic_error (_("The remote static key must be received before DH."));
				}
				if (e_state != e_all_set) {
					throw std::logic_error (_("The local ephemeral key must precede a DH."));
				}
				cu25519_shared_secret (sh, rs_pub, e_sec);
			} else {
				if (!s_set) {
					throw std::logic_error (_("The local static key must be set before DH."));
				}
				if (!re_set) {
					throw std::logic_error (_("The remove ephemeral key must be received before a DH."));
				}
				cu25519_shared_secret (sh, re_pub, s_sec);
			}
			mix_key (sh, 32);
			break;

		case se:
			if (initiator) {
				if (!s_set) {
					throw std::logic_error (_("The local static key must be set before DH."));
				}
				if (!re_set) {
					throw std::logic_error (_("The remove ephemeral key must be received before a DH."));
				}
				cu25519_shared_secret (sh, re_pub, s_sec);
			} else {
				if (!rs_set) {
					throw std::logic_error (_("The remote static key must be received before DH."));
				}
				if (e_state != e_all_set) {
					throw std::logic_error (_("The local ephemeral key must precede a DH."));
				}
				cu25519_shared_secret (sh, rs_pub, e_sec);
			}
			mix_key (sh, 32);
			break;

		case payload:
			encrypt_and_hash (pay, npay, out);
			return;

		case psk:
			mix_key_and_hash (pskv, 32);
			break;

		case finish:
			throw std::runtime_error (_("Attempting to send using finished handshake."));
		}
	}
	throw std::logic_error (_("End of pattern reached without a payload."));
}


int Handshake::read_message (const uint8_t *msg, size_t n, std::vector<uint8_t> &pay)
{
	uint8_t sh[32];
	size_t plen;
	size_t read_size;

	if (patidx == 0) {
		setup (false);
	}

	while (patidx < pat.size()) {
		switch (pat[patidx++]) {
		case e:
			if (n < 32) return -1;
			if (elligated) {
				Cu25519Ell rep;
				memcpy (rep.b, msg, 32);
				cu25519_elligator2_rev (&re_pub, rep);
			} else {
				memcpy (re_pub.b, msg, 32);
			}
			mix_hash (msg, 32);
			msg += 32;
			n -= 32;
			re_set = true;
			break;

		case s:
			read_size = 32 + (has_key() ? 16 : 0);
			if (n < read_size) return -1;
			if (decrypt_and_hash (msg, 32, rs_pub.b) < 0) {
				return -1;
			}
			msg += read_size;
			n -= read_size;
			rs_set = true;
			break;

		case ee:
			if (e_state != e_all_set) {
				throw std::logic_error (_("The local ephemeral key must precede an ee pattern."));
			}
			if (!re_set) {
				throw std::logic_error (_("The remote ephemeral key must precede an ee pattern."));
			}
			cu25519_shared_secret (sh, re_pub, e_sec);
			mix_key (sh, 32);
			break;

		case ss:
			if (!s_set) {
				throw std::logic_error (_("The local static key must be set before an ss pattern."));
			}
			if (!rs_set) {
				throw std::logic_error (_("The remote static key must be received before an ss pattern."));
			}
			cu25519_shared_secret (sh, rs_pub, s_sec);
			mix_key (sh, 32);
			break;

		case es:
			if (initiator) {
				if (!rs_set) {
					throw std::logic_error (_("The remote static key must be received before DH."));
				}
				if (e_state != e_all_set) {
					throw std::logic_error (_("The local ephemeral key must precede a DH."));
				}
				cu25519_shared_secret (sh, rs_pub, e_sec);
			} else {
				if (!s_set) {
					throw std::logic_error (_("The local static key must be set before DH."));
				}
				if (!re_set) {
					throw std::logic_error (_("The remove ephemeral key must be received before a DH."));
				}
				cu25519_shared_secret (sh, re_pub, s_sec);
			}
			mix_key (sh, 32);
			break;

		case se:
			if (initiator) {
				if (!s_set) {
					throw std::logic_error (_("The local static key must be set before DH."));
				}
				if (!re_set) {
					throw std::logic_error (_("The remove ephemeral key must be received before a DH."));
				}
				cu25519_shared_secret (sh, re_pub, s_sec);
			} else {
				if (!rs_set) {
					throw std::logic_error (_("The remote static key must be received before DH."));
				}
				if (e_state != e_all_set) {
					throw std::logic_error (_("The local ephemeral key must precede a DH."));
				}
				cu25519_shared_secret (sh, rs_pub, e_sec);
			}
			mix_key (sh, 32);
			break;

		case payload:
			pay.clear();
			if (has_key()) {
				if (n < 16) return -1;
				plen = n - 16;
			} else {
				plen = n;
			}
			return decrypt_and_hash (msg, plen, pay);

		case psk:
			mix_key_and_hash (pskv, 32);
			break;

		case finish:
			throw std::runtime_error (_("Attempting to receive using finished handshake."));
		}
	}
	throw std::logic_error (_("End of pattern reached without a payload."));
}

void Handshake::split (Cipher *tx, Cipher *rx)
{
	if (initiator) {
		Symmetric::split (tx, rx);
	} else {
		Symmetric::split (rx, tx);
	}
}


struct Predef_val {
	Handshake::Predef id;
	const char *name;
	Handshake::Pattern *pat;
	size_t npat;
};

// Patterns named depending on whether the static key of the participant is
// not known (N), known in advance (K) or transmitted (X).

static Handshake::Pattern pat_n[] = {
	Handshake::e, Handshake::es, Handshake::payload,
	Handshake::finish
};

static Handshake::Pattern pat_k[] = {
	Handshake::e, Handshake::es, Handshake::ss, Handshake::payload,
	Handshake::finish
};

static Handshake::Pattern pat_x[] = {
	Handshake::e, Handshake::es, Handshake::s, Handshake::ss, Handshake::payload,
	Handshake::finish
};

static Handshake::Pattern pat_nn[] = {
	Handshake::e, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_nk[] = {
	Handshake::e, Handshake::es, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_nx[] = {
	Handshake::e, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::s, Handshake::es, Handshake::payload,
	Handshake::finish
};

static Handshake::Pattern pat_kn[] = {
	Handshake::e, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::se, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_kk[] = {
	Handshake::e, Handshake::es, Handshake::ss, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::se, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_kx[] = {
	Handshake::e, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::se, Handshake::s, Handshake::es, Handshake::payload,
	Handshake::finish
};

static Handshake::Pattern pat_xn[] = {
	Handshake::e, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::payload,
	Handshake::s, Handshake::se, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_xk[] = {
	Handshake::e, Handshake::es, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::payload,
	Handshake::s, Handshake::se, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_xx[] = {
	Handshake::e, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::s, Handshake::es, Handshake::payload,
	Handshake::s, Handshake::se, Handshake::payload,
	Handshake::finish
};

static Handshake::Pattern pat_in[] = {
	Handshake::e, Handshake::s, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::se, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_ik[] = {
	Handshake::e, Handshake::es, Handshake::s, Handshake::ss, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::se, Handshake::payload,
	Handshake::finish
};
static Handshake::Pattern pat_ix[] = {
	Handshake::e, Handshake::s, Handshake::payload,
	Handshake::e, Handshake::ee, Handshake::se, Handshake::s, Handshake::es, Handshake::payload,
	Handshake::finish
};

// XX fallback.
static Handshake::Pattern pat_xf[] = {
	Handshake::e, Handshake::ee, Handshake::s, Handshake::es, Handshake::payload,
	Handshake::s, Handshake::se, Handshake::payload,
	Handshake::finish
};


static Predef_val pval[] = {
	{ Handshake::N, "N", pat_n, sizeof(pat_n)/sizeof(pat_n[0]) },
	{ Handshake::K, "K", pat_k, sizeof(pat_k)/sizeof(pat_k[0]) },
	{ Handshake::X, "X", pat_x, sizeof(pat_x)/sizeof(pat_x[0]) },
	{ Handshake::NN, "NN", pat_nn, sizeof(pat_nn)/sizeof(pat_nn[0]) },
	{ Handshake::NK, "NK", pat_nk, sizeof(pat_nk)/sizeof(pat_nk[0]) },
	{ Handshake::NX, "NX", pat_nx, sizeof(pat_nx)/sizeof(pat_nx[0]) },
	{ Handshake::KN, "KN", pat_kn, sizeof(pat_kn)/sizeof(pat_kn[0]) },
	{ Handshake::KK, "KK", pat_kk, sizeof(pat_kk)/sizeof(pat_kk[0]) },
	{ Handshake::KX, "KX", pat_kx, sizeof(pat_kx)/sizeof(pat_kx[0]) },
	{ Handshake::XN, "XN", pat_xn, sizeof(pat_xn)/sizeof(pat_xn[0]) },
	{ Handshake::XK, "XK", pat_xk, sizeof(pat_xk)/sizeof(pat_xk[0]) },
	{ Handshake::XX, "XX", pat_xx, sizeof(pat_xx)/sizeof(pat_xx[0]) },
	{ Handshake::IN, "IN", pat_in, sizeof(pat_in)/sizeof(pat_in[0]) },
	{ Handshake::IK, "IK", pat_ik, sizeof(pat_ik)/sizeof(pat_ik[0]) },
	{ Handshake::IX, "IX", pat_ix, sizeof(pat_ix)/sizeof(pat_ix[0]) },
	{ Handshake::XF, "XF", pat_xf, sizeof(pat_xf)/sizeof(pat_xf[0]) },
};

void Handshake::initialize (Predef pat, const uint8_t *prologue, size_t plen,
                            bool elligated, bool fallback)
{
	for (unsigned i = 0; i < sizeof(pval)/sizeof(pval[0]); ++i) {
		if (pval[i].id == pat) {
			initialize (pval[i].name, pval[i].pat, pval[i].npat, prologue,
			            plen, elligated, fallback);
			return;
		}
	}
	throw std::logic_error (_("This pattern is unknown"));
}

const char * Handshake::name (Handshake::Predef pd)
{
	for (unsigned i = 0; i < sizeof(pval)/sizeof(pval[0]); ++i) {
		if (pval[i].id == pd) {
			return pval[i].name;
		}
	}
	throw std::logic_error (_("This pattern is unknown"));
}


}}


