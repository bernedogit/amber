#include "noise.hpp"
#include <fstream>
#include "hasopt.hpp"

using namespace amber;

// Simplistic file encryption with Noise.

Cu25519Pair ini, res;

void write_packet (std::ostream &os, std::vector<uint8_t> &out)
{
	char two[2];
	be16enc (two, out.size());
	os.write (two, 2);
	os.write ((char*)&out[0], out.size());
}

void write (const char *iname, const char *oname)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is || !os) return;

	show_block (std::cout, "Sending from  ", ini.xp.b, 32);
	show_block (std::cout, "          to  ", res.xp.b, 32);
	Handshake hs;
	hs.initialize (Handshake::X, NULL, 0, true);
	hs.set_s (ini, false);
	hs.set_known_rs (res.xp);

	std::vector<uint8_t> out;
	hs.write_message (NULL, 0, out);
	write_packet (os, out);

	if (!hs.finished()) {
		std::cerr << "Handshake not finished while writing.\n";
		return;
	}
	Cipher cs;
	hs.split (&cs);

	char buf[1000];
	while (is) {
		is.read (buf, sizeof buf);
		cs.encrypt_padded (NULL, 0, (const uint8_t*)buf, is.gcount(), 200, out);
		write_packet (os, out);
		if (is.gcount() != sizeof buf) break;
	}
}

enum class Rp_result { packet_read, corrupt, eof };
Rp_result read_packet (std::istream &is, std::vector<uint8_t> &body)
{
	char two[2];
	size_t len;

	is.read (two, 2);
	if (is.gcount() == 0 && is.eof()) {
		return Rp_result::eof;
	}
	if (is.gcount() != 2) return Rp_result::corrupt;
	len = be16dec (two);
	body.resize (len);
	is.read ((char*)&body[0], len);
	if (is.gcount() != len) {
		return Rp_result::corrupt;
	}
	return Rp_result::packet_read;
}

void read (const char *iname, const char *oname)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is || !os) return;

	Handshake hs;
	hs.initialize (Handshake::X, NULL, 0, true);
	hs.set_s (res, true);

	std::vector<uint8_t> in, pay;
	if (read_packet (is, in) != Rp_result::packet_read) {
		std::cerr << "Error reading header.\n";
		return;
	}

	if (hs.read_message (&in[0], in.size(), pay) != 0) {
		std::cerr << "Error in handshake.\n";
		return;
	}
	if (!hs.finished()) {
		std::cerr << "The handshake is not finished.\n";
		return;
	}

	Cipher cs;
	hs.split (&cs);

	if (hs.get_rs() != NULL) {
		show_block (std::cout, "Receiving from", hs.get_rs()->b, 32);
	}

	while (is && !is.eof()) {
		Rp_result res = read_packet (is, in);
		if (res == Rp_result::corrupt) {
			std::cerr << "Error reading packet.\n";
			return;
		}
		if (res == Rp_result::eof) break;
		cs.decrypt_padded (NULL, 0, &in[0], in.size(), pay);
		os.write ((char*)&pay[0], pay.size());
	}
}

void real_main()
{
	randombytes_buf (ini.xs.b, 32);
	randombytes_buf (res.xs.b, 32);
	cu25519_generate (&ini.xs, &ini.xp);
	cu25519_generate (&res.xs, &res.xp);
	write ("foo.txt", "foo.enc");
	read ("foo.enc", "foo.dec");
}

int main()
{
	return run_main (real_main);
}




