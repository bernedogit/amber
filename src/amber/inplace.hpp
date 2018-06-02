#include "amber/soname.hpp"

// Encrypt and decrypt files in place. It does not create any temporary
// files. It will read and write to the same file. When encrypting the block
// filler size will be set to zero, resulting in the minimum expansion that
// the format allows.

namespace amber {   namespace AMBER_SONAME {

void inplace_encrypt (const char *name, const char *pass, int shifts=14);
void inplace_decrypt (const char *name, const char *pass, int max_shifts = 0);

}}


