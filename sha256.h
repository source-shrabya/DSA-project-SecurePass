#ifndef SHA256_H
#define SHA256_H

#include <string>

// Returns the raw 32-byte binary SHA-256 digest of input data.
std::string sha256_raw(const std::string &data);

// Convenience: return hex string (not used by HMAC, but available)
std::string sha256_hex(const std::string &data);

#endif
