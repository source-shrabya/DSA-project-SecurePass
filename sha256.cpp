#include "sha256.h"
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>

// Small, public-domain style SHA-256 implementation adapted for embedding.
// Produces raw 32-byte binary digest.

namespace {
    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    void process_block(const unsigned char block[64], uint32_t H[8]) {
        uint32_t W[64];
        for (int t = 0; t < 16; ++t) {
            W[t] = (uint32_t(block[t * 4]) << 24) | (uint32_t(block[t * 4 + 1]) << 16) |
                   (uint32_t(block[t * 4 + 2]) << 8) | uint32_t(block[t * 4 + 3]);
        }
        for (int t = 16; t < 64; ++t) {
            uint32_t s0 = rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >> 3);
            uint32_t s1 = rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >> 10);
            W[t] = W[t-16] + s0 + W[t-7] + s1;
        }

        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        for (int t = 0; t < 64; ++t) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + K[t] + W[t];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }
}

std::string sha256_raw(const std::string &data) {
    uint64_t bitlen = static_cast<uint64_t>(data.size()) * 8ULL;
    // Initial hash values
    uint32_t H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    // Prepare the message: pad
    std::vector<unsigned char> msg(data.begin(), data.end());
    // append 0x80
    msg.push_back(0x80);
    // append zeros until message length in bits ≡ 448 mod 512 => bytes ≡ 56 mod 64
    while ((msg.size() % 64) != 56) msg.push_back(0x00);
    // append big-endian 64-bit length
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<unsigned char>((bitlen >> (i*8)) & 0xff));
    }

    // process blocks
    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        process_block(&msg[offset], H);
    }

    // produce digest
    std::string digest;
    digest.resize(32);
    for (int i = 0; i < 8; ++i) {
        digest[i*4]     = static_cast<char>((H[i] >> 24) & 0xff);
        digest[i*4 + 1] = static_cast<char>((H[i] >> 16) & 0xff);
        digest[i*4 + 2] = static_cast<char>((H[i] >> 8) & 0xff);
        digest[i*4 + 3] = static_cast<char>((H[i]) & 0xff);
    }
    return digest;
}

std::string sha256_hex(const std::string &data) {
    std::string raw = sha256_raw(data);
    std::ostringstream oss;
    for (unsigned char c : raw) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(c) & 0xff);
    }
    return oss.str();
}
