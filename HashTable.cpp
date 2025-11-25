#include "HashTable.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <sstream>
#include <cstdio>
#if HASH_HAS_OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif
#include "sha256.h"

// Constructor: Initializes the table with nullptrs
HashTable::HashTable(int cap) : capacity(cap), count(0), loadFactorThreshold(0.75f) {
    table.resize(capacity, nullptr);
}

// Destructor: Cleans up all dynamic memory (linked list nodes)
HashTable::~HashTable() {
    for (int i = 0; i < capacity; i++) {
        HashNode* entry = table[i];
        while (entry != nullptr) {
            HashNode* prev = entry;
            entry = entry->next;
            delete prev;
        }
        table[i] = nullptr;
    }
}

// DSA1: Hash Function
// Uses a polynomial rolling hash (base 31) to compute index.
int HashTable::hash(std::string key) {
    long long hashValue = 0;
    long long p = 31;
    long long m = 1000000009LL; // 1e9+9 as integer literal
    long long power = 1;

    for (char c : key) {
        hashValue = (hashValue + (c - 'a' + 1) * power) % m;
        power = (power * p) % m;
    }
    // Ensure index is positive and fits in capacity
    long long idx = (hashValue % capacity + capacity) % capacity;
    return static_cast<int>(idx);
}

// DSA2: Insert
// Inserts a credential. Updates if site+user exists, otherwise adds new node.
void HashTable::insert(Credential cred) {
    int index = hash(cred.site);
    HashNode* node = table[index];

    // Check if it already exists to update it
    while (node != nullptr) {
        if (node->credential.site == cred.site && node->credential.username == cred.username) {
            node->credential.password = cred.password; // Update password
            return;
        }
        node = node->next;
    }

    // Insert at HEAD of the list (Separate Chaining)
    HashNode* newNode = new HashNode(cred);
    newNode->next = table[index];
    table[index] = newNode;
    count++;

    // Check Load Factor and Resize if needed
    if (static_cast<float>(count) / capacity > loadFactorThreshold) {
        rehash(nextPrime(2 * capacity));
    }
}

// DSA3: Search
// Returns a pointer to the credential if found, or nullptr.
Credential* HashTable::search(std::string site, std::string username) {
    int index = hash(site);
    HashNode* node = table[index];

    while (node != nullptr) {
        // Match site
        if (node->credential.site == site) {
            // If username is provided, match that too. If not, return first match (simple logic)
            if (username == "" || node->credential.username == username) {
                return &node->credential;
            }
        }
        node = node->next;
    }
    return nullptr;
}

// DSA4: Update
bool HashTable::update(std::string site, std::string username, std::string newPassword) {
    Credential* cred = search(site, username);
    if (cred != nullptr) {
        cred->password = newPassword;
        return true;
    }
    return false;
}

// DSA5: Remove
bool HashTable::remove(std::string site, std::string username) {
    int index = hash(site);
    HashNode* node = table[index];
    HashNode* prev = nullptr;

    while (node != nullptr) {
        if (node->credential.site == site && node->credential.username == username) {
            // Found it. Unlink the node.
            if (prev == nullptr) {
                // It was the head
                table[index] = node->next;
            } else {
                // It was in the middle/end
                prev->next = node->next;
            }
            delete node;
            count--;
            return true;
        }
        prev = node;
        node = node->next;
    }
    return false;
}

// DSA6: Rehash
// Creates a larger table and re-inserts all existing items.
void HashTable::rehash(int newCapacity) {
    std::cout << "Resizing table from " << capacity << " to " << newCapacity << "...\n";
    std::vector<HashNode*> oldTable = table;
    int oldCapacity = capacity;

    // Reset current table
    table.clear();
    table.resize(newCapacity, nullptr);
    capacity = newCapacity;
    count = 0; // Reset count because insert() increments it

    // Move old items to new table
    for (int i = 0; i < oldCapacity; i++) {
        HashNode* node = oldTable[i];
        while (node != nullptr) {
            insert(node->credential); // Re-hash and insert
            HashNode* temp = node;
            node = node->next;
            delete temp; // Clean up old node wrapper (insert makes a new one)
        }
    }
}

// Helper: XOR Cipher
std::string HashTable::xorCipher(std::string data, std::string key) {
    std::string result = data;
    if (key.empty()) return result; // avoid div by zero mod
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

// Helper: compute HMAC-SHA256 of data using key. Returns binary string of length 32.
// computeHMAC_SHA256: prefer OpenSSL when available, otherwise use embedded SHA256
#if HASH_HAS_OPENSSL
static std::string computeHMAC_SHA256(const std::string &data, const std::string &key) {
    unsigned int len = EVP_MAX_MD_SIZE;
    unsigned char digest[EVP_MAX_MD_SIZE];
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) return std::string();
    if (HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), NULL) != 1) {
        HMAC_CTX_free(ctx);
        return std::string();
    }
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    HMAC_Final(ctx, digest, &len);
    HMAC_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(digest), static_cast<size_t>(len));
}
#else
static std::string computeHMAC_SHA256(const std::string &data, const std::string &key) {
    // HMAC with SHA-256: block size = 64 bytes
    const size_t blockSize = 64;
    std::string k = key;
    if (k.size() > blockSize) k = sha256_raw(k);
    if (k.size() < blockSize) k.append(blockSize - k.size(), '\0');

    std::string o_key_pad(blockSize, '\0');
    std::string i_key_pad(blockSize, '\0');
    for (size_t i = 0; i < blockSize; ++i) {
        o_key_pad[i] = static_cast<char>(k[i] ^ 0x5c);
        i_key_pad[i] = static_cast<char>(k[i] ^ 0x36);
    }

    std::string inner = i_key_pad + data;
    std::string inner_hash = sha256_raw(inner);
    std::string outer = o_key_pad + inner_hash;
    std::string hmac = sha256_raw(outer);
    return hmac;
}
#endif

// Constant magic header to identify file format
static const char FILE_MAGIC[] = "SPASSv01"; // 8 bytes
static const size_t FILE_MAGIC_SIZE = 8;
static const size_t HMAC_SIZE = 32; // SHA256

// DSA7: Save
// Encrypts and writes to file.
bool HashTable::save(std::string filename, std::string key) {
    std::string buffer = "";
    
    // Serialize all data to one big string
    for (int i = 0; i < capacity; i++) {
        HashNode* node = table[i];
        while (node != nullptr) {
            buffer += node->credential.toCSV() + "\n";
            node = node->next;
        }
    }

    // Encrypt
    std::string encryptedData = xorCipher(buffer, key);

    // Always write new format (MAGIC + HMAC + payload) atomically for integrity
    // Compute HMAC over encrypted payload
    std::string hmac = computeHMAC_SHA256(encryptedData, key);
    if (hmac.size() != HMAC_SIZE) {
        // HMAC failure
        return false;
    }

    // Write atomically to a temp file then rename
    std::string tmpName = filename + ".tmp";
    std::ofstream outFile(tmpName, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) return false;

    // Write magic
    outFile.write(FILE_MAGIC, static_cast<std::streamsize>(FILE_MAGIC_SIZE));
    // Write HMAC
    outFile.write(hmac.data(), static_cast<std::streamsize>(hmac.size()));
    // Write payload
    outFile.write(encryptedData.data(), static_cast<std::streamsize>(encryptedData.size()));
    outFile.close();

    // Rename temp to final file
    if (std::rename(tmpName.c_str(), filename.c_str()) != 0) {
        // rename failed, remove temp
        std::remove(tmpName.c_str());
        return false;
    }
    return true;
}

// DSA8: Load
// Reads from file, Decrypts, and populates table.
bool HashTable::load(std::string filename, std::string key) {
    // Replace current data with file contents
    clear();

    std::ifstream inFile(filename, std::ios::binary | std::ios::ate);
    if (!inFile.is_open()) return false;

    std::streamsize size = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    if (size == 0) {
        inFile.close();
        return true; // empty file -> nothing to load
    }

    // Always expect new format (MAGIC + HMAC + payload) for integrity/auth
    if (static_cast<size_t>(size) < FILE_MAGIC_SIZE + HMAC_SIZE) {
        inFile.close();
        return false; // File too small to be valid format
    }

    // Read magic first
    std::string magicBuf(FILE_MAGIC_SIZE, '\0');
    inFile.read(&magicBuf[0], FILE_MAGIC_SIZE);
    if (inFile.gcount() != static_cast<std::streamsize>(FILE_MAGIC_SIZE)) {
        inFile.close();
        return false;
    }

    if (std::memcmp(magicBuf.data(), FILE_MAGIC, FILE_MAGIC_SIZE) != 0) {
        inFile.close();
        return false; // Magic header mismatch: file corrupted or wrong format
    }

    // Read HMAC
    std::string fileHmac(HMAC_SIZE, '\0');
    inFile.read(&fileHmac[0], HMAC_SIZE);
    if (inFile.gcount() != static_cast<std::streamsize>(HMAC_SIZE)) {
        inFile.close();
        return false;
    }

    // Read payload
    std::streamsize payloadSize = size - static_cast<std::streamsize>(FILE_MAGIC_SIZE + HMAC_SIZE);
    std::string encryptedData(static_cast<size_t>(payloadSize), '\0');
    if (payloadSize > 0) {
        inFile.read(&encryptedData[0], payloadSize);
        if (inFile.gcount() != payloadSize) {
            inFile.close();
            return false;
        }
    }
    inFile.close();

    // Verify HMAC (always, regardless of OpenSSL)
    std::string calcHmac = computeHMAC_SHA256(encryptedData, key);
    if (calcHmac.size() != fileHmac.size() || calcHmac != fileHmac) {
        return false; // integrity/auth failed: wrong key or file corrupted
    }

    // Decrypt and parse
    std::string decryptedData = xorCipher(encryptedData, key);
    std::stringstream ss(decryptedData);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.length() > 5) {
            insert(Credential::fromCSV(line));
        }
    }
    return true;
}

// Clears all entries from the hash table (keeps capacity)
void HashTable::clear() {
    for (int i = 0; i < capacity; ++i) {
        HashNode* node = table[i];
        while (node != nullptr) {
            HashNode* next = node->next;
            delete node;
            node = next;
        }
        table[i] = nullptr;
    }
    count = 0;
}

// Helpers for Math
bool HashTable::isPrime(int n) {
    if (n <= 1) return false;
    for (int i = 2; i * i <= n; i++) {
        if (n % i == 0) return false;
    }
    return true;
}

int HashTable::nextPrime(int n) {
    while (!isPrime(n)) {
        n++;
    }
    return n;
}

void HashTable::printTable() {
    for (int i = 0; i < capacity; i++) {
        if (table[i] != nullptr) {
            std::cout << "Bucket " << i << ": ";
            HashNode* temp = table[i];
            while (temp != nullptr) {
                std::cout << "[" << temp->credential.site << "] -> ";
                temp = temp->next;
            }
            std::cout << "NULL\n";
        }
    }
}
