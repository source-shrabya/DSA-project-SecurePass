#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <vector>
#include <string>
#include "HashNode.h"

// Detect OpenSSL availability at compile time; expose macro for tests and implementation
#if defined(__has_include)
#  if __has_include(<openssl/hmac.h>)
#    define HASH_HAS_OPENSSL 1
#  else
#    define HASH_HAS_OPENSSL 0
#  endif
#else
#  define HASH_HAS_OPENSSL 0
#endif

class HashTable {
private:
    std::vector<HashNode*> table; // The array of buckets
    int capacity;                 // Total number of buckets
    int count;                    // Total number of items stored
    float loadFactorThreshold;    // Limit before we resize (e.g., 0.75)

    // Helper to find the next prime number for resizing
    int nextPrime(int n);
    bool isPrime(int n);

    // Helper for encryption/decryption (XOR Cipher)
    std::string xorCipher(std::string data, std::string key);

public:
    // Constructor and Destructor
    HashTable(int cap = 101);
    ~HashTable();

    // Core DSA Operations
    int hash(std::string key);
    void insert(Credential cred);
    Credential* search(std::string site, std::string username = "");
    bool update(std::string site, std::string username, std::string newPassword);
    bool remove(std::string site, std::string username);
    void rehash(int newCapacity);

    // File Persistence Operations
    bool save(std::string filename, std::string key);
    bool load(std::string filename, std::string key);
    
    // Clear all entries from the table
    void clear();
    
    // Debug helper (optional)
    void printTable();
};

#endif