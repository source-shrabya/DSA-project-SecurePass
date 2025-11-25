#include <iostream>
#include <cstdio>
#include <string>
#include "HashTable.h"
#include "Credential.h"

int main() {
    const std::string fname = "test_data.bin";
    const std::string key = "testkey";

    // Basic operations
    HashTable ht(11);
    ht.insert(Credential("a.com", "alice", "p1"));
    ht.insert(Credential("b.com", "bob", "p2"));

    if (!ht.search("a.com", "alice")) { std::cerr << "FAIL: search a.com alice\n"; return 1; }

    if (!ht.update("a.com", "alice", "newpass")) { std::cerr << "FAIL: update\n"; return 1; }
    Credential* c = ht.search("a.com", "alice");
    if (!c || c->password != "newpass") { std::cerr << "FAIL: password not updated\n"; return 1; }

    if (!ht.remove("b.com", "bob")) { std::cerr << "FAIL: remove bob\n"; return 1; }
    if (ht.search("b.com", "bob")) { std::cerr << "FAIL: bob still present after remove\n"; return 1; }

    // Save to file
    if (!ht.save(fname, key)) { std::cerr << "FAIL: save failed\n"; return 1; }

    // Clear and ensure cleared
    ht.clear();
    if (ht.search("a.com", "alice")) { std::cerr << "FAIL: clear failed\n"; return 1; }

    // Load with correct key
    if (!ht.load(fname, key)) { std::cerr << "FAIL: load returned false with correct key\n"; return 1; }
    c = ht.search("a.com", "alice");
    if (!c || c->password != "newpass") { std::cerr << "FAIL: loaded data mismatch\n"; return 1; }

    // Load with wrong key should fail (integrity check) if HMAC support is present
#if HASH_HAS_OPENSSL
    HashTable ht2(11);
    if (ht2.load(fname, "wrongkey")) { std::cerr << "FAIL: load succeeded with wrong key (should fail)\n"; return 1; }
#else
    std::cout << "Note: OpenSSL not available; skipping wrong-key integrity test.\n";
#endif

    // Cleanup
    std::remove(fname.c_str());

    std::cout << "ALL TESTS PASSED\n";
    return 0;
}
