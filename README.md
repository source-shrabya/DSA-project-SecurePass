# SecurePass Manager (Team Goated)

A lightweight password manager built with C++ and data structures. Stores credentials in an encrypted hash table with optional integrity checks, atomic file I/O, and XOR-based encryption for data at rest.

## Features

- **Hash Table Data Structure**: Uses separate chaining with dynamic resizing (load factor threshold 0.75) and polynomial rolling hash.
- **Credential Storage**: Manage site, username, and password triples.
- **File Persistence**: Save/load credentials to/from encrypted files with atomic writes.
- **Integrity Checking**: HMAC-SHA256 verification (built-in or via OpenSSL) to detect tampering/wrong keys.
- **Portable Encryption**: Embedded SHA-256 implementation; works without external dependencies.
- **Unit Tests**: Comprehensive test suite covering insert, search, update, remove, save/load round-trips.
- **Interactive CLI**: User-friendly menu for adding, finding, updating, deleting credentials.

## Project Structure

```
.
├── main.cpp              # Interactive CLI application
├── HashTable.h/.cpp      # Hash table implementation + file I/O
├── HashNode.h            # Linked list node for chaining
├── Credential.h/.cpp     # Credential class (site, user, pass) + CSV serialization
├── sha256.h/.cpp         # Embedded SHA-256 implementation
└── README.md             # This file
```

## Build & Run

### Quick Start (No Dependencies)

Compile and run the interactive application:

```bash
cd "/Users/shrabyabhattarai/Desktop/USM/3rd Semester/DSA Final Project"
g++ -std=c++17 -Wall -Wextra main.cpp HashTable.cpp Credential.cpp sha256.cpp -o app
./app
```

### Run Unit Tests

Compile and run the test suite:

```bash
g++ -std=c++17 -Wall -Wextra test_hash.cpp HashTable.cpp Credential.cpp sha256.cpp -o tests_runner
./tests_runner
```

Expected output:
```
Note: OpenSSL not available; skipping wrong-key integrity test.
ALL TESTS PASSED
```

### Optional: Build with OpenSSL (Enhanced Performance)

If you have OpenSSL installed (e.g., via Homebrew on macOS), you can build with OpenSSL's HMAC library for better performance:

**macOS (Homebrew):**
```bash
g++ -std=c++17 -Wall -Wextra \
  -I/usr/local/opt/openssl/include \
  -L/usr/local/opt/openssl/lib \
  main.cpp HashTable.cpp Credential.cpp sha256.cpp \
  -lcrypto -o app
./app
```

**Linux (apt/yum):**
```bash
# First install: sudo apt-get install libssl-dev
g++ -std=c++17 -Wall -Wextra main.cpp HashTable.cpp Credential.cpp sha256.cpp -lcrypto -o app
./app
```

## Usage

### Interactive Mode

Run the application:
```bash
./app
```

You will see a menu:
```
Welcome to SecurePass (Team Goated)

=== SecurePass Manager ===
Commands:
  add     - Add new credential
  find    - Find a password
  update  - Update a password
  delete  - Delete a credential
  save    - Save to encrypted file
  load    - Load from encrypted file
  exit    - Exit program
--------------------------
Enter command: 
```

#### Add a Credential
```
Enter command: add
Site: github.com
Username: alice
Password: my_secret_token
Credential added!
```

#### Find a Password
```
Enter command: find
Enter Site to search: github.com

[FOUND] Site: github.com
        User: alice
        Pass: my_secret_token
```

#### Update a Password
```
Enter command: update
Site: github.com
Username: alice
New Password: new_secret_token
Password updated successfully.
```

#### Delete a Credential
```
Enter command: delete
Site: github.com
Username: alice
Credential removed.
```

#### Save Credentials to File
```
Enter command: save
Enter filename (e.g., data.csv): credentials.bin
Enter secure key for encryption: mysecretkey
Data saved securely to credentials.bin
```

#### Load Credentials from File
```
Enter command: load
Enter filename (e.g., data.csv): credentials.bin
Enter secure key for decryption: mysecretkey
Data loaded successfully.
```

#### Exit
```
Enter command: exit
Save before exiting? (y/n): y
Enter filename to save: backup.bin
Enter encryption key: mysecretkey
```

## Data Structures

### Hash Table
- **Capacity**: 101 (prime number, configurable)
- **Hash Function**: Polynomial rolling hash with modular arithmetic
- **Collision Handling**: Separate chaining (linked list)
- **Dynamic Resizing**: Doubles capacity when load factor exceeds 0.75; automatically finds next prime

### Credential
- **Fields**: `site` (string), `username` (string), `password` (string)
- **CSV Format**: `"site","username","password"` for serialization

### File Format

When saving, the file contains:

```
[MAGIC: 8 bytes "SPASSv01"]
[HMAC-SHA256: 32 bytes] (integrity check)
[Encrypted Payload]
  ├─ CSV lines of credentials (serialized)
  └─ XOR-encrypted with provided key
```

**Security Notes:**
- XOR cipher is for privacy (not suitable for critical security; consider AES-GCM for production).
- HMAC-SHA256 detects file tampering and wrong keys.
- Wrong key on load → HMAC verification fails → load returns false (no data corrupted).
- Atomic writes: file is written to `.tmp`, then renamed atomically to prevent partial/corrupt files on crash.

## Testing

The unit test suite (`test_hash.cpp`) covers:
1. **Basic Operations**: insert, search, update, remove
2. **File I/O**: save to file, clear table, load from file (round-trip)
3. **Integrity**: wrong-key load fails (when OpenSSL available)
4. **Edge Cases**: empty table save, zero-length file load

Run tests:
```bash
g++ -std=c++17 -Wall -Wextra test_hash.cpp HashTable.cpp Credential.cpp sha256.cpp -o tests_runner
./tests_runner
```

## Implementation Details

### Hash Function
- **Algorithm**: Polynomial rolling hash (base 31, modulus 10^9 + 9)
- **Input**: Credential site name
- **Output**: Bucket index (0 to capacity-1)

### Collision Resolution
- **Method**: Separate chaining (linked list per bucket)
- **Insert**: Checks if (site, user) exists; if so, updates password; otherwise inserts at chain head

### Load Factor Management
- **Threshold**: 0.75
- **Trigger**: When `count / capacity > 0.75`, rehash to `nextPrime(2 * capacity)`
- **Rehash Process**: Move all entries to new larger table using updated hash values

### Encryption
- **Method**: XOR stream cipher with repeating key
- **Weakness**: XOR alone is not cryptographically secure; suitable only for privacy (not authenticated).
- **HMAC**: Adds integrity via HMAC-SHA256 to detect tampering.

### SHA-256 (Embedded)
- **Source**: Public-domain style implementation
- **Output**: 32-byte raw binary digest
- **Used By**: HMAC-SHA256 computation when OpenSSL unavailable

## Performance Characteristics

| Operation | Avg Case | Worst Case |
|-----------|----------|-----------|
| Insert    | O(1)     | O(n)      |
| Search    | O(1)     | O(n)      |
| Update    | O(1)     | O(n)      |
| Remove    | O(1)     | O(n)      |
| Save      | O(n)     | O(n)      |
| Load      | O(n)     | O(n)      |

(n = number of credentials)

## Security Considerations

⚠️ **Not Production-Ready** — This is an educational project. For real password management:

1. **Encryption**: Replace XOR with authenticated encryption (AES-256-GCM via libsodium or OpenSSL).
2. **Key Derivation**: Use PBKDF2, Argon2, or scrypt to derive keys from passphrases.
3. **Master Password**: Require a strong master password; never store it.
4. **Memory Hygiene**: Clear sensitive data from memory after use (use secure_string or mlock).
5. **Randomization**: Use secure random for salts/IVs.
6. **Secure Storage**: Store encrypted vault file in a secure location with restricted permissions.

## Compilation Notes

- **C++ Standard**: C++17 (or later)
- **Compiler**: GCC, Clang (tested on macOS with Apple Clang)
- **Dependencies**: None required (OpenSSL optional for performance)
- **Warnings**: A few unused-variable warnings when OpenSSL is not linked (benign)

## Future Improvements

- [ ] Replace XOR with AES-256-GCM
- [ ] Add PBKDF2/Argon2 for key derivation
- [ ] Add multi-user support with master password
- [ ] Secure memory clearing (volatile, secure_string)
- [ ] Command-line arguments (--file, --key) for batch operations
- [ ] Export/import (JSON, CSV formats)
- [ ] Search by username (in addition to site)
- [ ] Password strength meter and generator

## Team

- **Team Name**: Goated
- **Project**: DSA Final Project (3rd Semester)
- **Date**: November 2025

## License

Educational use only. No warranty implied.

## Questions?

For questions or issues, refer to the inline code comments in:
- `HashTable.h/.cpp` for data structure and file I/O logic
- `Credential.h/.cpp` for serialization format
- `test_hash.cpp` for usage examples
