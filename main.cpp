#include <iostream>
#include <string>
#include "HashTable.h"
#include "Credential.h"

// Helper to get input cleanly
std::string getInput(std::string prompt) {
    std::cout << prompt;
    std::string val;
    std::getline(std::cin, val);
    return val;
}

void printMenu() {
    std::cout << "\n=== SecurePass Manager ===\n";
    std::cout << "Commands:\n";
    std::cout << "  add     - Add new credential\n";
    std::cout << "  find    - Find a password\n";
    std::cout << "  update  - Update a password\n";
    std::cout << "  delete  - Delete a credential\n";
    std::cout << "  save    - Save to encrypted file\n";
    std::cout << "  load    - Load from encrypted file\n";
    std::cout << "  exit    - Exit program\n";
    std::cout << "--------------------------\n";
}

int main() {
    HashTable ht(101); // Initial capacity
    std::string command;
    std::string fileKey = "default"; // Key used for encryption

    std::cout << "Welcome to SecurePass (Team Goated)\n";

    while (true) {
        printMenu();
        command = getInput("Enter command: ");

        if (command == "exit") {
            std::string ans = getInput("Save before exiting? (y/n): ");
            if (ans == "y" || ans == "Y") {
                std::string fname = getInput("Enter filename to save: ");
                std::string key = getInput("Enter encryption key: ");
                ht.save(fname, key);
            }
            break;
        }
        else if (command == "add") {
            std::string site = getInput("Site: ");
            std::string user = getInput("Username: ");
            std::string pass = getInput("Password: ");
            ht.insert(Credential(site, user, pass));
            std::cout << "Credential added!\n";
        }
        else if (command == "find") {
            std::string site = getInput("Enter Site to search: ");
            Credential* result = ht.search(site);
            if (result) {
                std::cout << "\n[FOUND] Site: " << result->site 
                          << "\n        User: " << result->username 
                          << "\n        Pass: " << result->password << "\n";
            } else {
                std::cout << "[!] Credential not found.\n";
            }
        }
        else if (command == "update") {
            std::string site = getInput("Site: ");
            std::string user = getInput("Username: ");
            std::string newPass = getInput("New Password: ");
            if (ht.update(site, user, newPass)) {
                std::cout << "Password updated successfully.\n";
            } else {
                std::cout << "[!] Could not find that record to update.\n";
            }
        }
        else if (command == "delete") {
            std::string site = getInput("Site: ");
            std::string user = getInput("Username: ");
            if (ht.remove(site, user)) {
                std::cout << "Credential removed.\n";
            } else {
                std::cout << "[!] Credential not found.\n";
            }
        }
        else if (command == "save") {
            std::string fname = getInput("Enter filename (e.g., data.csv): ");
            std::string key = getInput("Enter secure key for encryption: ");
            if (ht.save(fname, key)) {
                std::cout << "Data saved securely to " << fname << "\n";
            } else {
                std::cout << "Error saving file.\n";
            }
        }
        else if (command == "load") {
            std::string fname = getInput("Enter filename (e.g., data.csv): ");
            std::string key = getInput("Enter secure key for decryption: ");
            if (ht.load(fname, key)) {
                std::cout << "Data loaded successfully.\n";
            } else {
                std::cout << "Error loading file (File invalid or wrong key).\n";
            }
        }
        else {
            std::cout << "Unknown command. Try again.\n";
        }
    }

    return 0;
}