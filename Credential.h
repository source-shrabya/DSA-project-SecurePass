#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <string>
#include <iostream>

// The Credential class stores a single login entry.
class Credential {
public:
    std::string site;
    std::string username;
    std::string password;

    // Constructor
    Credential(std::string s = "", std::string u = "", std::string p = "");

    // Converts the object data to a CSV formatted string: "site","user","pass"
    std::string toCSV() const;

    // Static method to create a Credential object from a CSV line
    static Credential fromCSV(const std::string& line);
};

#endif