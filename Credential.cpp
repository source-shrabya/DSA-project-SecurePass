#include "Credential.h"
#include <sstream>

// Constructor implementation
Credential::Credential(std::string s, std::string u, std::string p) 
    : site(s), username(u), password(p) {}

// formatting: "site","username","password"
std::string Credential::toCSV() const {
    return "\"" + site + "\",\"" + username + "\",\"" + password + "\"";
}

// Parses a line like: "google.com","bob","123"
// This manually extracts text between quotes to handle the format safely.
Credential Credential::fromCSV(const std::string& line) {
    std::string s, u, p;
    std::string temp;
    int state = 0; // 0 = site, 1 = username, 2 = password

    // Simple parser: loops through the line and extracts content between quotes
    bool insideQuotes = false;
    for (char c : line) {
        if (c == '\"') {
            // Toggle state when we hit a quote
            if (insideQuotes) {
                // End of a field
                if (state == 0) s = temp;
                else if (state == 1) u = temp;
                else if (state == 2) p = temp;
                temp = "";
                state++;
            }
            insideQuotes = !insideQuotes;
        } else if (insideQuotes) {
            // Add character to current field if we are inside quotes
            temp += c;
        }
    }
    return Credential(s, u, p);
}