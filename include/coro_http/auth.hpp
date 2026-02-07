#pragma once

#include <string>
#include <sstream>
#include <iomanip>

namespace coro_http {

// Base64 encoding helper
inline std::string base64_encode(const std::string& input) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::string result;
    int val = 0;
    int valb = -6;
    
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (result.size() % 4) {
        result.push_back('=');
    }
    
    return result;
}

enum class AuthType {
    None,
    Basic,
    Bearer
};

class Auth {
public:
    // Create Basic Authentication header
    static std::string basic(const std::string& username, const std::string& password) {
        std::string credentials = username + ":" + password;
        return "Basic " + base64_encode(credentials);
    }
    
    // Create Bearer Token header
    static std::string bearer(const std::string& token) {
        return "Bearer " + token;
    }
    
    // Create API Key header (custom header name)
    static std::pair<std::string, std::string> api_key(
        const std::string& key_value,
        const std::string& header_name = "X-API-Key") {
        return {header_name, key_value};
    }
};

}
