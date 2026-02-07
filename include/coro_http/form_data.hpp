#pragma once

#include <string>
#include <map>
#include <sstream>
#include <iomanip>

namespace coro_http {

// URL encoding helper
inline std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (std::isalnum(static_cast<unsigned char>(c)) || 
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            // Encode special characters
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

// Form data for application/x-www-form-urlencoded
class FormData {
public:
    FormData() = default;
    
    // Add a field
    FormData& add(const std::string& key, const std::string& value) {
        fields_[key] = value;
        return *this;
    }
    
    // Add a field (convenience for chaining)
    FormData& set(const std::string& key, const std::string& value) {
        return add(key, value);
    }
    
    // Encode to application/x-www-form-urlencoded format
    std::string encode() const {
        std::ostringstream result;
        bool first = true;
        
        for (const auto& [key, value] : fields_) {
            if (!first) {
                result << '&';
            }
            result << url_encode(key) << '=' << url_encode(value);
            first = false;
        }
        
        return result.str();
    }
    
    // Get content type
    static std::string content_type() {
        return "application/x-www-form-urlencoded";
    }
    
    // Get all fields
    const std::map<std::string, std::string>& fields() const {
        return fields_;
    }
    
    // Check if empty
    bool empty() const {
        return fields_.empty();
    }
    
    // Clear all fields
    void clear() {
        fields_.clear();
    }

private:
    std::map<std::string, std::string> fields_;
};

}
