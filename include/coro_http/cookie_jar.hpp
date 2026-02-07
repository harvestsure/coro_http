#pragma once

#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <sstream>
#include <algorithm>

namespace coro_http {

struct Cookie {
    std::string name;
    std::string value;
    std::string domain;
    std::string path{"/"};
    std::chrono::system_clock::time_point expires;
    bool secure{false};
    bool http_only{false};
    bool session{true};  // Session cookie if true (no expires)
    
    Cookie() = default;
    
    Cookie(const std::string& n, const std::string& v)
        : name(n), value(v) {}
    
    // Check if cookie is expired
    bool is_expired() const {
        if (session) return false;
        return std::chrono::system_clock::now() > expires;
    }
    
    // Check if cookie matches domain
    bool matches_domain(const std::string& request_domain) const {
        if (domain.empty()) return true;
        
        // Exact match
        if (domain == request_domain) return true;
        
        // Domain cookie (starts with .)
        if (domain[0] == '.') {
            std::string domain_suffix = domain.substr(1);
            if (request_domain.size() >= domain_suffix.size()) {
                auto pos = request_domain.size() - domain_suffix.size();
                return request_domain.substr(pos) == domain_suffix;
            }
        }
        
        return false;
    }
    
    // Check if cookie matches path
    bool matches_path(const std::string& request_path) const {
        if (path.empty() || path == "/") return true;
        
        // Path must be prefix of request path
        if (request_path.find(path) == 0) {
            // Exact match or path ends with /
            if (request_path.size() == path.size() || 
                request_path[path.size()] == '/' ||
                path.back() == '/') {
                return true;
            }
        }
        
        return false;
    }
};

class CookieJar {
public:
    CookieJar() = default;
    
    // Add a cookie
    void add(const Cookie& cookie) {
        std::string key = cookie.domain + cookie.path + cookie.name;
        cookies_[key] = cookie;
    }
    
    // Set a simple cookie (name=value)
    void set(const std::string& name, const std::string& value, 
             const std::string& domain = "", const std::string& path = "/") {
        Cookie cookie(name, value);
        cookie.domain = domain;
        cookie.path = path;
        add(cookie);
    }
    
    // Parse Set-Cookie header and add to jar
    void parse_set_cookie(const std::string& set_cookie_header, const std::string& default_domain) {
        Cookie cookie;
        cookie.domain = default_domain;
        
        // Split by semicolon
        std::istringstream ss(set_cookie_header);
        std::string segment;
        bool first = true;
        
        while (std::getline(ss, segment, ';')) {
            // Trim whitespace
            segment.erase(0, segment.find_first_not_of(" \t"));
            segment.erase(segment.find_last_not_of(" \t") + 1);
            
            if (first) {
                // First segment is name=value
                auto eq_pos = segment.find('=');
                if (eq_pos != std::string::npos) {
                    cookie.name = segment.substr(0, eq_pos);
                    cookie.value = segment.substr(eq_pos + 1);
                }
                first = false;
            } else {
                // Parse attributes
                auto eq_pos = segment.find('=');
                std::string attr_name = segment.substr(0, eq_pos);
                std::string attr_value = (eq_pos != std::string::npos) 
                    ? segment.substr(eq_pos + 1) : "";
                
                // Convert to lowercase for comparison
                std::transform(attr_name.begin(), attr_name.end(), 
                             attr_name.begin(), ::tolower);
                
                if (attr_name == "domain") {
                    cookie.domain = attr_value;
                } else if (attr_name == "path") {
                    cookie.path = attr_value;
                } else if (attr_name == "secure") {
                    cookie.secure = true;
                } else if (attr_name == "httponly") {
                    cookie.http_only = true;
                } else if (attr_name == "max-age") {
                    // Convert max-age to expires
                    try {
                        int max_age = std::stoi(attr_value);
                        cookie.expires = std::chrono::system_clock::now() + 
                                       std::chrono::seconds(max_age);
                        cookie.session = false;
                    } catch (...) {}
                }
                // TODO: Parse Expires attribute (requires date parsing)
            }
        }
        
        if (!cookie.name.empty()) {
            add(cookie);
        }
    }
    
    // Get all cookies for a request
    std::string get_cookies_for_request(const std::string& domain, 
                                        const std::string& path,
                                        bool is_https) const {
        std::vector<std::string> matching_cookies;
        
        for (const auto& [key, cookie] : cookies_) {
            // Skip expired cookies
            if (cookie.is_expired()) continue;
            
            // Skip secure cookies on non-HTTPS
            if (cookie.secure && !is_https) continue;
            
            // Check domain and path match
            if (cookie.matches_domain(domain) && cookie.matches_path(path)) {
                matching_cookies.push_back(cookie.name + "=" + cookie.value);
            }
        }
        
        // Join with semicolons
        std::ostringstream result;
        for (size_t i = 0; i < matching_cookies.size(); ++i) {
            if (i > 0) result << "; ";
            result << matching_cookies[i];
        }
        
        return result.str();
    }
    
    // Get a specific cookie value
    std::string get(const std::string& name, const std::string& domain = "") const {
        for (const auto& [key, cookie] : cookies_) {
            if (cookie.name == name && !cookie.is_expired()) {
                if (domain.empty() || cookie.matches_domain(domain)) {
                    return cookie.value;
                }
            }
        }
        return "";
    }
    
    // Remove a cookie
    void remove(const std::string& name, const std::string& domain = "", 
                const std::string& path = "/") {
        std::string key = domain + path + name;
        cookies_.erase(key);
    }
    
    // Clear all cookies
    void clear() {
        cookies_.clear();
    }
    
    // Get all cookies
    std::vector<Cookie> all_cookies() const {
        std::vector<Cookie> result;
        for (const auto& [key, cookie] : cookies_) {
            if (!cookie.is_expired()) {
                result.push_back(cookie);
            }
        }
        return result;
    }
    
    // Remove expired cookies
    void remove_expired() {
        for (auto it = cookies_.begin(); it != cookies_.end(); ) {
            if (it->second.is_expired()) {
                it = cookies_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    std::map<std::string, Cookie> cookies_;  // key = domain+path+name
};

}
