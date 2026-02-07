#pragma once

#include <string>
#include <regex>

namespace coro_http {

struct UrlInfo {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
    bool is_https;
};

inline UrlInfo parse_url(const std::string& url) {
    UrlInfo info;
    
    std::regex url_regex(R"(^(https?):\/\/([^:\/\s]+)(?::(\d+))?(\/[^\s]*)?)");
    std::smatch matches;
    
    if (std::regex_search(url, matches, url_regex)) {
        info.scheme = matches[1].str();
        info.host = matches[2].str();
        info.port = matches[3].matched ? matches[3].str() : (matches[1].str() == "https" ? "443" : "80");
        info.path = matches[4].matched ? matches[4].str() : "/";
        info.is_https = matches[1].str() == "https";
    } else {
        throw std::runtime_error("Invalid URL format");
    }
    
    return info;
}

inline std::string method_to_string(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DEL: return "DELETE";
        case HttpMethod::HEAD: return "HEAD";
        case HttpMethod::PATCH: return "PATCH";
        case HttpMethod::OPTIONS: return "OPTIONS";
        default: return "GET";
    }
}

}
