#pragma once

#include "http_response.hpp"
#include "chunked_decoder.hpp"
#include "compression.hpp"
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace coro_http {

inline bool strcasecmp_parser(const std::string& a, const char* b) {
    size_t len = std::strlen(b);
    return a.size() == len && std::equal(a.begin(), a.end(), b,
        [](char ca, char cb) { return std::tolower(ca) == std::tolower(cb); });
}

inline HttpResponse parse_response(const std::string& response_data) {
    HttpResponse response;
    std::istringstream stream(response_data);
    std::string line;

    if (std::getline(stream, line)) {
        if (line.back() == '\r') line.pop_back();
        
        std::istringstream status_line(line);
        std::string http_version;
        int status_code;
        std::string reason;
        
        status_line >> http_version >> status_code;
        std::getline(status_line, reason);
        if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
        
        response.set_status_code(status_code);
        response.set_reason(reason);
    }

    while (std::getline(stream, line) && line != "\r") {
        if (line.back() == '\r') line.pop_back();
        
        auto colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            while (!value.empty() && value[0] == ' ') value = value.substr(1);
            while (!value.empty() && value.back() == ' ') value.pop_back();
            
            response.add_header(key, value);
        }
    }

    std::string body;
    std::string remaining((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    
    std::string transfer_encoding = response.get_header("Transfer-Encoding");
    std::transform(transfer_encoding.begin(), transfer_encoding.end(), transfer_encoding.begin(), ::tolower);
    
    if (transfer_encoding.find("chunked") != std::string::npos) {
        remaining = decode_chunked(remaining);
    }
    
    std::string content_encoding = response.get_header("Content-Encoding");
    std::transform(content_encoding.begin(), content_encoding.end(), content_encoding.begin(), ::tolower);
    
    if (content_encoding == "gzip") {
        remaining = decompress_gzip(remaining);
    } else if (content_encoding == "deflate") {
        remaining = decompress_deflate(remaining);
    }
    
    response.set_body(remaining);

    return response;
}

inline std::string build_request(const HttpRequest& request, const UrlInfo& url_info, bool enable_compression = true, bool keep_alive = false) {
    std::ostringstream req;
    
    req << method_to_string(request.method()) << " " << url_info.path << " HTTP/1.1\r\n";
    req << "Host: " << url_info.host << "\r\n";
    
    bool has_accept_encoding = false;
    bool has_connection = false;
    for (const auto& [key, value] : request.headers()) {
        req << key << ": " << value << "\r\n";
        if (strcasecmp_parser(key, "Accept-Encoding")) {
            has_accept_encoding = true;
        }
        if (strcasecmp_parser(key, "Connection")) {
            has_connection = true;
        }
    }
    
    if (enable_compression && !has_accept_encoding) {
        req << "Accept-Encoding: gzip, deflate\r\n";
    }
    
    if (!request.body().empty()) {
        req << "Content-Length: " << request.body().size() << "\r\n";
    }
    
    if (!has_connection) {
        req << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n";
    }
    
    req << "\r\n";
    
    if (!request.body().empty()) {
        req << request.body();
    }
    
    return req.str();
}

}
