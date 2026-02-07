#pragma once

#include <string>
#include <map>

namespace coro_http {

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DEL,
    HEAD,
    PATCH,
    OPTIONS
};

class HttpRequest {
public:
    HttpRequest(HttpMethod method, const std::string& url)
        : method_(method), url_(url) {}

    HttpRequest& add_header(const std::string& key, const std::string& value) {
        headers_[key] = value;
        return *this;
    }

    HttpRequest& set_body(const std::string& body) {
        body_ = body;
        return *this;
    }

    HttpMethod method() const { return method_; }
    const std::string& url() const { return url_; }
    const std::map<std::string, std::string>& headers() const { return headers_; }
    const std::string& body() const { return body_; }

private:
    HttpMethod method_;
    std::string url_;
    std::map<std::string, std::string> headers_;
    std::string body_;
};

}
