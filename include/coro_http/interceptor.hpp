#pragma once

#include "http_request.hpp"
#include "http_response.hpp"
#include <functional>
#include <vector>

namespace coro_http {

// Request interceptor - can modify request before sending
using RequestInterceptor = std::function<void(HttpRequest&)>;

// Response interceptor - can inspect/modify response after receiving
using ResponseInterceptor = std::function<void(const HttpRequest&, HttpResponse&)>;

class InterceptorChain {
public:
    InterceptorChain() = default;
    
    // Add request interceptor
    void add_request_interceptor(RequestInterceptor interceptor) {
        request_interceptors_.push_back(std::move(interceptor));
    }
    
    // Add response interceptor
    void add_response_interceptor(ResponseInterceptor interceptor) {
        response_interceptors_.push_back(std::move(interceptor));
    }
    
    // Execute all request interceptors
    void process_request(HttpRequest& request) const {
        for (const auto& interceptor : request_interceptors_) {
            interceptor(request);
        }
    }
    
    // Execute all response interceptors
    void process_response(const HttpRequest& request, HttpResponse& response) const {
        for (const auto& interceptor : response_interceptors_) {
            interceptor(request, response);
        }
    }
    
    // Clear all interceptors
    void clear() {
        request_interceptors_.clear();
        response_interceptors_.clear();
    }
    
    // Check if has any interceptors
    bool has_request_interceptors() const {
        return !request_interceptors_.empty();
    }
    
    bool has_response_interceptors() const {
        return !response_interceptors_.empty();
    }

private:
    std::vector<RequestInterceptor> request_interceptors_;
    std::vector<ResponseInterceptor> response_interceptors_;
};

// Common interceptor factories

namespace interceptors {

// Add authorization header to all requests
inline RequestInterceptor authorization(const std::string& auth_header) {
    return [auth_header](HttpRequest& req) {
        req.add_header("Authorization", auth_header);
    };
}

// Add custom header to all requests
inline RequestInterceptor custom_header(const std::string& key, const std::string& value) {
    return [key, value](HttpRequest& req) {
        req.add_header(key, value);
    };
}

// Add User-Agent header
inline RequestInterceptor user_agent(const std::string& ua) {
    return custom_header("User-Agent", ua);
}

// Log requests
inline RequestInterceptor log_request(std::function<void(const HttpRequest&)> logger) {
    return [logger](HttpRequest& req) {
        logger(req);
    };
}

// Log responses
inline ResponseInterceptor log_response(std::function<void(const HttpResponse&)> logger) {
    return [logger](const HttpRequest&, HttpResponse& resp) {
        logger(resp);
    };
}

// Check response status and throw on error
inline ResponseInterceptor throw_on_error() {
    return [](const HttpRequest&, HttpResponse& resp) {
        if (resp.status_code() >= 400) {
            throw std::runtime_error("HTTP Error " + std::to_string(resp.status_code()) + 
                                   ": " + resp.reason());
        }
    };
}

}  // namespace interceptors

}  // namespace coro_http
