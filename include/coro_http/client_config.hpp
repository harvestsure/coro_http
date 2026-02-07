#pragma once

#include <chrono>
#include <string>

namespace coro_http {

struct ClientConfig {
    std::chrono::milliseconds connect_timeout{30000};
    std::chrono::milliseconds read_timeout{30000};
    std::chrono::milliseconds request_timeout{60000};
    
    bool follow_redirects{true};
    int max_redirects{10};
    
    bool enable_compression{true};
    
    bool verify_ssl{false};
    std::string ca_cert_file;
    std::string ca_cert_path;
    
    std::string proxy_url;
    std::string proxy_username;
    std::string proxy_password;
    
    // Connection pool settings
    bool enable_connection_pool{true};
    int max_connections_per_host{5};
    std::chrono::seconds connection_idle_timeout{60};
    
    // Rate limiting settings
    bool enable_rate_limit{false};
    int rate_limit_requests{100};      // requests per window
    std::chrono::seconds rate_limit_window{1};  // window size
};

}
