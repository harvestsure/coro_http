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
    
    bool enable_connection_pool{true};
    int max_connections_per_host{5};
    std::chrono::seconds connection_idle_timeout{60};
    
    // Rate limiting settings
    bool enable_rate_limit{false};
    int rate_limit_requests{100};      // requests per window
    std::chrono::seconds rate_limit_window{1};  // window size
    
    // Retry settings
    bool enable_retry{false};
    int max_retries{3};                // Maximum number of retry attempts
    std::chrono::milliseconds initial_retry_delay{1000};  // Initial delay before retry
    double retry_backoff_factor{2.0};  // Exponential backoff multiplier
    std::chrono::milliseconds max_retry_delay{30000};     // Maximum retry delay
    bool retry_on_timeout{true};       // Retry on connection/read timeout
    bool retry_on_connection_error{true};  // Retry on connection errors
    bool retry_on_5xx{false};          // Retry on 5xx server errors (disabled by default)
    
    // Cookie settings
    bool enable_cookies{false};        // Enable automatic cookie management
};

}
