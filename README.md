# coro_http

A modern C++20 HTTP/HTTPS client library based on [ASIO](https://github.com/chriskohlhoff/asio), supporting both synchronous and coroutine-based interfaces with advanced features like automatic compression, redirect following, and configurable timeouts.

## Features

- ✅ **HTTP/HTTPS Support** - Seamless HTTP and HTTPS requests with SSL/TLS
- ✅ **C++20 Coroutines** - Modern async/await syntax for non-blocking operations
- ✅ **Synchronous API** - Traditional blocking API for simple use cases
- ✅ **Complete HTTP Methods** - GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS
- ✅ **Connection Pool** - Keep-Alive support with automatic connection reuse
- ✅ **Rate Limiting** - Built-in request rate limiter to avoid API throttling
- ✅ **Timeout Control** - Configurable connect, read, and request timeouts
- ✅ **Auto Redirects** - Automatic HTTP 3xx redirect following with chain tracking
- ✅ **Compression** - Automatic gzip/deflate decompression
- ✅ **Chunked Transfer** - Support for Transfer-Encoding: chunked
- ✅ **SSL Verification** - Optional certificate verification with custom CA support
- ✅ **Proxy Support** - HTTP/HTTPS/SOCKS5 proxies with authentication
- ✅ **Header-Only** - Easy integration, no compilation required
- ✅ **Custom Headers** - Flexible builder pattern for request customization
- ✅ **Auto Dependency** - CMake FetchContent automatically downloads ASIO

## Why coro_http?

- **Production-Ready**: Handles real-world HTTP complexities (redirects, compression, chunked encoding)
- **Type-Safe**: Leverages C++20 features for compile-time safety
- **Flexible**: Choose between sync for simplicity or coroutines for performance
- **Zero Config**: Sensible defaults with opt-in customization
- **Lightweight**: Header-only library with minimal dependencies

## Requirements

- C++20 compiler (GCC 10+, Clang 10+, MSVC 2019+)
- CMake 3.20+
- OpenSSL (for HTTPS support)
- zlib (for compression support)

### Windows Dependencies

On Windows, we recommend using [vcpkg](https://github.com/microsoft/vcpkg) to install dependencies:

```bash
# Install vcpkg (if not already installed)
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat

# Install dependencies
vcpkg install openssl:x64-windows zlib:x64-windows

# Configure CMake with vcpkg toolchain
cmake -B build -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

## Installation

### Using CMake FetchContent

```cmake
include(FetchContent)

FetchContent_Declare(
    coro_http
    GIT_REPOSITORY https://github.com/yourusername/coro_http.git
    GIT_TAG main
)

FetchContent_MakeAvailable(coro_http)

target_link_libraries(your_target PRIVATE coro_http)
```

### Manual Build

```bash
git clone https://github.com/yourusername/coro_http.git
cd coro_http (Simple & Straightforward)

```cpp
#include <coro_http/coro_http.hpp>
#include <iostream>

int main() {
    coro_http::HttpClient client;
    
    // Simple GET request
    auto response = client.get("https://api.github.com/users/github");
    std::cout << "Status: " << response.status_code() << "\n";
    std::cout << "Body: " << response.body() << "\n";
    
    // POST with JSON body
    auto post_resp = client.post(
        "https://httpbin.org/post",
        R"({"name": "test", "value": 123})"
    );
    
    // Automatic redirect following, compression, and SSL
    auto redir_resp = client.get("https://httpbin.org/redirect/3");
    std::cout << "Followed " << redir_resp.redirect_chain().size() << " redirects\n";
    
    return 0;
}
```

### Coroutine API (High Performance)

```cpp
#include <coro_http/coro_http.hpp>
#include <iostream>

asio::awaitable<void> async_main(coro_http::CoroHttpClient& client) {
    // Async GET request with co_await
    auto response = co_await client.co_get("https://api.github.com/users/github");
    std::cout << "Status: " << response.status_code() << "\n";
    
    // Concurrent requests for better performance
    auto resp1_task = client.co_get("https://httpbin.org/get");
    auto resp2_task = client.co_get("https://httpbin.org/ip");
    
    auto resp1 = co_await resp1_task;
    auto resp2 = co_await resp2_task;
    
    std::cout << "Both requests completed!\n" client.co_get("https://api.github.com/users/github");
    std::cout << "Status: " << response.status_code() << "\n";
    
    // Concurrent requests
    auto resp1 = client.co_get("https://httpbin.org/get");
    auto resp2 = client.co_get("https://httpbin.org/ip");
    
    auto r1 = co_await resp1;
    auto r2 = co_await resp2;
}

int main() {
    coro_http::CoroHttpClient client;
    client.run([&]() -> asio::awaitable<void> {
        co_await async_main(client);
    });
    return 0;
}
```

## Configuration

### ClientConfig Options

```cpp
#include <coro_http/client_config.hpp>

coro_http::ClientConfig config;

// Timeout settings (in milliseconds)
config.connect_timeout = std::chrono::milliseconds(5000);  // Connection timeout
config.read_timeout = std::chrono::milliseconds(10000);     // Read timeout
config.request_timeout = std::chrono::milliseconds(30000);  // Overall request timeout

// Redirect settings
config.follow_redirects = true;   // Enable automatic redirect following
config.max_redirects = 10;        // Maximum number of redirects to follow

// Compression settings
config.enable_compression = true; // Enable gzip/deflate decompression

// SSL/TLS settings
config.verify_ssl = false;                        // Enable certificate verification
config.ca_cert_file = "/path/to/ca-bundle.crt";  // Custom CA certificate file
config.ca_cert_path = "/path/to/certs/";         // Custom CA certificate directory

// Proxy settings
config.proxy_url = "http://proxy.example.com:8080";  // HTTP/HTTPS/SOCKS5 proxy
config.proxy_username = "username";                   // Proxy authentication (optional)
config.proxy_password = "password";                   // Proxy password (optional)

// Connection pool settings
config.enable_connection_pool = true;              // Enable connection pooling (default: true)
config.max_connections_per_host = 5;               // Max connections per host (default: 5)
config.connection_idle_timeout = std::chrono::seconds(60);  // Idle timeout (default: 60s)

// Rate limiting settings  
config.enable_rate_limit = true;                   // Enable rate limiting (default: false)
config.rate_limit_requests = 100;                  // Max requests per window (default: 100)
config.rate_limit_window = std::chrono::seconds(1);  // Rate limit window (default: 1s)

// Create client with config
coro_http::HttpClient client(config);

// Or update config after creation
client.set_config(config);
```

### Advanced Features

#### Redirect Chain Tracking

```cpp
auto response = client.get("https://httpbin.org/redirect/3");
std::cout << "Final status: " << response.status_code() << "\n";
std::cout << "Redirects: " << response.redirect_chain().size() << "\n";
for (const auto& url : response.redirect_chain()) {
    std::cout << "  -> " << url << "\n";
}
```

#### Compression Support

```cpp
// Compression is enabled by default
// The library automatically:
// - Adds "Accept-Encoding: gzip, deflate" header
// - Decompresses response based on Content-Encoding header
auto response = client.get("https://httpbin.org/gzip");
// Body is automatically decompressed
```

#### SSL Certificate Verification

```cpp
coro_http::ClientConfig config;
config.verify_ssl = true;  // Enable strict certificate verification
config.ca_cert_file = "/etc/ssl/certs/ca-certificates.crt";

coro_http::HttpClient client(config);
auto response = client.get("https://example.com");
```

#### Proxy Support

The library supports HTTP, HTTPS, and SOCKS5 proxies with optional authentication:

```cpp
coro_http::ClientConfig config;

// HTTP proxy (standard proxy for HTTP requests)
config.proxy_url = "http://proxy.example.com:8080";

// SOCKS5 proxy (works with both HTTP and HTTPS)
config.proxy_url = "socks5://127.0.0.1:1080";

// Proxy with authentication
config.proxy_url = "http://proxy.example.com:8080";
config.proxy_username = "user";
config.proxy_password = "password";

coro_http::HttpClient client(config);

// For HTTP requests, proxy forwards the request
auto http_resp = client.get("http://example.com");

// For HTTPS requests, proxy uses HTTP CONNECT tunneling
auto https_resp = client.get("https://example.com");
```

**Supported Proxy Types:**
- **HTTP Proxy** (`http://...`): Standard HTTP proxy for HTTP requests, CONNECT tunneling for HTTPS
- **HTTPS Proxy** (`https://...`): Same as HTTP proxy but with TLS connection to proxy server
- **SOCKS5 Proxy** (`socks5://...`): SOCKS5 protocol for both HTTP and HTTPS with optional username/password authentication

```cpp
// Complete proxy example
coro_http::ClientConfig config;
config.proxy_url = "socks5://proxy.example.com:1080";
config.proxy_username = "myuser";
config.proxy_password = "mypass";
config.verify_ssl = true;

coro_http::CoroHttpClient client(config);
client.run([&]() -> asio::awaitable<void> {
    auto response = co_await client.co_get("https://api.ipify.org?format=json");
    std::cout << "My IP through proxy: " << response.body() << "\n";
});
```

#### Connection Pool & Keep-Alive

The library automatically reuses TCP/TLS connections for better performance. This is especially important for:
- **High-frequency trading APIs** (Binance, OKX, etc.)
- **Repeated requests** to the same server
- **REST API polling**

```cpp
coro_http::ClientConfig config;
config.enable_connection_pool = true;         // Default: true
config.max_connections_per_host = 5;          // Max 5 connections per host
config.connection_idle_timeout = std::chrono::seconds(60);  // Keep connections for 60s

coro_http::HttpClient client(config);

// First request: establishes connection  (~300ms with TLS handshake)
auto resp1 = client.get("https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT");

// Subsequent requests: reuse connection (~50ms, 6x faster!)
auto resp2 = client.get("https://api.binance.com/api/v3/account");
auto resp3 = client.get("https://api.binance.com/api/v3/openOrders");

// Check pool statistics
auto stats = client.get_pool_stats();
std::cout << "Active connections: " << stats.total_http_connections << "\n";

// Clear pool if needed
client.clear_connection_pool();
```

**Performance Impact:**
- Without connection pool: Each request = DNS + TCP handshake + TLS handshake + HTTP (~300ms)
- With connection pool: First request ~300ms, subsequent requests ~50ms
- **Up to 6x faster for repeated requests!**

#### Rate Limiting

Built-in rate limiter helps avoid API throttling (essential for exchange APIs):

```cpp
coro_http::ClientConfig config;
config.enable_rate_limit = true;
config.rate_limit_requests = 10;              // 10 requests
config.rate_limit_window = std::chrono::seconds(1);  // per second

coro_http::HttpClient client(config);

// These requests will be automatically throttled
for (int i = 0; i < 20; ++i) {
    // First 10 requests go through immediately
    // Next 10 wait until the next 1-second window
    auto resp = client.get("https://api.example.com/data");
    
    std::cout << "Rate limit remaining: " << client.get_rate_limit_remaining() << "\n";
}

// Reset rate limiter if needed
client.reset_rate_limiter();
```

**Common Exchange Rate Limits:**
- **Binance**: 1200 requests/minute (20 req/s)
- **OKX**: 20 requests/2 seconds (10 req/s)  
- **Coinbase**: 10 requests/second

**Trading Bot Example:**
```cpp
coro_http::ClientConfig config;
config.enable_connection_pool = true;
config.enable_rate_limit = true;
config.rate_limit_requests = 10;
config.rate_limit_window = std::chrono::seconds(1);

coro_http::CoroHttpClient client(config);

client.run([&]() -> asio::awaitable<void> {
    while (true) {
        // Fetch ticker prices (automatically rate limited)
        auto btc = co_await client.co_get("https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT");
        auto eth = co_await client.co_get("https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT");
        
        // Process data...
        std::cout << "Remaining capacity: " << client.get_rate_limit_remaining() << "\n";
    }
});
```

#### Timeout Handling

```cpp
coro_http::ClientConfig config;
config.connect_timeout = std::chrono::milliseconds(1000);
config.read_timeout = std::chrono::milliseconds(2000);

coro_http::HttpClient client(config);

try {
    auto response = client.get("https://slow-server.com");
} catch (const std::runtime_error& e) {
    // Handle timeout: "Connection timeout" or "Read timeout"
    std::cerr << "Request failed: " << e.what() << "\n";
}
```

## API Reference

### Synchronous HttpClient

```cpp
// Default configuration
coro_http::HttpClient client;

// With custom configuration
coro_http::ClientConfig config;
config.connect_timeout = std::chrono::milliseconds(5000);
coro_http::HttpClient client(config);

// HTTP Methods
auto resp = client.get(url);
auto resp = client.post(url, body);
auto resp = client.put(url, body);
auto resp = client.del(url);
auto resp = client.head(url);
auto resp = client.patch(url, body);
auto resp = client.options(url);

// Custom request with headers
coro_http::HttpRequest req(coro_http::HttpMethod::GET, url);
req.add_header("Authorization", "Bearer token")
   .add_header("User-Agent", "MyApp/1.0")
   .set_body("request body");
auto resp = client.execute(req);
```

### Coroutine CoroHttpClient

```cpp
coro_http::CoroHttpClient client;

client.run([&]() -> asio::awaitable<void> {
    // All methods return awaitable<HttpResponse>
    auto resp = co_await client.co_get(url);
    auto resp = co_await client.co_post(url, body);
    auto resp = co_await client.co_put(url, body);
    auto resp = co_await client.co_delete(url);
    auto resp = co_await client.co_head(url);
    auto resp = co_await client.co_patch(url, body);
    auto resp = co_await client.co_options(url);
    
    // Custom coroutine request
    coro_http::HttpRequest req(coro_http::HttpMethod::POST, url);
    req.add_header("Content-Type", "application/json");
    auto resp = co_await client.co_execute(req);
});
```

### Response Object

```cpp
class HttpResponse {
    int status_code() const;
    const std::string& reason() const;
    const std::map<std::string, std::string>& headers() const;
    const std::string& body() const;
    const std::vector<std::string>& redirect_chain() const;
    std::string get_header(const std::string& key) const;  // Case-insensitive
};

// Usage
auto response = client.get("https://api.example.com");
std::cout << "Status: " << response.status_code() << "\n";
std::cout << "Body: " << response.body() << "\n";
std::cout << "Content-Type: " << response.get_header("Content-Type") << "\n";

// Check redirects
if (!response.redirect_chain().empty()) {
    std::cout << "Followed " << response.redirect_chain().size() << " redirects\n";
}
```
    const std::string& reason() const;
    const std::map<std::string, std::string>& headers() const;
    const std::string& body() const;
};
```

## Examples

See the [examples](examples/) directory for complete working examples:

- [sync_example.cpp](examples/sync_example.cpp) - Synchronous API usage with HTTP/HTTPS
- [coro_example.cpp](examples/coro_example.cpp) - Coroutine API usage with all methods
- [https_example.cpp](examples/https_example.cpp) - HTTPS requests demonstration
- [advanced_example.cpp](examples/advanced_example.cpp) - Advanced features (compression, redirects, timeouts, custom headers)
- [proxy_example.cpp](examples/proxy_example.cpp) - Proxy support (HTTP/HTTPS/SOCKS5) with authentication
- [keepalive_example.cpp](examples/keepalive_example.cpp) - Connection pooling and rate limiting for high-performance scenarios

## Building Examples

```bash
cd build
cmake ..
make

# Run examples
./example_sync
./example_coro
./example_https
./example_advanced
./example_proxy
./example_keepalive
./example_proxy
```

## Troubleshooting

### SSL Errors

If you encounter SSL certificate errors, you can:

1. Disable verification (not recommended for production):
```cpp
config.verify_ssl = false;
```

2. Specify a CA certificate bundle:
```cpp
config.verify_ssl = true;
config.ca_cert_file = "/etc/ssl/certs/ca-certificates.crt";
```


## Performance Considerations

### Synchronous vs Coroutine

- **Synchronous API**: Best for simple scripts, CLI tools, or when making sequential requests
- **Coroutine API**: Best for servers, high-throughput applications, or when making many concurrent requests

### Connection Pooling (Enabled by Default)

The library automatically reuses connections for better performance:

- **First request**: DNS + TCP + TLS handshake + HTTP ≈ 300ms
- **Subsequent requests**: HTTP only ≈ 50ms (6x faster!)
- **Configurable**: `config.enable_connection_pool`, `config.max_connections_per_host`

**Best for:**
- Trading bots and exchange APIs
- Repeated API polling
- Microservice communication

**Disable if:** You need fresh connections for every request (rare)

### Rate Limiting

Enable rate limiting to avoid API throttling:

```cpp
config.enable_rate_limit = true;
config.rate_limit_requests = 10;  // Match your API limit
config.rate_limit_window = std::chrono::seconds(1);
```

### Memory Usage

The library buffers entire responses in memory. For very large responses (e.g., large file downloads), consider streaming approaches or external tools.

## Roadmap

Future enhancements under consideration:

- ✅ Connection pooling and Keep-Alive support
- ✅ Rate limiting
- Streaming downloads/uploads  
- HTTP/2 support
- WebSocket upgrade
- Cookie management
- Request retry with exponential backoff
- Async rate limiter (currently synchronous)
### Timeout Issues

Adjust timeouts based on your network conditions:
```cpp
config.connect_timeout = std::chrono::milliseconds(10000);  // 10 seconds
config.read_timeout = std::chrono::milliseconds(30000);     // 30 seconds
```

### Compression Issues

If you experience issues with compressed responses:
```cpp
config.enable_compression = false;  // Disable automatic decompression
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
