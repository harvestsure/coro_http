# coro-http-client

[![windows](https://github.com/harvestsure/coro-http-client/actions/workflows/windows.yml/badge.svg)](https://github.com/harvestsure/coro-http-client/actions/workflows/windows.yml)
[![ubuntu](https://github.com/harvestsure/coro-http-client/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/harvestsure/coro-http-client/actions/workflows/ubuntu.yml)
[![macos](https://github.com/harvestsure/coro-http-client/actions/workflows/macos.yml/badge.svg)](https://github.com/harvestsure/coro-http-client/actions/workflows/macos.yml)

A modern C++20 HTTP/HTTPS client library with coroutine-based async/await API.

## Features

- ✅ HTTP/HTTPS support with SSL/TLS
- ✅ C++20 coroutines for async operations  
- ✅ Connection pooling with Keep-Alive
- ✅ Automatic redirects and compression
- ✅ Retry policies with exponential backoff
- ✅ Rate limiting and timeout control
- ✅ Proxy support (HTTP/HTTPS/SOCKS5)
- ✅ Server-Sent Events (SSE) streaming
- ✅ Header-only library

## Quick Start

### Coroutine API

```cpp
#include <coro_http/coro_http.hpp>

int main() {
    asio::io_context io_ctx;
    coro_http::CoroHttpClient client(io_ctx);
    
    client.run([&]() -> asio::awaitable<void> {
        auto response = co_await client.co_get("https://api.github.com/users/github");
        std::cout << "Status: " << response.status_code() << "\n";
    });
    
    return 0;
}
```

### Server-Sent Events (SSE)

```cpp
coro_http::HttpRequest request(coro_http::HttpMethod::GET, "https://example.com/events");
request.add_header("Accept", "text/event-stream");

co_await client.co_stream_events(request, [](const coro_http::SseEvent& event) {
    std::cout << "Event type: " << event.type << "\n";
    std::cout << "Data: " << event.data << "\n";
});
```

## Requirements

- C++20 compiler
- CMake 3.20+
- OpenSSL, zlib

## Installation

```bash
git clone https://github.com/harvestsure/coro-http-client.git
cd coro-http-client
mkdir build && cd build
cmake ..
make
```

## Documentation

For detailed documentation, see:

- [API Reference](docs/API_REFERENCE.md) - Complete API documentation
- [SSE Support](docs/SSE_SUPPORT.md) - Server-Sent Events guide
- [Examples](docs/EXAMPLES.md) - Detailed examples
- [Features](docs/FEATURES.md) - Feature descriptions
- [Configuration](docs/CONFIGURATION.md) - Advanced configuration

## License

MIT License
