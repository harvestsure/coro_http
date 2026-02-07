#include <iostream>
#include <asio.hpp>
#include "coro_http/http_client.hpp"
#include "coro_http/coro_http_client.hpp"

using namespace coro_http;

void sync_http_proxy_example() {
    std::cout << "--- Synchronous HTTP Proxy Example ---\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.proxy_url = "http://proxy.example.com:8080";
    // config.proxy_username = "user";
    // config.proxy_password = "pass";
    
    HttpClient client(io_ctx, config);
    
    try {
        auto response = client.get("http://httpbin.org/ip");
        std::cout << "Status: " << response.status_code() << "\n";
        std::cout << "Body: " << response.body() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

void sync_https_proxy_example() {
    std::cout << "\n--- Synchronous HTTPS Proxy (CONNECT) Example ---\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.proxy_url = "http://proxy.example.com:8080";
    // config.proxy_username = "user";
    // config.proxy_password = "pass";
    
    HttpClient client(io_ctx, config);
    
    try {
        auto response = client.get("https://httpbin.org/ip");
        std::cout << "Status: " << response.status_code() << "\n";
        std::cout << "Body: " << response.body() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

void sync_socks5_proxy_example() {
    std::cout << "\n--- Synchronous SOCKS5 Proxy Example ---\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.proxy_url = "socks5://127.0.0.1:1080";
    // config.proxy_username = "user";
    // config.proxy_password = "pass";
    
    HttpClient client(io_ctx, config);
    
    try {
        auto response = client.get("http://httpbin.org/ip");
        std::cout << "Status: " << response.status_code() << "\n";
        std::cout << "Body: " << response.body() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

void async_http_proxy_example() {
    std::cout << "\n--- Asynchronous HTTP Proxy Example ---\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.proxy_url = "http://proxy.example.com:8080";
    // config.proxy_username = "user";
    // config.proxy_password = "pass";
    
    CoroHttpClient client(io_ctx, config);
    
    client.run([&client]() -> asio::awaitable<void> {
        try {
            auto response = co_await client.co_get("http://httpbin.org/ip");
            std::cout << "Status: " << response.status_code() << "\n";
            std::cout << "Body: " << response.body() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    });
}

void async_https_proxy_example() {
    std::cout << "\n--- Asynchronous HTTPS Proxy (CONNECT) Example ---\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.proxy_url = "http://proxy.example.com:8080";
    
    CoroHttpClient client(io_ctx, config);
    
    client.run([&client]() -> asio::awaitable<void> {
        try {
            auto response = co_await client.co_get("https://httpbin.org/ip");
            std::cout << "Status: " << response.status_code() << "\n";
            std::cout << "Body: " << response.body() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    });
}

void async_socks5_proxy_example() {
    std::cout << "\n--- Asynchronous SOCKS5 Proxy Example ---\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.proxy_url = "socks5://127.0.0.1:1080";
    // config.proxy_username = "user";
    // config.proxy_password = "pass";
    
    CoroHttpClient client(io_ctx, config);
    
    client.run([&client]() -> asio::awaitable<void> {
        try {
            auto response = co_await client.co_get("http://httpbin.org/ip");
            std::cout << "Status: " << response.status_code() << "\n";
            std::cout << "Body: " << response.body() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    });
}

int main() {
    std::cout << "Proxy Examples for coro_http\n";
    std::cout << "========================================\n\n";
    std::cout << "Note: These examples require working proxy servers.\n";
    std::cout << "Update proxy URLs and credentials as needed.\n\n";
    
    // Uncomment the examples you want to test
    // Make sure you have a working proxy server at the specified addresses
    
    // sync_http_proxy_example();
    // sync_https_proxy_example();
    // sync_socks5_proxy_example();
    
    // async_http_proxy_example();
    // async_https_proxy_example();
    // async_socks5_proxy_example();
    
    std::cout << "\nAll examples are commented out by default.\n";
    std::cout << "Uncomment the ones you want to run and configure valid proxy settings.\n";
    
    return 0;
}
