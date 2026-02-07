#include <iostream>
#include <chrono>
#include <asio.hpp>
#include "coro_http/http_client.hpp"
#include "coro_http/coro_http_client.hpp"

using namespace coro_http;

void sync_connection_pool_demo() {
    std::cout << "=== Synchronous Connection Pool Demo ===\n\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.enable_connection_pool = true;
    config.max_connections_per_host = 3;
    config.connection_idle_timeout = std::chrono::seconds(30);
    
    HttpClient client(io_ctx, config);
    
    // Make multiple requests to the same host
    std::cout << "Making 5 requests to httpbin.org...\n";
    auto start = std::chrono::steady_clock::now();
    
    for (int i = 0; i < 5; ++i) {
        try {
            auto response = client.get("http://httpbin.org/delay/1");
            std::cout << "Request " << (i+1) << ": Status = " << response.status_code() << "\n";
            
            // Show connection pool stats
            auto stats = client.get_pool_stats();
            std::cout << "  Pool: " << stats.total_http_connections << " total, "
                      << stats.active_http_connections << " active\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "\nTotal time: " << duration.count() << "ms\n";
    std::cout << "Average per request: " << duration.count() / 5 << "ms\n\n";
}

void sync_rate_limiter_demo() {
    std::cout << "=== Synchronous Rate Limiter Demo ===\n\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.enable_rate_limit = true;
    config.rate_limit_requests = 3;  // 3 requests per second
    config.rate_limit_window = std::chrono::seconds(1);
    
    HttpClient client(io_ctx, config);
    
    std::cout << "Rate limit: " << config.rate_limit_requests << " requests per second\n";
    std::cout << "Making 6 requests (should take ~2 seconds)...\n\n";
    
    auto start = std::chrono::steady_clock::now();
    
    for (int i = 0; i < 6; ++i) {
        auto request_start = std::chrono::steady_clock::now();
        
        std::cout << "Request " << (i+1) << " - Remaining capacity: " 
                  << client.get_rate_limit_remaining() << " ";
        
        try {
            auto response = client.get("http://httpbin.org/uuid");
            
            auto request_end = std::chrono::steady_clock::now();
            auto request_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                request_end - request_start);
            
            std::cout << "- Done in " << request_duration.count() << "ms "
                      << "(Status: " << response.status_code() << ")\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "\nTotal time: " << duration.count() << "ms\n\n";
}

void async_connection_pool_demo() {
    std::cout << "=== Asynchronous Connection Pool Demo ===\n\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.enable_connection_pool = true;
    config.max_connections_per_host = 3;
    
    CoroHttpClient client(io_ctx, config);
    
    client.run([&]() -> asio::awaitable<void> {
        std::cout << "Making 5 concurrent requests to httpbin.org...\n";
        auto start = std::chrono::steady_clock::now();
        
        // Launch all requests concurrently
        std::vector<asio::awaitable<HttpResponse>> tasks;
        for (int i = 0; i < 5; ++i) {
            tasks.push_back(client.co_get("http://httpbin.org/delay/1"));
        }
        
        // Wait for all to complete
        for (size_t i = 0; i < tasks.size(); ++i) {
            try {
                auto response = co_await std::move(tasks[i]);
                std::cout << "Request " << (i+1) << ": Status = " << response.status_code() << "\n";
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
            }
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        auto stats = client.get_pool_stats();
        std::cout << "\nPool stats: " << stats.total_http_connections << " total, "
                  << stats.active_http_connections << " active\n";
        std::cout << "Total time: " << duration.count() << "ms\n";
        std::cout << "Average per request: " << duration.count() / 5 << "ms\n\n";
    });
}

void async_rate_limiter_demo() {
    std::cout << "=== Asynchronous Rate Limiter Demo ===\n\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.enable_rate_limit = true;
    config.rate_limit_requests = 5;  // 5 requests per second
    config.rate_limit_window = std::chrono::seconds(1);
    
    CoroHttpClient client(io_ctx, config);
    
    client.run([&]() -> asio::awaitable<void> {
        std::cout << "Rate limit: " << config.rate_limit_requests << " requests per second\n";
        std::cout << "Making 10 requests concurrently (should be throttled)...\n\n";
        
        auto start = std::chrono::steady_clock::now();
        
        for (int i = 0; i < 10; ++i) {
            auto request_start = std::chrono::steady_clock::now();
            
            std::cout << "Request " << (i+1) << " - Remaining: " 
                      << client.get_rate_limit_remaining() << " ";
            
            try {
                auto response = co_await client.co_get("http://httpbin.org/uuid");
                
                auto request_end = std::chrono::steady_clock::now();
                auto request_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    request_end - request_start);
                
                std::cout << "- Done in " << request_duration.count() << "ms "
                          << "(Status: " << response.status_code() << ")\n";
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
            }
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "\nTotal time: " << duration.count() << "ms\n\n";
    });
}

void trading_simulation_demo() {
    std::cout << "=== Trading Exchange Simulation ===\n\n";
    std::cout << "Simulating Binance-like API usage with rate limiting\n\n";
    
    asio::io_context io_ctx;
    ClientConfig config;
    config.enable_connection_pool = true;
    config.max_connections_per_host = 5;
    config.enable_rate_limit = true;
    config.rate_limit_requests = 10;  // Binance-like limit
    config.rate_limit_window = std::chrono::seconds(1);
    config.connect_timeout = std::chrono::milliseconds(5000);
    
    CoroHttpClient client(io_ctx, config);
    
    client.run([&]() -> asio::awaitable<void> {
        std::cout << "Connection pool: " << config.max_connections_per_host << " max per host\n";
        std::cout << "Rate limit: " << config.rate_limit_requests << " req/s\n\n";
        
        auto start = std::chrono::steady_clock::now();
        
        // Simulate checking multiple ticker prices
        std::vector<std::string> symbols = {"BTCUSDT", "ETHUSDT", "BNBUSDT"};
        
        for (int round = 0; round < 3; ++round) {
            std::cout << "Round " << (round + 1) << ":\n";
            
            for (const auto& symbol : symbols) {
                try {
                    // // Real Binance API would be:
                    // auto response = co_await client.co_get(
                    //     "https://api.binance.com/api/v3/ticker/price?symbol=" + symbol);
                    
                    // Using httpbin for demo
                    auto response = co_await client.co_get("http://httpbin.org/uuid");
                    
                    std::cout << "  " << symbol << ": Status " << response.status_code()
                              << " (rate limit remaining: " << client.get_rate_limit_remaining() << ")\n";
                } catch (const std::exception& e) {
                    std::cerr << "  Error fetching " << symbol << ": " << e.what() << "\n";
                }
            }
            std::cout << "\n";
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        auto stats = client.get_pool_stats();
        std::cout << "Complete!\n";
        std::cout << "Pool: " << stats.total_http_connections << " connections used\n";
        std::cout << "Time: " << duration.count() << "ms\n\n";
    });
}

int main() {
    std::cout << "Connection Pool and Rate Limiter Examples\n";
    std::cout << "==========================================\n\n";
    
    std::cout << "This demo shows:\n";
    std::cout << "1. Connection pooling for better performance\n";
    std::cout << "2. Rate limiting to avoid API throttling\n";
    std::cout << "3. Trading-like scenarios\n\n";
    
    // Uncomment the demos you want to run:
    
    sync_connection_pool_demo();
    sync_rate_limiter_demo();
    
    async_connection_pool_demo();
    async_rate_limiter_demo();
    
    trading_simulation_demo();
    
    std::cout << "All demos are commented out by default.\n";
    std::cout << "Uncomment the ones you want to test.\n";
    std::cout << "\nNote: These demos make real HTTP requests and may take time to complete.\n";
    
    return 0;
}
