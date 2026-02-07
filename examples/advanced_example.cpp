#include <coro_http/coro_http.hpp>
#include <coro_http/client_config.hpp>
#include <iostream>
#include <chrono>
#include <asio.hpp>

int main() {
    try {
        asio::io_context io_ctx;
        
        coro_http::ClientConfig config;
        config.connect_timeout = std::chrono::milliseconds(5000);
        config.read_timeout = std::chrono::milliseconds(10000);
        config.request_timeout = std::chrono::milliseconds(30000);
        config.follow_redirects = true;
        config.max_redirects = 5;
        config.enable_compression = true;
        config.verify_ssl = false;

        coro_http::HttpClient client(io_ctx, config);

        std::cout << "=== Test: Compression Support ===" << "\n";
        auto gzip_resp = client.get("https://httpbin.org/gzip");
        std::cout << "Status: " << gzip_resp.status_code() << "\n";
        std::cout << "Body length: " << gzip_resp.body().length() << "\n";
        std::cout << "Content-Encoding: " << gzip_resp.get_header("Content-Encoding") << "\n\n";

        std::cout << "=== Test: HTTP Redirect ===" << "\n";
        auto redirect_resp = client.get("https://httpbin.org/redirect/3");
        std::cout << "Status: " << redirect_resp.status_code() << "\n";
        std::cout << "Redirect chain size: " << redirect_resp.redirect_chain().size() << "\n";
        for (size_t i = 0; i < redirect_resp.redirect_chain().size(); ++i) {
            std::cout << "  Redirect " << (i + 1) << ": " << redirect_resp.redirect_chain()[i] << "\n";
        }
        std::cout << "\n";

        std::cout << "=== Test: Custom Headers ===" << "\n";
        coro_http::HttpRequest custom_req(coro_http::HttpMethod::GET, "https://httpbin.org/headers");
        custom_req.add_header("X-Custom-Header", "CustomValue")
                  .add_header("User-Agent", "CoroHttpClient/2.0")
                  .add_header("Accept", "application/json");
        auto custom_resp = client.execute(custom_req);
        std::cout << "Status: " << custom_resp.status_code() << "\n";
        std::cout << "Body: " << custom_resp.body().substr(0, 300) << "...\n\n";

        std::cout << "=== Test: POST with JSON ===" << "\n";
        coro_http::HttpRequest post_req(coro_http::HttpMethod::POST, "https://httpbin.org/post");
        post_req.add_header("Content-Type", "application/json")
                .set_body(R"({"name":"test","value":123,"nested":{"key":"value"}})");
        auto post_resp = client.execute(post_req);
        std::cout << "Status: " << post_resp.status_code() << "\n";
        std::cout << "Response length: " << post_resp.body().length() << "\n\n";

        std::cout << "=== Test: Response Headers ===" << "\n";
        auto headers_resp = client.get("https://httpbin.org/response-headers?Custom-Header=CustomValue");
        std::cout << "Status: " << headers_resp.status_code() << "\n";
        std::cout << "Headers:\n";
        for (const auto& [key, value] : headers_resp.headers()) {
            std::cout << "  " << key << ": " << value << "\n";
        }
        std::cout << "\n";

        std::cout << "=== Test: Timeout Configuration ===" << "\n";
        coro_http::ClientConfig timeout_config;
        timeout_config.connect_timeout = std::chrono::milliseconds(1000);
        timeout_config.read_timeout = std::chrono::milliseconds(2000);
        coro_http::HttpClient timeout_client(io_ctx, timeout_config);
        
        try {
            auto delay_resp = timeout_client.get("https://httpbin.org/delay/10");
            std::cout << "Unexpected success\n";
        } catch (const std::exception& e) {
            std::cout << "Timeout caught as expected: " << e.what() << "\n\n";
        }

        std::cout << "=== Test: HTTP Methods ===" << "\n";
        std::cout << "PUT: " << client.put("https://httpbin.org/put", R"({"updated":true})").status_code() << "\n";
        std::cout << "DELETE: " << client.del("https://httpbin.org/delete").status_code() << "\n";
        std::cout << "PATCH: " << client.patch("https://httpbin.org/patch", R"({"patched":true})").status_code() << "\n";
        std::cout << "HEAD: " << client.head("https://httpbin.org/get").status_code() << "\n";
        std::cout << "OPTIONS: " << client.options("https://httpbin.org/get").status_code() << "\n\n";

        std::cout << "All tests completed successfully!\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
