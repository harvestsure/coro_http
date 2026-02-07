#include "../include/coro_http/coro_http.hpp"
#include <iostream>

using namespace coro_http;

int main() {
    std::cout << "=== HTTP Auth & Features Example ===" << std::endl;
    
    ClientConfig config;
    config.connect_timeout = std::chrono::seconds(5);
    config.read_timeout = std::chrono::seconds(5);
    
    // Example 1: Basic Auth
    std::cout << "\n[1] Basic Auth" << std::endl;
    try {
        HttpClient client(config);
        auto req = HttpRequest(HttpMethod::GET, "https://httpbin.org/basic-auth/user/passwd");
        req.add_header("Authorization", Auth::basic("user", "passwd"));
        auto resp = client.execute(req);
        std::cout << "Status: " << resp.status_code() << std::endl;
        std::cout << "Body: " << resp.body().substr(0, 100) << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // Example 2: Bearer Token
    std::cout << "\n[2] Bearer Token" << std::endl;
    try {
        HttpClient client(config);
        auto req = HttpRequest(HttpMethod::GET, "https://httpbin.org/bearer");
        req.add_header("Authorization", Auth::bearer("test-token-123"));
        auto resp = client.execute(req);
        std::cout << "Status: " << resp.status_code() << std::endl;
        std::cout << "Body: " << resp.body().substr(0, 100) << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // Example 3: Form Data POST
    std::cout << "\n[3] Form Data POST" << std::endl;
    try {
        HttpClient client(config);
        FormData form;
        form.add("username", "john_doe")
            .add("email", "john@example.com")
            .add("message", "Hello World!");
        
        std::cout << "Encoded form: " << form.encode() << std::endl;
        
        auto req = HttpRequest(HttpMethod::POST, "https://httpbin.org/post");
        req.add_header("Content-Type", FormData::content_type());
        req.set_body(form.encode());
        
        auto resp = client.execute(req);
        std::cout << "Status: " << resp.status_code() << std::endl;
        std::cout << "Body (first 200 chars): " << resp.body().substr(0, 200) << "..." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // Example 4: Cookies
    std::cout << "\n[4] Cookies Management" << std::endl;
    try {
        ClientConfig cfg = config;
        cfg.enable_cookies = true;
        HttpClient client(cfg);
        
        // First request sets cookies
        auto r1 = client.get("https://httpbin.org/cookies/set?session=abc123&user=john");
        std::cout << "First request status: " << r1.status_code() << std::endl;
        
        // Show stored cookies
        std::cout << "Stored cookies:" << std::endl;
        for (const auto& c : client.cookies().all_cookies()) {
            std::cout << "  " << c.name << " = " << c.value << std::endl;
        }
        
        // Second request should include cookies automatically
        auto r2 = client.get("https://httpbin.org/cookies");
        std::cout << "\nSecond request status: " << r2.status_code() << std::endl;
        std::cout << "Response body: " << r2.body().substr(0, 150) << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // Example 5: Auth Helpers Demo
    std::cout << "\n[5] Auth Helpers Demo" << std::endl;
    std::cout << "Basic Auth Header: " << Auth::basic("user", "pass") << std::endl;
    std::cout << "Bearer Token Header: " << Auth::bearer("mytoken123") << std::endl;
    auto [header_name, header_value] = Auth::api_key("secret-key-xyz", "X-API-Key");
    std::cout << "API Key: " << header_name << " = " << header_value << std::endl;
    
    // Example 6: Manual Cookie Operations
    std::cout << "\n[6] Manual Cookie Operations" << std::endl;
    CookieJar jar;
    jar.set("session_id", "xyz789", "example.com");
    jar.set("user_pref", "dark_mode", "example.com");
    
    std::string cookie_header = jar.get_cookies_for_request("example.com", "/", false);
    std::cout << "Cookie header for example.com: " << cookie_header << std::endl;
    
    std::cout << "\n=== All Examples Completed ===" << std::endl;
    return 0;
}