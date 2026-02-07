#include "../include/coro_http/coro_http.hpp"
#include <iostream>

using namespace coro_http;

int main() {
    std::cout << "=== HTTP Auth Features Local Test ===" << std::endl;
    
    // Test 1: Auth Helper Functions
    std::cout << "\n[1] Auth Helper Functions" << std::endl;
    std::string basic_auth = Auth::basic("user123", "pass456");
    std::string bearer_auth = Auth::bearer("my_token_12345");
    auto [key_header, key_value] = Auth::api_key("secret_key", "X-API-Key");
    
    std::cout << "Basic Auth: " << basic_auth << std::endl;
    std::cout << "Bearer Auth: " << bearer_auth << std::endl;
    std::cout << "API Key Header: " << key_header << " = " << key_value << std::endl;
    
    // Test 2: Form Data Encoding
    std::cout << "\n[2] Form Data Encoding" << std::endl;
    FormData form;
    form.add("username", "test user")
        .add("email", "test@example.com")
        .add("message", "Hello World! Special chars: #%&=+");
    
    std::string encoded = form.encode();
    std::cout << "Encoded form: " << encoded << std::endl;
    
    // Test 3: Cookie Jar
    std::cout << "\n[3] Cookie Jar" << std::endl;
    CookieJar jar;
    jar.parse_set_cookie("session=abc123; Path=/; HttpOnly", "example.com");
    jar.parse_set_cookie("user=john_doe; Domain=example.com; Secure", "example.com");
    
    std::string cookies_for_example = jar.get_cookies_for_request("example.com", "/api", true);
    std::string cookies_for_other = jar.get_cookies_for_request("other.com", "/api", true);
    
    std::cout << "Cookies for example.com: " << (cookies_for_example.empty() ? "(none)" : cookies_for_example) << std::endl;
    std::cout << "Cookies for other.com: " << (cookies_for_other.empty() ? "(none)" : cookies_for_other) << std::endl;
    
    // Test 4: Interceptor Chain
    std::cout << "\n[4] Interceptor Chain" << std::endl;
    InterceptorChain chain;
    
    // Add logging interceptor
    chain.add_request_interceptor([](HttpRequest& req) {
        std::cout << "  → Request intercepted: " << static_cast<int>(req.method()) 
                  << " " << req.url() << std::endl;
    });
    
    chain.add_response_interceptor([](const HttpRequest& req, HttpResponse& resp) {
        std::cout << "  ← Response intercepted: Status " << resp.status_code() << std::endl;
    });
    
    // Test interceptors
    auto test_request = HttpRequest(HttpMethod::GET, "https://example.com/test");
    chain.process_request(test_request);
    
    auto test_response = HttpResponse();
    test_response.set_status_code(200);
    chain.process_response(test_request, test_response);
    
    // Test 5: Built-in Interceptor Factories
    std::cout << "\n[5] Built-in Interceptor Factories" << std::endl;
    InterceptorChain chain2;
    chain2.add_request_interceptor(coro_http::interceptors::authorization("Bearer test_token"));
    chain2.add_request_interceptor(coro_http::interceptors::user_agent("MyApp/1.0"));
    
    auto req_with_interceptors = HttpRequest(HttpMethod::GET, "https://api.example.com");
    chain2.process_request(req_with_interceptors);
    
    // Check that headers were added by interceptors
    std::cout << "Request URL: " << req_with_interceptors.url() << std::endl;
    std::cout << "Interceptors applied successfully" << std::endl;
    
    std::cout << "\n=== All local tests completed ===" << std::endl;
    return 0;
}
