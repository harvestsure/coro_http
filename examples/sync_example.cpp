#include <coro_http/coro_http.hpp>
#include <iostream>
#include <asio.hpp>

int main() {
    try {
        asio::io_context io_ctx;
        coro_http::HttpClient client(io_ctx);

        std::cout << "=== HTTP GET ==="  << "\n";
        auto get_resp = client.get("http://httpbin.org/get");
        std::cout << "Status: " << get_resp.status_code() << "\n";
        std::cout << "Body: " << get_resp.body().substr(0, 100) << "...\n\n";

        std::cout << "=== HTTPS GET ===" << "\n";
        auto https_resp = client.get("https://httpbin.org/get");
        std::cout << "Status: " << https_resp.status_code() << "\n\n";

        std::cout << "=== POST ===" << "\n";
        auto post_resp = client.post(
            "https://httpbin.org/post",
            R"({"name":"test","value":123})"
        );
        std::cout << "Status: " << post_resp.status_code() << "\n\n";

        std::cout << "=== PUT ===" << "\n";
        auto put_resp = client.put(
            "https://httpbin.org/put",
            R"({"updated":true})"
        );
        std::cout << "Status: " << put_resp.status_code() << "\n\n";

        std::cout << "=== DELETE ===" << "\n";
        auto del_resp = client.del("https://httpbin.org/delete");
        std::cout << "Status: " << del_resp.status_code() << "\n\n";

        std::cout << "=== PATCH ===" << "\n";
        auto patch_resp = client.patch(
            "https://httpbin.org/patch",
            R"({"patched":true})"
        );
        std::cout << "Status: " << patch_resp.status_code() << "\n\n";

        std::cout << "=== HEAD ===" << "\n";
        auto head_resp = client.head("https://httpbin.org/get");
        std::cout << "Status: " << head_resp.status_code() << "\n";
        std::cout << "Body Length: " << head_resp.body().length() << "\n\n";

        std::cout << "=== OPTIONS ===" << "\n";
        auto options_resp = client.options("https://httpbin.org/get");
        std::cout << "Status: " << options_resp.status_code() << "\n\n";

        std::cout << "=== Custom Request ===" << "\n";
        coro_http::HttpRequest custom_req(coro_http::HttpMethod::GET, "https://httpbin.org/headers");
        custom_req.add_header("X-Custom-Header", "CustomValue")
                  .add_header("User-Agent", "CoroHttpClient/1.0");
        auto custom_resp = client.execute(custom_req);
        std::cout << "Status: " << custom_resp.status_code() << "\n";
        std::cout << "Body: " << custom_resp.body().substr(0, 150) << "...\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
