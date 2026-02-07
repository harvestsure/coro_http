#include <coro_http/coro_http.hpp>
#include <iostream>
#include <asio.hpp>

asio::awaitable<void> async_main(coro_http::CoroHttpClient& client) {
    try {
        std::cout << "=== Coroutine HTTP GET ===" << "\n";
        auto get_resp = co_await client.co_get("http://httpbin.org/get");
        std::cout << "Status: " << get_resp.status_code() << "\n";
        std::cout << "Body: " << get_resp.body().substr(0, 100) << "...\n\n";

        std::cout << "=== Coroutine HTTPS GET ===" << "\n";
        auto https_resp = co_await client.co_get("https://httpbin.org/get");
        std::cout << "Status: " << https_resp.status_code() << "\n\n";

        std::cout << "=== Coroutine POST ===" << "\n";
        auto post_resp = co_await client.co_post(
            "https://httpbin.org/post",
            R"({"name":"async_test","value":456})"
        );
        std::cout << "Status: " << post_resp.status_code() << "\n\n";

        std::cout << "=== Coroutine PUT ===" << "\n";
        auto put_resp = co_await client.co_put(
            "https://httpbin.org/put",
            R"({"updated":true})"
        );
        std::cout << "Status: " << put_resp.status_code() << "\n\n";

        std::cout << "=== Coroutine DELETE ===" << "\n";
        auto del_resp = co_await client.co_delete("https://httpbin.org/delete");
        std::cout << "Status: " << del_resp.status_code() << "\n\n";

        std::cout << "=== Coroutine PATCH ===" << "\n";
        auto patch_resp = co_await client.co_patch(
            "https://httpbin.org/patch",
            R"({"patched":true})"
        );
        std::cout << "Status: " << patch_resp.status_code() << "\n\n";

        std::cout << "=== Coroutine HEAD ===" << "\n";
        auto head_resp = co_await client.co_head("https://httpbin.org/get");
        std::cout << "Status: " << head_resp.status_code() << "\n\n";

        std::cout << "=== Coroutine OPTIONS ===" << "\n";
        auto options_resp = co_await client.co_options("https://httpbin.org/get");
        std::cout << "Status: " << options_resp.status_code() << "\n\n";

        std::cout << "=== Custom Coroutine Request ===" << "\n";
        coro_http::HttpRequest custom_req(coro_http::HttpMethod::GET, "https://httpbin.org/headers");
        custom_req.add_header("X-Async-Header", "AsyncValue")
                  .add_header("User-Agent", "CoroHttpClient/1.0");
        auto custom_resp = co_await client.co_execute(custom_req);
        std::cout << "Status: " << custom_resp.status_code() << "\n";
        std::cout << "Body: " << custom_resp.body().substr(0, 150) << "...\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

int main() {
    asio::io_context io_ctx;
    coro_http::CoroHttpClient client(io_ctx);
    client.run([&]() -> asio::awaitable<void> {
        co_await async_main(client);
    });
    return 0;
}
