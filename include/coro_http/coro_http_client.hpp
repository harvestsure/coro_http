#pragma once

#include "http_request.hpp"
#include "http_response.hpp"
#include "url_parser.hpp"
#include "http_parser.hpp"
#include "client_config.hpp"
#include "proxy_handler.hpp"
#include "connection_pool.hpp"
#include "rate_limiter.hpp"
#include "retry_policy.hpp"
#include "cookie_jar.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <sstream>
#include <type_traits>

namespace coro_http {

class CoroHttpClient {
public:
    explicit CoroHttpClient(asio::io_context& io_context)
        : CoroHttpClient(io_context, ClientConfig{}) {}
    
    CoroHttpClient(asio::io_context& io_context, const ClientConfig& config)
        : io_context_(io_context), 
          ssl_context_(asio::ssl::context::tlsv12_client),
          config_(config),
          proxy_info_(parse_proxy_url(config.proxy_url)),
          connection_pool_(config.max_connections_per_host, config.connection_idle_timeout),
          rate_limiter_(config.enable_rate_limit ? config.rate_limit_requests : 0, config.rate_limit_window),
          retry_policy_(config.max_retries,
                       config.initial_retry_delay,
                       config.retry_backoff_factor,
                       config.max_retry_delay,
                       config.retry_on_timeout,
                       config.retry_on_connection_error,
                       config.retry_on_5xx) {
        ssl_context_.set_default_verify_paths();
        
        if (config_.verify_ssl) {
            ssl_context_.set_verify_mode(asio::ssl::verify_peer);
            if (!config_.ca_cert_file.empty()) {
                ssl_context_.load_verify_file(config_.ca_cert_file);
            }
            if (!config_.ca_cert_path.empty()) {
                ssl_context_.add_verify_path(config_.ca_cert_path);
            }
        } else {
            ssl_context_.set_verify_mode(asio::ssl::verify_none);
        }
        
        if (!config_.proxy_username.empty()) {
            proxy_info_.username = config_.proxy_username;
            proxy_info_.password = config_.proxy_password;
        }
    }

    asio::awaitable<HttpResponse> co_execute(const HttpRequest& request) {
        if (!config_.enable_retry) {
            co_return co_await co_execute_with_redirects(request, 0);
        }
        
        // Retry logic with exponential backoff
        retry_policy_.reset();
        
        while (true) {
            std::exception_ptr eptr;
            HttpResponse response;
            bool success = false;
            bool should_retry_on_status = false;
            bool should_retry_on_error = false;
            std::chrono::milliseconds delay{0};
            
            // Try to execute request
            try {
                response = co_await co_execute_with_redirects(request, 0);
                success = true;
                
                // Check if we should retry based on status code  
                if (retry_policy_.current_attempt() < retry_policy_.max_retries() &&
                    config_.retry_on_5xx && 
                    response.status_code() >= 500 && 
                    response.status_code() < 600) {
                    should_retry_on_status = true;
                    retry_policy_.increment_attempt();
                    delay = retry_policy_.get_delay();
                }
            } catch (...) {
                eptr = std::current_exception();
            }
            
            // If successful and no retry needed, return response
            if (success && !should_retry_on_status) {
                co_return response;
            }
            
            // Handle retry on status code
            if (should_retry_on_status) {
                asio::steady_timer timer(io_context_);
                timer.expires_after(delay);
                co_await timer.async_wait(asio::use_awaitable);
                continue;
            }
            
            // Handle exception - check if should retry
            if (eptr) {
                try {
                    std::rethrow_exception(eptr);
                } catch (const std::exception& e) {
                    if (config_.enable_retry && retry_policy_.should_retry(e, 0)) {
                        should_retry_on_error = true;
                        retry_policy_.increment_attempt();
                        delay = retry_policy_.get_delay();
                    } else {
                        throw;  // No more retries
                    }
                }
                
                if (should_retry_on_error) {
                    asio::steady_timer timer(io_context_);
                    timer.expires_after(delay);
                    co_await timer.async_wait(asio::use_awaitable);
                    continue;
                }
            }
        }
    }

private:
    asio::awaitable<HttpResponse> co_execute_with_redirects(const HttpRequest& request, int redirect_count) {
        auto url_info = parse_url(request.url());
        
        // Add cookies to request if enabled
        HttpRequest req_with_cookies = request;
        if (config_.enable_cookies) {
            std::string cookies = cookie_jar_.get_cookies_for_request(
                url_info.host, url_info.path, url_info.is_https);
            if (!cookies.empty()) {
                req_with_cookies.add_header("Cookie", cookies);
            }
        }
        
        HttpResponse response;
        if (url_info.is_https) {
            response = co_await co_execute_https(req_with_cookies, url_info);
        } else {
            response = co_await co_execute_http(req_with_cookies, url_info);
        }
        
        // Extract cookies from response if enabled
        if (config_.enable_cookies) {
            for (const auto& [key, value] : response.headers()) {
                if (strcasecmp_parser(key, "Set-Cookie")) {
                    cookie_jar_.parse_set_cookie(value, url_info.host);
                }
            }
        }
        
        if (config_.follow_redirects && 
            redirect_count < config_.max_redirects &&
            (response.status_code() >= 300 && response.status_code() < 400)) {
            
            std::string location = response.get_header("Location");
            if (!location.empty()) {
                response.add_redirect(location);
                
                if (location[0] == '/') {
                    location = url_info.scheme + "://" + url_info.host + 
                              (url_info.port != (url_info.is_https ? "443" : "80") ? ":" + url_info.port : "") + 
                              location;
                }
                
                HttpRequest redirect_req(HttpMethod::GET, location);
                for (const auto& [key, value] : request.headers()) {
                    redirect_req.add_header(key, value);
                }
                
                auto redirect_resp = co_await co_execute_with_redirects(redirect_req, redirect_count + 1);
                for (const auto& url : response.redirect_chain()) {
                    redirect_resp.add_redirect(url);
                }
                co_return redirect_resp;
            }
        }
        
        co_return response;
    }

    asio::awaitable<HttpResponse> co_execute_http(const HttpRequest& request, const UrlInfo& url_info) {
        // Apply rate limiting (synchronous for now)
        rate_limiter_.acquire();
        
        // Use connection pool if enabled
        if (config_.enable_connection_pool && proxy_info_.type == ProxyType::NONE) {
            co_return co_await co_execute_http_pooled(request, url_info);
        }
        
        // Non-pooled connection for proxy requests
        asio::ip::tcp::socket socket(io_context_);
        co_await co_connect_socket(socket, url_info);
        
        std::string request_str;
        if (proxy_info_.type == ProxyType::HTTP) {
            request_str = build_proxy_request(request, url_info, config_.enable_compression);
        } else {
            request_str = build_request(request, url_info, config_.enable_compression);
        }
        
        co_await asio::async_write(socket, asio::buffer(request_str), asio::use_awaitable);
        std::string response_data = co_await co_read_response(socket, request.method());
        
        co_return parse_response(response_data);
    }
    
    asio::awaitable<HttpResponse> co_execute_http_pooled(const HttpRequest& request, const UrlInfo& url_info) {
        auto socket = connection_pool_.get_connection(io_context_, url_info.host, url_info.port);
        
        // Check if we need to connect
        if (!socket->is_open()) {
            asio::ip::tcp::resolver resolver(io_context_);
            auto endpoints = co_await resolver.async_resolve(
                url_info.host, url_info.port, asio::use_awaitable);
            co_await asio::async_connect(*socket, endpoints, asio::use_awaitable);
        }
        
        std::string request_str = build_request(request, url_info, config_.enable_compression, true);
        
        try {
            co_await asio::async_write(*socket, asio::buffer(request_str), asio::use_awaitable);
            std::string response_data = co_await co_read_response(*socket, request.method());
            
            // Parse response and check Connection header
            auto response = parse_response(response_data);
            
            // Check if server wants to close the connection
            std::string connection_header = response.get_header("Connection");
            std::transform(connection_header.begin(), connection_header.end(), 
                         connection_header.begin(), ::tolower);
            bool should_keep_alive = (connection_header != "close");
            
            // Return connection to pool only if keep-alive
            connection_pool_.release_connection(socket, url_info.host, url_info.port, should_keep_alive);
            
            // Close socket if server requested close
            if (!should_keep_alive) {
                asio::error_code ec;
                socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
                socket->close(ec);
            }
            
            co_return response;
        } catch (...) {
            // Don't return broken connection to pool
            asio::error_code ec;
            socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            socket->close(ec);
            throw;
        }
    }

    asio::awaitable<HttpResponse> co_execute_https(const HttpRequest& request, const UrlInfo& url_info) {
        // Apply rate limiting (synchronous for now)
        rate_limiter_.acquire();
        
        // Use SSL connection pool if enabled
        if (config_.enable_connection_pool && proxy_info_.type == ProxyType::NONE) {
            co_return co_await co_execute_https_pooled(request, url_info);
        }
        
        // Non-pooled connection for proxy requests
        asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(io_context_, ssl_context_);
        
        co_await co_connect_socket(ssl_socket.next_layer(), url_info);
        
        if (proxy_info_.type != ProxyType::NONE) {
            co_await co_establish_tunnel(ssl_socket.next_layer(), url_info);
        }
        
        if (config_.verify_ssl) {
            SSL_set_tlsext_host_name(ssl_socket.native_handle(), url_info.host.c_str());
        }
        
        co_await ssl_socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);
        
        std::string request_str = build_request(request, url_info, config_.enable_compression);
        co_await asio::async_write(ssl_socket, asio::buffer(request_str), asio::use_awaitable);
        
        std::string response_data = co_await co_read_response(ssl_socket, request.method());
        
        co_return parse_response(response_data);
    }
    
    asio::awaitable<HttpResponse> co_execute_https_pooled(const HttpRequest& request, const UrlInfo& url_info) {
        auto ssl_stream = connection_pool_.get_ssl_connection(io_context_, ssl_context_, url_info.host, url_info.port);
        
        // Check if we need to connect
        if (!ssl_stream->lowest_layer().is_open()) {
            asio::ip::tcp::resolver resolver(io_context_);
            auto endpoints = co_await resolver.async_resolve(
                url_info.host, url_info.port, asio::use_awaitable);
            co_await asio::async_connect(ssl_stream->lowest_layer(), endpoints, asio::use_awaitable);
            
            if (config_.verify_ssl) {
                SSL_set_tlsext_host_name(ssl_stream->native_handle(), url_info.host.c_str());
            }
            
            co_await ssl_stream->async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);
        }
        
        std::string request_str = build_request(request, url_info, config_.enable_compression, true);
        
        try {
            co_await asio::async_write(*ssl_stream, asio::buffer(request_str), asio::use_awaitable);
            std::string response_data = co_await co_read_response(*ssl_stream, request.method());
            
            // Parse response and check Connection header
            auto response = parse_response(response_data);
            
            // Check if server wants to close the connection
            std::string connection_header = response.get_header("Connection");
            std::transform(connection_header.begin(), connection_header.end(), 
                         connection_header.begin(), ::tolower);
            bool should_keep_alive = (connection_header != "close");
            
            // Return connection to pool only if keep-alive
            connection_pool_.release_ssl_connection(ssl_stream, url_info.host, url_info.port, should_keep_alive);
            
            // Close SSL connection if server requested close
            if (!should_keep_alive) {
                asio::error_code ec;
                co_await ssl_stream->async_shutdown(asio::use_awaitable);
                ssl_stream->lowest_layer().close(ec);
            }
            
            co_return response;
        } catch (...) {
            // Don't return broken connection to pool
            asio::error_code ec;
            ssl_stream->lowest_layer().close(ec);
            throw;
        }
    }

    asio::awaitable<void> co_connect_socket(asio::ip::tcp::socket& socket, const UrlInfo& url_info) {
        asio::ip::tcp::resolver resolver(io_context_);
        
        std::string connect_host;
        std::string connect_port;
        
        if (proxy_info_.type != ProxyType::NONE) {
            connect_host = proxy_info_.host;
            connect_port = proxy_info_.port;
        } else {
            connect_host = url_info.host;
            connect_port = url_info.port;
        }
        
        auto endpoints = co_await resolver.async_resolve(
            connect_host, 
            connect_port, 
            asio::use_awaitable
        );
        
        co_await asio::async_connect(socket, endpoints, asio::use_awaitable);
        
        if (proxy_info_.type == ProxyType::SOCKS5) {
            co_await co_perform_socks5_handshake(socket, url_info);
        }
    }

    asio::awaitable<void> co_establish_tunnel(asio::ip::tcp::socket& socket, const UrlInfo& url_info) {
        std::string connect_req = build_connect_request(
            url_info.host, url_info.port,
            proxy_info_.username, proxy_info_.password
        );
        
        co_await asio::async_write(socket, asio::buffer(connect_req), asio::use_awaitable);
        
        std::array<char, 8192> buffer;
        auto [ec, len] = co_await socket.async_read_some(
            asio::buffer(buffer),
            asio::as_tuple(asio::use_awaitable)
        );
        
        if (ec && ec != asio::error::eof) {
            throw std::system_error(ec);
        }
        
        std::string response(buffer.data(), len);
        if (!parse_connect_response(response)) {
            throw std::runtime_error("Proxy CONNECT failed");
        }
    }

    asio::awaitable<void> co_perform_socks5_handshake(asio::ip::tcp::socket& socket, const UrlInfo& url_info) {
        bool use_auth = !proxy_info_.username.empty();
        std::string handshake = build_socks5_handshake(use_auth);
        co_await asio::async_write(socket, asio::buffer(handshake), asio::use_awaitable);
        
        std::array<char, 2> response1;
        co_await asio::async_read(socket, asio::buffer(response1), asio::use_awaitable);
        
        if (response1[0] != 0x05) {
            throw std::runtime_error("Invalid SOCKS5 response");
        }
        
        if (response1[1] == 0x02) {
            std::string auth = build_socks5_auth(proxy_info_.username, proxy_info_.password);
            co_await asio::async_write(socket, asio::buffer(auth), asio::use_awaitable);
            
            std::array<char, 2> auth_response;
            co_await asio::async_read(socket, asio::buffer(auth_response), asio::use_awaitable);
            
            if (auth_response[1] != 0x00) {
                throw std::runtime_error("SOCKS5 authentication failed");
            }
        } else if (response1[1] != 0x00) {
            throw std::runtime_error("SOCKS5 method not accepted");
        }
        
        std::string connect_req = build_socks5_connect(url_info.host, url_info.port);
        co_await asio::async_write(socket, asio::buffer(connect_req), asio::use_awaitable);
        
        std::array<char, 10> connect_response;
        co_await asio::async_read(socket, asio::buffer(connect_response), asio::use_awaitable);
        
        if (connect_response[1] != 0x00) {
            throw std::runtime_error("SOCKS5 connection failed");
        }
    }

    std::string build_proxy_request(const HttpRequest& request, const UrlInfo& url_info, bool enable_compression) {
        std::ostringstream req;
        
        std::string full_url = url_info.scheme + "://" + url_info.host;
        if (url_info.port != (url_info.is_https ? "443" : "80")) {
            full_url += ":" + url_info.port;
        }
        full_url += url_info.path;
        
        req << method_to_string(request.method()) << " " << full_url << " HTTP/1.1\r\n";
        req << "Host: " << url_info.host << "\r\n";
        
        bool has_accept_encoding = false;
        for (const auto& [key, value] : request.headers()) {
            req << key << ": " << value << "\r\n";
            if (strcasecmp_parser(key, "Accept-Encoding")) {
                has_accept_encoding = true;
            }
        }
        
        if (enable_compression && !has_accept_encoding) {
            req << "Accept-Encoding: gzip, deflate\r\n";
        }
        
        if (!request.body().empty()) {
            req << "Content-Length: " << request.body().size() << "\r\n";
        }
        
        req << "Connection: close\r\n";
        req << "\r\n";
        
        if (!request.body().empty()) {
            req << request.body();
        }
        
        return req.str();
    }

    template<typename AsyncReadStream>
    struct has_lowest_layer_impl {
        template<typename T>
        static auto test(int) -> decltype(std::declval<T&>().lowest_layer(), std::true_type());
        template<typename>
        static std::false_type test(...);
        using type = decltype(test<AsyncReadStream>(0));
        static constexpr bool value = type::value;
    };

    template<typename AsyncReadStreamT>
    static auto& get_underlying_layer(AsyncReadStreamT& s) {
        if constexpr (has_lowest_layer_impl<AsyncReadStreamT>::value) {
            return s.lowest_layer();
        } else {
            return s;
        }
    }

    template<typename AsyncReadStream>
    asio::awaitable<std::string> co_read_response(AsyncReadStream& stream, HttpMethod request_method = HttpMethod::GET) {
        std::string response_data;
        std::array<char, 8192> buffer;
        
        bool headers_complete = false;
        size_t content_length = 0;
        bool is_chunked = false;
        size_t headers_end_pos = 0;
        
        while (true) {
            auto [ec, len] = co_await stream.async_read_some(
                asio::buffer(buffer),
                asio::as_tuple(asio::use_awaitable)
            );
            
            if (len > 0) {
                response_data.append(buffer.data(), len);
                
                // Check if headers are complete
                if (!headers_complete) {
                    size_t header_end = response_data.find("\r\n\r\n");
                    if (header_end != std::string::npos) {
                        headers_complete = true;
                        headers_end_pos = header_end + 4;
                        
                        // Parse headers to find Content-Length or Transfer-Encoding
                        std::string headers = response_data.substr(0, headers_end_pos);
                        
                        // Check for chunked encoding
                        if (headers.find("Transfer-Encoding: chunked") != std::string::npos ||
                            headers.find("transfer-encoding: chunked") != std::string::npos) {
                            is_chunked = true;
                        }
                        
                        // Try to find Content-Length
                        size_t cl_pos = headers.find("Content-Length:");
                        if (cl_pos == std::string::npos) {
                            cl_pos = headers.find("content-length:");
                        }
                        if (cl_pos != std::string::npos) {
                            size_t value_start = headers.find(':', cl_pos) + 1;
                            size_t value_end = headers.find('\r', value_start);
                            std::string cl_str = headers.substr(value_start, value_end - value_start);
                            // Trim whitespace
                            cl_str.erase(0, cl_str.find_first_not_of(" \t"));
                            cl_str.erase(cl_str.find_last_not_of(" \t") + 1);
                            try {
                                content_length = std::stoull(cl_str);
                            } catch (...) {}
                        }
                    }
                }
                
                // Check if we have complete body
                if (headers_complete) {
                    // Per RFC, responses to HEAD must not include a message body.
                    // Don't wait for a body for HEAD requests — treat response as complete.
                    if (request_method == HttpMethod::HEAD) {
                        break;
                    }
                    size_t body_size = response_data.size() - headers_end_pos;
                    
                    if (is_chunked) {
                        // For chunked, check if we have the final chunk (0\r\n\r\n)
                        if (response_data.find("0\r\n\r\n") != std::string::npos) {
                            break;
                        }
                    } else if (content_length > 0) {
                        // For content-length, check if we have all data
                        if (body_size >= content_length) {
                            break;
                        }
                    }
                }
            }
            
            if (ec == asio::error::eof || ec == asio::ssl::error::stream_truncated) {
                break;
            } else if (ec) {
                throw std::system_error(ec);
            }
            
            // Safety: if we have headers but no content length and no chunked,
            // and we got some data, try a short wait and then check for available bytes
            if (headers_complete && !is_chunked && content_length == 0 && len > 0) {
                asio::steady_timer timer(io_context_);
                timer.expires_after(std::chrono::milliseconds(100));
                co_await timer.async_wait(asio::use_awaitable);

                // Determine underlying layer (socket) to query available bytes.
                // Works for both plain sockets and ssl streams.
                int available_bytes = 0;
                try {
                    if constexpr (has_lowest_layer_impl<AsyncReadStream>::value) {
                        available_bytes = static_cast<int>(get_underlying_layer(stream).available());
                    } else {
                        available_bytes = static_cast<int>(stream.available());
                    }
                } catch (...) {
                    available_bytes = 0;
                }

                if (available_bytes > 0) {
                    auto [peek_ec, peek_len] = co_await stream.async_read_some(
                        asio::buffer(buffer),
                        asio::as_tuple(asio::use_awaitable)
                    );

                    if (peek_len > 0) {
                        response_data.append(buffer.data(), peek_len);
                    }
                } else {
                    // No more data, response complete
                    break;
                }
            }
        }
        
        co_return response_data;
    }

public:

    asio::awaitable<HttpResponse> co_get(const std::string& url) {
        co_return co_await co_execute(HttpRequest(HttpMethod::GET, url));
    }

    asio::awaitable<HttpResponse> co_post(const std::string& url, const std::string& body) {
        co_return co_await co_execute(HttpRequest(HttpMethod::POST, url).set_body(body));
    }

    asio::awaitable<HttpResponse> co_put(const std::string& url, const std::string& body) {
        co_return co_await co_execute(HttpRequest(HttpMethod::PUT, url).set_body(body));
    }

    asio::awaitable<HttpResponse> co_delete(const std::string& url) {
        co_return co_await co_execute(HttpRequest(HttpMethod::DEL, url));
    }

    asio::awaitable<HttpResponse> co_head(const std::string& url) {
        co_return co_await co_execute(HttpRequest(HttpMethod::HEAD, url));
    }

    asio::awaitable<HttpResponse> co_patch(const std::string& url, const std::string& body) {
        co_return co_await co_execute(HttpRequest(HttpMethod::PATCH, url).set_body(body));
    }

    asio::awaitable<HttpResponse> co_options(const std::string& url) {
        co_return co_await co_execute(HttpRequest(HttpMethod::OPTIONS, url));
    }

    template<typename CoroFunc>
    void run(CoroFunc&& coro) {
        asio::co_spawn(io_context_, std::forward<CoroFunc>(coro), asio::detached);
        io_context_.run();
    }
    
    void set_config(const ClientConfig& config) {
        config_ = config;
    }
    
    const ClientConfig& get_config() const {
        return config_;
    }
    
    // Get connection pool statistics
    ConnectionPool::Stats get_pool_stats() const {
        return connection_pool_.get_stats();
    }
    
    // Clear connection pool
    void clear_connection_pool() {
        connection_pool_.clear();
    }
    
    // Get rate limiter remaining capacity
    int get_rate_limit_remaining() const {
        return rate_limiter_.remaining();
    }
    
    // Reset rate limiter
    void reset_rate_limiter() {
        rate_limiter_.reset();
    }
    
    // Get cookie jar
    CookieJar& cookies() {
        return cookie_jar_;
    }
    
    // Get cookie jar (const)
    const CookieJar& cookies() const {
        return cookie_jar_;
    }

private:
    asio::io_context& io_context_;
    asio::ssl::context ssl_context_;
    ClientConfig config_;
    ProxyInfo proxy_info_;
    ConnectionPool connection_pool_;
    RateLimiter rate_limiter_;
    RetryPolicy retry_policy_;
    CookieJar cookie_jar_;
};

}
