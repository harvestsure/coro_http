#pragma once

#include "http_request.hpp"
#include "http_response.hpp"
#include "url_parser.hpp"
#include "http_parser.hpp"
#include "client_config.hpp"
#include "proxy_handler.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <system_error>
#include <memory>
#include <sstream>

namespace coro_http {

class HttpClient {
public:
    HttpClient() : HttpClient(ClientConfig{}) {}
    
    explicit HttpClient(const ClientConfig& config) 
        : io_context_(), 
          ssl_context_(asio::ssl::context::tlsv12_client),
          config_(config),
          proxy_info_(parse_proxy_url(config.proxy_url)) {
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

    HttpResponse execute(const HttpRequest& request) {
        return execute_with_redirects(request, 0);
    }

private:
    HttpResponse execute_with_redirects(const HttpRequest& request, int redirect_count) {
        auto url_info = parse_url(request.url());
        
        HttpResponse response;
        if (url_info.is_https) {
            response = execute_https(request, url_info);
        } else {
            response = execute_http(request, url_info);
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
                
                auto redirect_resp = execute_with_redirects(redirect_req, redirect_count + 1);
                for (const auto& url : response.redirect_chain()) {
                    redirect_resp.add_redirect(url);
                }
                return redirect_resp;
            }
        }
        
        return response;
    }

    HttpResponse execute_http(const HttpRequest& request, const UrlInfo& url_info) {
        asio::ip::tcp::socket socket(io_context_);
        connect_socket(socket, url_info);
        
        std::string request_str;
        if (proxy_info_.type == ProxyType::HTTP) {
            request_str = build_proxy_request(request, url_info, config_.enable_compression);
        } else {
            request_str = build_request(request, url_info, config_.enable_compression);
        }
        
        asio::write(socket, asio::buffer(request_str));
        std::string response_data = read_with_timeout(socket);
        
        return parse_response(response_data);
    }

    HttpResponse execute_https(const HttpRequest& request, const UrlInfo& url_info) {
        asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(io_context_, ssl_context_);
        
        if (proxy_info_.type != ProxyType::NONE) {
            connect_socket(ssl_socket.next_layer(), url_info);
            establish_tunnel(ssl_socket.next_layer(), url_info);
        } else {
            connect_socket(ssl_socket.next_layer(), url_info);
        }
        
        if (config_.verify_ssl) {
            SSL_set_tlsext_host_name(ssl_socket.native_handle(), url_info.host.c_str());
        }
        
        ssl_socket.handshake(asio::ssl::stream_base::client);
        
        std::string request_str = build_request(request, url_info, config_.enable_compression);
        asio::write(ssl_socket, asio::buffer(request_str));
        
        std::string response_data = read_with_timeout(ssl_socket);
        
        return parse_response(response_data);
    }

    void connect_socket(asio::ip::tcp::socket& socket, const UrlInfo& url_info) {
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
        
        auto endpoints = resolver.resolve(connect_host, connect_port);
        
        asio::steady_timer timer(io_context_);
        timer.expires_after(config_.connect_timeout);
        bool timeout_occurred = false;
        
        timer.async_wait([&](const std::error_code& ec) {
            if (!ec) {
                timeout_occurred = true;
                socket.close();
            }
        });
        
        std::error_code connect_ec;
        asio::connect(socket, endpoints, connect_ec);
        timer.cancel();
        
        if (timeout_occurred || connect_ec == asio::error::operation_aborted) {
            throw std::runtime_error("Connection timeout");
        }
        if (connect_ec) {
            throw std::system_error(connect_ec);
        }
        
        if (proxy_info_.type == ProxyType::SOCKS5) {
            perform_socks5_handshake(socket, url_info);
        }
    }

    void establish_tunnel(asio::ip::tcp::socket& socket, const UrlInfo& url_info) {
        std::string connect_req = build_connect_request(
            url_info.host, url_info.port,
            proxy_info_.username, proxy_info_.password
        );
        
        asio::write(socket, asio::buffer(connect_req));
        
        std::array<char, 8192> buffer;
        std::error_code ec;
        size_t len = socket.read_some(asio::buffer(buffer), ec);
        
        if (ec && ec != asio::error::eof) {
            throw std::system_error(ec);
        }
        
        std::string response(buffer.data(), len);
        if (!parse_connect_response(response)) {
            throw std::runtime_error("Proxy CONNECT failed");
        }
    }

    void perform_socks5_handshake(asio::ip::tcp::socket& socket, const UrlInfo& url_info) {
        bool use_auth = !proxy_info_.username.empty();
        std::string handshake = build_socks5_handshake(use_auth);
        asio::write(socket, asio::buffer(handshake));
        
        std::array<char, 2> response1;
        asio::read(socket, asio::buffer(response1));
        
        if (response1[0] != 0x05) {
            throw std::runtime_error("Invalid SOCKS5 response");
        }
        
        if (response1[1] == 0x02) {
            std::string auth = build_socks5_auth(proxy_info_.username, proxy_info_.password);
            asio::write(socket, asio::buffer(auth));
            
            std::array<char, 2> auth_response;
            asio::read(socket, asio::buffer(auth_response));
            
            if (auth_response[1] != 0x00) {
                throw std::runtime_error("SOCKS5 authentication failed");
            }
        } else if (response1[1] != 0x00) {
            throw std::runtime_error("SOCKS5 method not accepted");
        }
        
        std::string connect_req = build_socks5_connect(url_info.host, url_info.port);
        asio::write(socket, asio::buffer(connect_req));
        
        std::array<char, 10> connect_response;
        asio::read(socket, asio::buffer(connect_response));
        
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

    template<typename SyncReadStream>
    std::string read_with_timeout(SyncReadStream& stream) {
        std::string response_data;
        std::array<char, 8192> buffer;
        
        asio::steady_timer timer(io_context_);
        timer.expires_after(config_.read_timeout);
        bool timeout_occurred = false;
        
        timer.async_wait([&](const std::error_code& ec) {
            if (!ec) {
                timeout_occurred = true;
                std::error_code close_ec;
                stream.lowest_layer().close(close_ec);
            }
        });
        
        std::error_code ec;
        while (true) {
            size_t len = stream.read_some(asio::buffer(buffer), ec);
            if (len > 0) {
                response_data.append(buffer.data(), len);
            }
            
            if (ec == asio::error::eof || ec == asio::ssl::error::stream_truncated) {
                break;
            } else if (ec == asio::error::operation_aborted && timeout_occurred) {
                timer.cancel();
                throw std::runtime_error("Read timeout");
            } else if (ec) {
                timer.cancel();
                throw std::system_error(ec);
            }
        }
        
        timer.cancel();
        return response_data;
    }

public:

    HttpResponse get(const std::string& url) {
        return execute(HttpRequest(HttpMethod::GET, url));
    }

    HttpResponse post(const std::string& url, const std::string& body) {
        return execute(HttpRequest(HttpMethod::POST, url).set_body(body));
    }

    HttpResponse put(const std::string& url, const std::string& body) {
        return execute(HttpRequest(HttpMethod::PUT, url).set_body(body));
    }

    HttpResponse del(const std::string& url) {
        return execute(HttpRequest(HttpMethod::DEL, url));
    }

    HttpResponse head(const std::string& url) {
        return execute(HttpRequest(HttpMethod::HEAD, url));
    }

    HttpResponse patch(const std::string& url, const std::string& body) {
        return execute(HttpRequest(HttpMethod::PATCH, url).set_body(body));
    }

    HttpResponse options(const std::string& url) {
        return execute(HttpRequest(HttpMethod::OPTIONS, url));
    }
    
    void set_config(const ClientConfig& config) {
        config_ = config;
    }
    
    const ClientConfig& get_config() const {
        return config_;
    }

private:
    asio::io_context io_context_;
    asio::ssl::context ssl_context_;
    ClientConfig config_;
    ProxyInfo proxy_info_;
};

}