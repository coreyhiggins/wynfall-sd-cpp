// Wynfall patch (MIT, same as upstream): the request guard for a server that runs on a person's own PC.
// Upstream sd-server answers every origin with Access-Control-Allow-Origin and has no authentication, so any web
// page in any browser could drive the GPU and read the images back. This guard runs before routing and:
//   1. refuses any Host header that is not 127.0.0.1:<port> or localhost:<port> (DNS rebinding),
//   2. refuses any request that carries an Origin header (a browser page; Wynfall Desktop never sends one),
//   3. answers no Access-Control-* headers and refuses OPTIONS with 405 (no CORS preflight can succeed),
//   4. requires "Authorization: Bearer <key>" on every route, compared in constant time.
#pragma once

#include <cctype>
#include <string>

#include "httplib.h"

namespace wynfall {

inline bool constant_time_equal(const std::string& a, const std::string& b) {
    const size_t n = a.size() > b.size() ? a.size() : b.size();
    unsigned char diff = a.size() == b.size() ? 0 : 1;
    for (size_t i = 0; i < n; i++) {
        const unsigned char x = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char y = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= static_cast<unsigned char>(x ^ y);
    }
    return diff == 0;
}

inline std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

inline bool host_allowed(const std::string& host_header, int port) {
    const std::string h = lower(host_header);
    const std::string p = ":" + std::to_string(port);
    return h == "127.0.0.1" + p || h == "localhost" + p;
}

inline bool is_loopback_ip(const std::string& ip) {
    return ip == "127.0.0.1" || ip == "localhost";
}

// Returns Handled (with the response filled in) when the request must not reach a route.
inline httplib::Server::HandlerResponse guard(const httplib::Request& req, httplib::Response& res, const std::string& key, int port) {
    auto deny = [&](int status, const char* text) {
        res.status = status;
        res.set_content(text, "text/plain");
        return httplib::Server::HandlerResponse::Handled;
    };
    if (!host_allowed(req.get_header_value("Host"), port)) return deny(403, "bad host");
    if (req.has_header("Origin")) return deny(403, "browser requests are not accepted");
    if (req.method == "OPTIONS") return deny(405, "no preflight");
    if (!constant_time_equal(req.get_header_value("Authorization"), "Bearer " + key)) {
        res.set_header("WWW-Authenticate", "Bearer");
        return deny(401, "unauthorized");
    }
    return httplib::Server::HandlerResponse::Unhandled;
}

}  // namespace wynfall
