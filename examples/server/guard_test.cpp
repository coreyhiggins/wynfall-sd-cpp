// Wynfall patch: runs the real guard behind a real HTTP server on an ephemeral loopback port and attacks it the way a
// web page or a rebinding site would. Exit code 0 means every check held. No model is loaded.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

#include "httplib.h"
#include "wynfall_guard.h"

static int failures = 0;
#define CHECK(cond, what)                                              \
    do {                                                               \
        if (!(cond)) { std::printf("FAIL %s\n", what); failures++; }   \
        else std::printf("ok   %s\n", what);                           \
    } while (0)

// A fresh connection per request, retried: the guard answers before it reads the body, which can reset a reused
// connection. A reset is neither a pass nor a fail by itself, so each check waits for a real response.
template <typename F>
static httplib::Result attempt(int port, F f) {
    httplib::Result r(nullptr, httplib::Error::Unknown);
    for (int i = 0; i < 6 && !r; i++) {
        if (i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        httplib::Client c("127.0.0.1", port);
        r = f(c);
    }
    return r;
}
static httplib::Result do_get(int port, const std::string& path) {
    return attempt(port, [&](httplib::Client& c) { return c.Get(path); });
}
static httplib::Result do_post(int port, const std::string& path, const httplib::Headers& h, const std::string& body) {
    return attempt(port, [&](httplib::Client& c) { return c.Post(path, h, body, "application/json"); });
}
static httplib::Result do_options(int port, const std::string& path, const httplib::Headers& h) {
    return attempt(port, [&](httplib::Client& c) { return c.Options(path, h); });
}

int main() {
    const std::string key = "test-key-0123456789abcdef";
    httplib::Server svr;
    int port = svr.bind_to_any_port("127.0.0.1");
    svr.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) { return wynfall::guard(req, res, key, port); });
    svr.Post("/v1/images/generations", [](const httplib::Request&, httplib::Response& res) { res.set_content("{\"data\":[{\"b64_json\":\"SECRET\"}]}", "application/json"); });
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) { res.set_content("index", "text/plain"); });
    std::thread t([&] { svr.listen_after_bind(); });
    svr.wait_until_ready();

    const std::string body = "{\"prompt\":\"x\"}";
    const std::string route = "/v1/images/generations";
    const httplib::Headers auth = {{"Authorization", "Bearer " + key}};

    auto r = do_post(port, route, {}, body);
    CHECK(r && r->status == 401, "no key -> 401");
    CHECK(r && r->body.find("SECRET") == std::string::npos, "no key -> no image bytes");
    r = do_post(port, route, {{"Authorization", "Bearer wrong"}}, body);
    CHECK(r && r->status == 401, "wrong key -> 401");
    r = do_get(port, "/");
    CHECK(r && r->status == 401, "index also needs the key");

    r = do_post(port, route, {{"Origin", "https://evil.example"}}, body);
    CHECK(r && r->status != 200 && !r->has_header("Access-Control-Allow-Origin"), "evil Origin without key: no ACAO");
    r = do_post(port, route, {{"Origin", "https://evil.example"}, {"Authorization", "Bearer " + key}}, body);
    CHECK(r && r->status == 403 && !r->has_header("Access-Control-Allow-Origin"), "evil Origin even with the key: 403, no ACAO");

    r = do_options(port, route, {{"Origin", "https://evil.example"}, {"Access-Control-Request-Method", "POST"}, {"Access-Control-Request-Headers", "authorization"}});
    CHECK(r && r->status != 204 && r->status != 200 && !r->has_header("Access-Control-Allow-Origin") && !r->has_header("Access-Control-Allow-Headers"), "preflight gets no CORS grant");

    r = do_post(port, route, {{"Host", "attacker.example"}, {"Authorization", "Bearer " + key}}, body);
    CHECK(r && r->status == 403, "Host attacker.example with the key -> 403");
    r = do_post(port, route, {{"Host", "attacker.example:" + std::to_string(port)}, {"Authorization", "Bearer " + key}}, body);
    CHECK(r && r->status == 403, "rebinding Host with the right port -> 403");

    r = do_post(port, route, auth, body);
    CHECK(r && r->status == 200 && r->body.find("SECRET") != std::string::npos, "right key, right host -> 200");
    CHECK(r && !r->has_header("Access-Control-Allow-Origin") && !r->has_header("Access-Control-Allow-Credentials"), "no CORS headers on success");
    CHECK(wynfall::constant_time_equal("abc", "abc") && !wynfall::constant_time_equal("abc", "abd") && !wynfall::constant_time_equal("abc", "ab"), "constant_time_equal");
    CHECK(wynfall::is_loopback_ip("127.0.0.1") && !wynfall::is_loopback_ip("0.0.0.0") && !wynfall::is_loopback_ip("192.168.1.5"), "bind check");

    svr.stop();
    t.join();
    std::printf(failures ? "FAILED %d\n" : "all guard checks held\n", failures);
    return failures ? 1 : 0;
}
