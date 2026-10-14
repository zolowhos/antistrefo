// re_mcp_side.cpp - local MCP transport hosted beside the GUI TUI.
// Module: mcp (C++17).
// Owns: listen thread, accept loop, and stdio attach bridge for agents.
// Depends: re_mcp.h, re_mcp_side.h, re_str. Frames stay on the side channel only.
#include "mcp/re_mcp_side.h"

#include "utils/text/re_str.h"
#include "mcp/re_mcp.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <fcntl.h>
#    include <io.h>
#    include <winsock2.h>
#    include <ws2tcpip.h>
using sock_t = SOCKET;
constexpr sock_t kInvalid = INVALID_SOCKET;
#else
#    include <unistd.h>
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <sys/socket.h>
#    include <sys/un.h>
using sock_t = int;
constexpr sock_t kInvalid = -1;
#endif

namespace {

constexpr size_t kEpMax = 256;
std::atomic<bool> g_run{false};
std::thread g_thread;
sock_t g_listen = kInvalid;
char g_endpoint[kEpMax];
#if !defined(_WIN32)
char g_unix_path[108];
#endif

void sock_close(sock_t fd) {
    if (fd == kInvalid)
        return;
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
}

bool sock_init(void) {
#if defined(_WIN32)
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
#else
    return true;
#endif
}

void sock_fini(void) {
#if defined(_WIN32)
    WSACleanup();
#endif
}

void copy_ep(char *dst, size_t cap, const char *src) {
    size_t n = 0;
    if (!dst || !cap)
        return;
    if (!src)
        src = "";
    while (src[n] && n + 1u < cap) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

std::string path_file(void) {
#if defined(_WIN32)
    const char *home = std::getenv("TEMP");
    if (!home)
        home = ".";
    return std::string(home) + "\\antistrefo-mcp.path";
#else
    const char *home = std::getenv("TMPDIR");
    if (!home)
        home = "/tmp";
    return std::string(home) + "/antistrefo-mcp.path";
#endif
}

void write_path_file(const char *endpoint) {
    FILE *f = std::fopen(path_file().c_str(), "wb");
    re_str_t ep = re_str(endpoint);
    if (!f)
        return;
    std::fwrite(endpoint, 1, ep.n, f);
    std::fputc('\n', f);
    std::fclose(f);
}

std::string read_path_file(void) {
    FILE *f = std::fopen(path_file().c_str(), "rb");
    char buf[kEpMax];
    size_t n;
    if (!f)
        return {};
    n = std::fread(buf, 1, sizeof(buf) - 1u, f);
    std::fclose(f);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        n--;
    buf[n] = '\0';
    return std::string(buf);
}

sock_t listen_tcp(char *endpoint, size_t cap) {
    sock_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    socklen_t alen = sizeof(addr);
    if (fd == kInvalid)
        return kInvalid;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 4) != 0) {
        sock_close(fd);
        return kInvalid;
    }
    if (getsockname(fd, (sockaddr *)&addr, &alen) != 0) {
        sock_close(fd);
        return kInvalid;
    }
    std::snprintf(endpoint, cap, "tcp:127.0.0.1:%u", (unsigned)ntohs(addr.sin_port));
    return fd;
}

#if !defined(_WIN32)
sock_t listen_unix(char *endpoint, size_t cap) {
    sock_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    if (fd == kInvalid)
        return kInvalid;
    addr.sun_family = AF_UNIX;
    std::snprintf(g_unix_path, sizeof(g_unix_path), "/tmp/antistrefo-mcp-%d.sock", (int)getpid());
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_unix_path);
    unlink(g_unix_path);
    if (bind(fd, (sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 4) != 0) {
        sock_close(fd);
        g_unix_path[0] = '\0';
        return kInvalid;
    }
    std::snprintf(endpoint, cap, "unix:%s", g_unix_path);
    return fd;
}
#endif

sock_t connect_tcp(const char *rest) {
    unsigned a = 0, b = 0, c = 0, d = 0, port = 0;
    sock_t fd;
    sockaddr_in addr{};
    if (std::sscanf(rest, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) != 5)
        return kInvalid;
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kInvalid)
        return kInvalid;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) != 0) {
        sock_close(fd);
        return kInvalid;
    }
    return fd;
}

#if !defined(_WIN32)
sock_t connect_unix(const char *path) {
    sock_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    if (fd == kInvalid)
        return kInvalid;
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) != 0) {
        sock_close(fd);
        return kInvalid;
    }
    return fd;
}
#endif

sock_t connect_endpoint(const char *endpoint) {
    re_str_t ep = re_str(endpoint);
    if (!ep.n)
        return kInvalid;
    if (re_str_starts_cstr(ep, "tcp:"))
        return connect_tcp(endpoint + 4);
#if !defined(_WIN32)
    if (re_str_starts_cstr(ep, "unix:"))
        return connect_unix(endpoint + 5);
#endif
    return kInvalid;
}

void serve_client(sock_t cfd) {
#if defined(_WIN32)
    int raw = _open_osfhandle((intptr_t)cfd, _O_RDWR | _O_BINARY);
    if (raw < 0) {
        sock_close(cfd);
        return;
    }
    int out_raw = _dup(raw);
    FILE *in = _fdopen(raw, "rb");
    FILE *out = out_raw >= 0 ? _fdopen(out_raw, "wb") : nullptr;
    if (!in || !out) {
        if (in)
            std::fclose(in);
        if (out)
            std::fclose(out);
        else {
            if (out_raw >= 0)
                _close(out_raw);
            _close(raw);
        }
        return;
    }
#else
    int out_fd = dup((int)cfd);
    FILE *in = fdopen((int)cfd, "r");
    FILE *out = out_fd >= 0 ? fdopen(out_fd, "w") : nullptr;
    if (!in || !out) {
        if (in)
            std::fclose(in);
        else
            sock_close(cfd);
        if (out)
            std::fclose(out);
        else if (out_fd >= 0)
            close(out_fd);
        return;
    }
#endif
    re_mcp_serve_files(in, out);
    std::fclose(in);
    std::fclose(out);
}

void accept_loop(void) {
    while (g_run.load()) {
        sock_t cfd = accept(g_listen, nullptr, nullptr);
        if (cfd == kInvalid) {
            if (!g_run.load())
                break;
            continue;
        }
        // A stop poke connects once with g_run already false; drop it.
        if (!g_run.load()) {
            sock_close(cfd);
            break;
        }
        std::thread(serve_client, cfd).detach();
    }
}

std::string resolve_endpoint(const char *endpoint) {
    if (endpoint && endpoint[0])
        return endpoint;
    if (const char *env = std::getenv("ANTISTREFO_MCP"))
        return env;
    return read_path_file();
}

int relay_stdio(sock_t fd) {
    std::thread up([fd]() {
        char buf[4096];
        size_t got;
        while ((got = std::fread(buf, 1, sizeof(buf), stdin)) > 0) {
#if defined(_WIN32)
            if (send(fd, buf, (int)got, 0) <= 0)
                break;
#else
            if (send(fd, buf, got, 0) <= 0)
                break;
#endif
        }
#if defined(_WIN32)
        shutdown(fd, SD_SEND);
#else
        shutdown(fd, SHUT_WR);
#endif
    });
    char buf[4096];
#if defined(_WIN32)
    int n;
    while ((n = recv(fd, buf, (int)sizeof(buf), 0)) > 0) {
        if (std::fwrite(buf, 1, (size_t)n, stdout) != (size_t)n)
            break;
        std::fflush(stdout);
    }
#else
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
        if (std::fwrite(buf, 1, (size_t)n, stdout) != (size_t)n)
            break;
        std::fflush(stdout);
    }
#endif
    if (up.joinable())
        up.join();
    return 0;
}

} // namespace

bool re_mcp_side_start(char *endpoint, size_t cap) {
    if (g_run.load()) {
        copy_ep(endpoint, cap, g_endpoint);
        return g_endpoint[0] != '\0';
    }
    if (!sock_init())
        return false;
#if !defined(_WIN32)
    g_unix_path[0] = '\0';
    g_listen = listen_unix(g_endpoint, sizeof(g_endpoint));
    if (g_listen == kInvalid)
#endif
        g_listen = listen_tcp(g_endpoint, sizeof(g_endpoint));
    if (g_listen == kInvalid) {
        sock_fini();
        return false;
    }
    write_path_file(g_endpoint);
    copy_ep(endpoint, cap, g_endpoint);
    g_run.store(true);
    g_thread = std::thread(accept_loop);
    return true;
}

void re_mcp_side_stop(void) {
    char ep[kEpMax];
    if (!g_run.exchange(false))
        return;
    // Closing the listen socket alone does not always wake accept on every
    // host; a local connect unblocks the thread so join cannot hang the GUI.
    copy_ep(ep, sizeof(ep), g_endpoint);
    if (ep[0]) {
        sock_t poke = connect_endpoint(ep);
        sock_close(poke);
    }
    sock_close(g_listen);
    g_listen = kInvalid;
    if (g_thread.joinable())
        g_thread.join();
#if !defined(_WIN32)
    if (g_unix_path[0])
        unlink(g_unix_path);
    g_unix_path[0] = '\0';
#endif
    g_endpoint[0] = '\0';
    sock_fini();
}

int re_mcp_attach_main(const char *endpoint) {
    std::string ep;
    sock_t fd;
    int rc;
    if (!sock_init())
        return 6;
    ep = resolve_endpoint(endpoint);
    if (ep.empty()) {
        std::fprintf(stderr, "mcp --attach needs an endpoint, ANTISTREFO_MCP, or a running gui\n");
        sock_fini();
        return 2;
    }
    fd = connect_endpoint(ep.c_str());
    if (fd == kInvalid) {
        std::fprintf(stderr, "mcp --attach could not connect to %s\n", ep.c_str());
        sock_fini();
        return 6;
    }
    rc = relay_stdio(fd);
    sock_close(fd);
    sock_fini();
    return rc;
}
