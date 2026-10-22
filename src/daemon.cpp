#include "saslik/licensing.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace fs = std::filesystem;
using saslik::licensing::Store;
namespace {
std::atomic_bool running{true};
int listener_fd = -1;

void stop(int) {
    running = false;
    auto fd = listener_fd;
    listener_fd = -1;
    if (fd >= 0) ::close(fd);
}
}

static std::string read_request(int fd) {
    std::string value; std::array<char, 4096> buffer{};
    while (value.size() <= 64 * 1024) {
        auto size = ::read(fd, buffer.data(), buffer.size());
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) throw std::runtime_error("read failed");
        if (!size) return value;
        value.append(buffer.data(), static_cast<std::size_t>(size));
    }
    throw std::runtime_error("request too large");
}

static std::int64_t now() { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }

static std::string handle(Store const& store, std::string const& request) {
    auto newline = request.find('\n');
    auto command = request.substr(0, newline);
    auto body = newline == std::string::npos ? std::string{} : request.substr(newline + 1);
    if (command == "PING") return "OK pong\n";
    if (command.rfind("INSTALL ", 0) == 0) {
        auto expected = std::stoull(command.substr(8));
        if (expected != body.size()) throw std::runtime_error("license size mismatch");
        auto license = store.install(body, now()); return "OK id=" + license.id + "\n";
    }
    auto state = store.state(now());
    if (command == "SUMMARY") {
        std::ostringstream out; out << "OK licenses=" << state.active.size() << " support_until=" << state.support_until << " features=";
        bool first = true; for (auto const& feature : state.features) { if (!first) out << ','; out << feature; first = false; }
        return out.str() + "\n";
    }
    if (command.rfind("HAS ", 0) == 0) return std::string("OK ") + (state.has(command.substr(4)) ? "1\n" : "0\n");
    if (command.rfind("ARGS ", 0) == 0) {
        auto found = state.arguments.find(command.substr(5));
        std::ostringstream out; out << "OK";
        if (found != state.arguments.end()) for (auto const& [key, value] : found->second) out << '\t' << key << '=' << value;
        return out.str() + "\n";
    }
    throw std::runtime_error("unknown command");
}

int main(int argc, char** argv) {
    fs::path storage = "/var/lib/saslik-licensing/licenses.d";
    fs::path issuers = "/etc/saslik/licensing/issuers.d";
    fs::path socket_path = "/run/saslik/licensing.sock";
    for (int index = 1; index < argc; ++index) {
        std::string option = argv[index];
        if (index + 1 >= argc) { std::cerr << "missing option value\n"; return 2; }
        if (option == "--storage") storage = argv[++index];
        else if (option == "--issuers") issuers = argv[++index];
        else if (option == "--socket") socket_path = argv[++index];
        else { std::cerr << "unknown option: " << option << '\n'; return 2; }
    }
    fs::create_directories(socket_path.parent_path());
    ::unlink(socket_path.c_str());
    int listener = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) { std::perror("socket"); return 1; }
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    if (socket_path.string().size() >= sizeof(address.sun_path)) { std::cerr << "socket path too long\n"; return 1; }
    std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1);
    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || ::listen(listener, 16) != 0) {
        std::perror("bind/listen"); return 1;
    }
    ::chmod(socket_path.c_str(), 0660);
    listener_fd = listener;
    std::signal(SIGINT, stop); std::signal(SIGTERM, stop);
    Store store(storage, issuers);
    while (running) {
        int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0 && errno == EINTR) continue;
        if (client < 0 && !running) break;
        if (client < 0) { std::perror("accept"); break; }
        try { auto response = handle(store, read_request(client)); ::send(client, response.data(), response.size(), MSG_NOSIGNAL); }
        catch (std::exception const& error) { auto response = std::string("ERR ") + error.what() + "\n"; ::send(client, response.data(), response.size(), MSG_NOSIGNAL); }
        ::close(client);
    }
    if (listener_fd >= 0) ::close(listener_fd);
    listener_fd = -1;
    ::unlink(socket_path.c_str()); return 0;
}
