#include "saslik/licensing.hpp"
#include "saslik/dns_key.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace fs = std::filesystem;
using saslik::licensing::Store;

namespace {

constexpr std::size_t max_request_size = 64 * 1024;

std::atomic_bool running{true};
int listener_fd = -1;

void stop(int) {
    running = false;
    auto fd = listener_fd;
    listener_fd = -1;
    if (fd >= 0) {
        ::close(fd);
    }
}

} // namespace

static std::string read_request(int fd) {
    std::string request;
    std::array<char, 4096> buffer{};

    while (request.size() <= max_request_size) {
        auto bytes_read = ::read(fd, buffer.data(), buffer.size());
        if (bytes_read < 0 && errno == EINTR) {
            continue;
        }
        if (bytes_read < 0) {
            throw std::runtime_error("read failed");
        }
        if (bytes_read == 0) {
            return request;
        }
        request.append(buffer.data(), static_cast<std::size_t>(bytes_read));
    }

    throw std::runtime_error("request too large");
}

static std::int64_t current_time() {
    return std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
}

static bool safe_token(std::string const& value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
               return std::isalnum(character) || character == '.' ||
                      character == '_' || character == '-';
           });
}

static void install_issuer(fs::path const& issuers, std::string const& name,
                           std::string const& pem) {
    if (!safe_token(name) || pem.empty() || pem.size() > max_request_size) {
        throw std::runtime_error("invalid issuer public key");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> input(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        input ? PEM_read_bio_PUBKEY(input.get(), nullptr, nullptr, nullptr)
              : nullptr,
        &EVP_PKEY_free);
    if (!key || EVP_PKEY_is_a(key.get(), "ED25519") != 1) {
        throw std::runtime_error("issuer key must be an Ed25519 public key");
    }

    fs::create_directories(issuers);
    auto destination = issuers / (name + ".pem");
    auto temporary = destination;
    temporary += ".tmp." + std::to_string(::getpid());

    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output || !(output << pem) || !output.flush()) {
            throw std::runtime_error("cannot write issuer public key");
        }
    }

    fs::permissions(temporary, fs::perms::owner_read | fs::perms::owner_write |
                               fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace);
    fs::rename(temporary, destination);
}

static std::string handle(Store const& store, fs::path const& issuers,
                          fs::path const& root_key,
                          std::string const& request) {
    auto newline = request.find('\n');
    auto command = request.substr(0, newline);
    auto body = newline == std::string::npos ? std::string{} : request.substr(newline + 1);
    if (command == "PING") {
        return "OK pong\n";
    }
    if (command.rfind("INSTALL-ISSUER ", 0) == 0) {
        std::istringstream options(command.substr(15));
        std::string name;
        std::size_t expected{};
        if (!(options >> name >> expected) || expected != body.size()) {
            throw std::runtime_error("issuer key size mismatch");
        }
        install_issuer(issuers, name, body);
        return "OK issuer=" + name + "\n";
    }
    if (command.rfind("INSTALL-SIGNED-ISSUER ", 0) == 0) {
        auto expected = std::stoull(command.substr(22));
        if (expected != body.size()) {
            throw std::runtime_error("signed issuer record size mismatch");
        }
        auto record = saslik::licensing::parse_dns_key_record(body);
        saslik::licensing::verify_dns_key_record(record, root_key,
                                                  current_time());
        install_issuer(issuers, record.issuer,
                       saslik::licensing::dns_key_as_pem(record));
        return "OK issuer=" + record.issuer + "\n";
    }
    if (command.rfind("INSTALL ", 0) == 0) {
        auto expected = std::stoull(command.substr(8));
        if (expected != body.size()) {
            throw std::runtime_error("license size mismatch");
        }
        auto license = store.install(body, current_time());
        return "OK id=" + license.id + "\n";
    }

    auto state = store.state(current_time());
    if (command == "REPORT") {
        std::ostringstream out;
        out << "OK\nROOT\tv1\t";
        try {
            out << saslik::licensing::public_key_fingerprint(root_key);
        } catch (std::exception const&) {
            out << '-';
        }
        out << '\n';

        std::vector<fs::path> signing_keys;
        std::error_code error;
        if (fs::is_directory(issuers, error)) {
            for (auto const& entry : fs::directory_iterator(issuers)) {
                if (entry.is_regular_file() && entry.path().extension() == ".pem") {
                    signing_keys.push_back(entry.path());
                }
            }
        }
        std::sort(signing_keys.begin(), signing_keys.end());
        for (auto const& key : signing_keys) {
            auto issuer = key.stem().string();
            if (!safe_token(issuer)) {
                continue;
            }
            out << "SIGNING\t" << issuer << "\tv1\t";
            try {
                out << saslik::licensing::public_key_fingerprint(key);
            } catch (std::exception const&) {
                out << '-';
            }
            out << '\n';
        }
        for (auto const& license : state.active) {
            out << "LICENSE\t" << license.id;
            for (auto const& feature : license.features) {
                out << '\t' << feature;
            }
            out << '\n';
        }
        return out.str();
    }
    if (command == "SUMMARY") {
        std::ostringstream out;
        out << "OK licenses=" << state.active.size()
            << " support_until=" << state.support_until << " features=";
        bool first = true;
        for (auto const& feature : state.features) {
            if (!first) {
                out << ',';
            }
            out << feature;
            first = false;
        }
        return out.str() + "\n";
    }
    if (command.rfind("HAS ", 0) == 0) {
        return std::string("OK ") +
               (state.has(command.substr(4)) ? "1\n" : "0\n");
    }
    if (command.rfind("ARGS ", 0) == 0) {
        auto found = state.arguments.find(command.substr(5));
        std::ostringstream out;
        out << "OK";
        if (found != state.arguments.end()) {
            for (auto const& [key, value] : found->second) {
                out << '\t' << key << '=' << value;
            }
        }
        return out.str() + "\n";
    }
    throw std::runtime_error("unknown command");
}

int main(int argc, char** argv) {
    fs::path storage = "/var/lib/saslik-licensing/licenses.d";
    fs::path issuers = "/etc/saslik/licensing/issuers.d";
    fs::path socket_path = "/run/saslik/licensing.sock";
    fs::path root_key = "/etc/saslik/licensing/root.pem";

    for (int index = 1; index < argc; ++index) {
        std::string option = argv[index];
        if (index + 1 >= argc) {
            std::cerr << "missing option value\n";
            return 2;
        }
        if (option == "--storage") {
            storage = argv[++index];
        } else if (option == "--issuers") {
            issuers = argv[++index];
        } else if (option == "--socket") {
            socket_path = argv[++index];
        } else if (option == "--root-key") {
            root_key = argv[++index];
        } else {
            std::cerr << "unknown option: " << option << '\n';
            return 2;
        }
    }

    fs::create_directories(socket_path.parent_path());
    ::unlink(socket_path.c_str());

    int listener = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        std::perror("socket");
        return 1;
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path.string().size() >= sizeof(address.sun_path)) {
        std::cerr << "socket path too long\n";
        ::close(listener);
        return 1;
    }
    std::strncpy(address.sun_path, socket_path.c_str(),
                 sizeof(address.sun_path) - 1);
    if (::bind(listener, reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) != 0 ||
        ::listen(listener, 16) != 0) {
        std::perror("bind/listen");
        ::close(listener);
        return 1;
    }

    ::chmod(socket_path.c_str(), 0660);
    listener_fd = listener;
    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);

    Store store(storage, issuers);
    while (running) {
        int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0 && errno == EINTR) {
            continue;
        }
        if (client < 0 && !running) {
            break;
        }
        if (client < 0) {
            std::perror("accept");
            break;
        }

        try {
            auto response =
                handle(store, issuers, root_key, read_request(client));
            ::send(client, response.data(), response.size(), MSG_NOSIGNAL);
        } catch (std::exception const& error) {
            auto response = std::string("ERR ") + error.what() + "\n";
            ::send(client, response.data(), response.size(), MSG_NOSIGNAL);
        }
        ::close(client);
    }

    if (listener_fd >= 0) {
        ::close(listener_fd);
    }
    listener_fd = -1;
    ::unlink(socket_path.c_str());
    return 0;
}
