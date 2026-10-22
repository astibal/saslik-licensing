#include "saslik/licensing.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <tuple>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace {

constexpr std::size_t max_license_size = 64 * 1024;

bool safe_token(std::string const& value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(
               value.begin(), value.end(), [](unsigned char character) {
                   return std::isalnum(character) || character == '.' ||
                          character == '_' || character == '-';
               });
}

std::int64_t number(std::string const& value, char const* field) {
    std::size_t used = 0;
    try {
        auto result = std::stoll(value, &used);
        if (used != value.size()) {
            throw std::invalid_argument("tail");
        }
        return result;
    } catch (...) {
        throw std::runtime_error(std::string("invalid ") + field);
    }
}

std::vector<unsigned char> decode64(std::string value) {
    if (value.empty() || value.size() % 4 != 0) {
        throw std::runtime_error("invalid signature encoding");
    }
    std::vector<unsigned char> out(value.size() / 4 * 3 + 1);
    auto size = EVP_DecodeBlock(out.data(), reinterpret_cast<unsigned char const*>(value.data()),
                                static_cast<int>(value.size()));
    if (size < 0) {
        throw std::runtime_error("invalid signature encoding");
    }
    while (!value.empty() && value.back() == '=') {
        --size;
        value.pop_back();
    }
    out.resize(static_cast<std::size_t>(size));
    return out;
}

std::string read_file(fs::path const& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open " + path.string());
    }
    std::string text((std::istreambuf_iterator<char>(input)), {});
    if (text.size() > max_license_size) {
        throw std::runtime_error("license is too large");
    }
    return text;
}

void write_all(int fd, std::string const& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        auto sent = ::send(fd, value.data() + offset, value.size() - offset, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent <= 0) {
            throw std::runtime_error("socket write failed");
        }
        offset += static_cast<std::size_t>(sent);
    }
}

} // namespace

namespace saslik::licensing {

bool LicenseState::has(std::string const& feature) const {
    return features.contains(feature);
}

License parse_license(std::string const& text) {
    if (text.size() > max_license_size) {
        throw std::runtime_error("license is too large");
    }
    std::istringstream input(text);
    std::string line;
    if (!std::getline(input, line) || line != "SASLIK-LICENSE/1")
        throw std::runtime_error("unsupported license format");
    License result;
    std::map<std::string, std::string> scalar;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        auto split = line.find('=');
        if (split == std::string::npos) {
            throw std::runtime_error("malformed license line");
        }
        auto key = line.substr(0, split);
        auto value = line.substr(split + 1);
        if (key == "feature") {
            if (!safe_token(value)) {
                throw std::runtime_error("invalid feature");
            }
            result.features.insert(value);
        } else if (key == "argument") {
            auto colon = value.find(':');
            auto equal = value.find('=', colon == std::string::npos ? 0 : colon + 1);
            if (colon == std::string::npos || equal == std::string::npos) {
                throw std::runtime_error("invalid argument");
            }
            auto component = value.substr(0, colon);
            auto name = value.substr(colon + 1, equal - colon - 1);
            auto argument = value.substr(equal + 1);
            if (!safe_token(component) || !safe_token(name) ||
                argument.size() > 1024 ||
                argument.find('\n') != std::string::npos) {
                throw std::runtime_error("invalid argument");
            }
            if (!result.arguments[component].emplace(name, argument).second) {
                throw std::runtime_error("duplicate argument");
            }
        } else {
            if (!scalar.emplace(key, value).second) {
                throw std::runtime_error("duplicate field");
            }
        }
    }
    auto take = [&](char const* key) -> std::string {
        auto it = scalar.find(key);
        if (it == scalar.end()) {
            throw std::runtime_error(std::string("missing ") + key);
        }
        auto value = it->second;
        scalar.erase(it);
        return value;
    };

    result.id = take("id");
    result.issuer = take("issuer");
    result.product = take("product");
    result.subject = take("subject");
    result.issued_at = number(take("issued_at"), "issued_at");
    result.not_before = number(take("not_before"), "not_before");
    result.not_after = number(take("not_after"), "not_after");
    result.support_until = number(take("support_until"), "support_until");
    result.signature = take("signature");
    if (!scalar.empty() || !safe_token(result.id) ||
        !safe_token(result.issuer) || result.product != "saslik" ||
        result.subject.empty() || result.subject.size() > 256) {
        throw std::runtime_error("invalid license fields");
    }
    return result;
}

std::string canonical_payload(License const& value) {
    std::ostringstream out;
    out << "SASLIK-LICENSE/1\n"
        << "id=" << value.id << '\n' << "issuer=" << value.issuer << '\n'
        << "product=" << value.product << '\n' << "subject=" << value.subject << '\n'
        << "issued_at=" << value.issued_at << '\n' << "not_before=" << value.not_before << '\n'
        << "not_after=" << value.not_after << '\n' << "support_until=" << value.support_until << '\n';
    for (auto const& feature : value.features) {
        out << "feature=" << feature << '\n';
    }
    for (auto const& [component, arguments] : value.arguments) {
        for (auto const& [name, argument] : arguments) {
            out << "argument=" << component << ':' << name << '=' << argument << '\n';
        }
    }
    return out.str();
}

void verify_license(License const& license, fs::path const& issuers_dir, std::int64_t now) {
    if (license.not_before > license.not_after || now < license.not_before ||
        now > license.not_after) {
        throw std::runtime_error("license is not currently valid");
    }

    auto key_path = issuers_dir / (license.issuer + ".pem");
    struct FileCloser {
        void operator()(FILE* value) const {
            if (value) {
                fclose(value);
            }
        }
    };
    std::unique_ptr<FILE, FileCloser> file(fopen(key_path.c_str(), "r"));
    if (!file) {
        throw std::runtime_error("unknown license issuer");
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_PUBKEY(file.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free);
    if (!key) {
        throw std::runtime_error("invalid issuer public key");
    }
    auto payload = canonical_payload(license);
    auto signature = decode64(license.signature);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context ||
        EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr,
                             key.get()) != 1 ||
        EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                         reinterpret_cast<unsigned char const*>(payload.data()),
                         payload.size()) != 1) {
        throw std::runtime_error("license signature verification failed");
    }
}

Store::Store(fs::path licenses_dir, fs::path issuers_dir)
    : licenses_dir_(std::move(licenses_dir)), issuers_dir_(std::move(issuers_dir)) {}

LicenseState Store::state(std::int64_t now) const {
    LicenseState result;
    std::error_code error;
    if (!fs::is_directory(licenses_dir_, error)) {
        return result;
    }
    for (auto const& entry : fs::directory_iterator(licenses_dir_)) {
        if (!entry.is_regular_file() ||
            entry.path().extension() != ".license") {
            continue;
        }
        try {
            auto license = parse_license(read_file(entry.path()));
            verify_license(license, issuers_dir_, now);
            result.support_until = std::max(result.support_until, license.support_until);
            result.features.insert(license.features.begin(), license.features.end());
            // Later expiry wins for argument collisions; stable id order breaks ties.
            result.active.push_back(std::move(license));
        } catch (std::exception const&) {
            // Invalid files stay on disk for diagnosis but never enter the facade.
        }
    }
    std::sort(result.active.begin(), result.active.end(), [](auto const& a, auto const& b) {
        return std::tie(a.not_after, a.id) < std::tie(b.not_after, b.id);
    });
    for (auto const& license : result.active) {
        for (auto const& [component, arguments] : license.arguments) {
            for (auto const& [key, value] : arguments) {
                result.arguments[component][key] = value;
            }
        }
    }
    return result;
}

License Store::install(std::string const& text, std::int64_t now) const {
    auto license = parse_license(text);
    verify_license(license, issuers_dir_, now);
    fs::create_directories(licenses_dir_);
    auto destination = licenses_dir_ / (license.id + ".license");
    auto temporary = destination;
    temporary += ".tmp." + std::to_string(::getpid());
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output || !(output << text) || !output.flush()) {
            throw std::runtime_error("cannot write license storage");
        }
    }
    fs::permissions(temporary, fs::perms::owner_read | fs::perms::owner_write |
                               fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace);
    fs::rename(temporary, destination);
    return license;
}

std::string query_socket(fs::path const& socket, std::string const& request,
                         std::string const& body) {
    int raw = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (raw < 0) {
        throw std::runtime_error("cannot create licensing socket");
    }
    std::unique_ptr<int, void (*)(int*)> fd(&raw, [](int* value) {
        if (*value >= 0) {
            ::close(*value);
        }
    });

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket.string().size() >= sizeof(address.sun_path)) {
        throw std::runtime_error("socket path is too long");
    }
    std::strncpy(address.sun_path, socket.c_str(), sizeof(address.sun_path) - 1);
    if (::connect(raw, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        throw std::runtime_error("licensing service is unavailable");
    write_all(raw, request + "\n" + body);
    ::shutdown(raw, SHUT_WR);
    std::string response;
    std::array<char, 4096> buffer{};
    while (true) {
        auto size = ::read(raw, buffer.data(), buffer.size());
        if (size < 0 && errno == EINTR) {
            continue;
        }
        if (size < 0) {
            throw std::runtime_error("socket read failed");
        }
        if (size == 0) {
            break;
        }
        response.append(buffer.data(), static_cast<std::size_t>(size));
        if (response.size() > max_license_size) {
            throw std::runtime_error("oversized response");
        }
    }
    return response;
}

} // namespace saslik::licensing
