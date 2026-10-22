#include "saslik/licensing.hpp"
#include "saslik/dns_key.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>

namespace fs = std::filesystem;
using saslik::licensing::License;
using saslik::licensing::DnsKeyRecord;

namespace {

struct FileCloser {
    void operator()(FILE* file) const {
        if (file) {
            std::fclose(file);
        }
    }
};

using File = std::unique_ptr<FILE, FileCloser>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX,
                                   decltype(&EVP_PKEY_CTX_free)>;
using DigestContext = std::unique_ptr<EVP_MD_CTX,
                                      decltype(&EVP_MD_CTX_free)>;

std::int64_t current_time() {
    return std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
}

std::int64_t parse_time(std::string const& value, char const* option) {
    std::size_t used = 0;
    try {
        auto result = std::stoll(value, &used);
        if (used != value.size()) {
            throw std::invalid_argument("trailing text");
        }
        return result;
    } catch (std::exception const&) {
        throw std::invalid_argument(std::string("invalid value for ") + option);
    }
}

std::string require_value(int argc, char** argv, int& index,
                          char const* option) {
    if (index + 1 >= argc) {
        throw std::invalid_argument(std::string("missing value for ") + option);
    }
    return argv[++index];
}

void require_new_file(fs::path const& path) {
    if (fs::exists(path)) {
        throw std::runtime_error("refusing to overwrite " + path.string());
    }
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path());
    }
}

std::string base64(std::vector<unsigned char> const& bytes) {
    std::string encoded(4 * ((bytes.size() + 2) / 3), '\0');
    auto size = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(encoded.data()), bytes.data(),
        static_cast<int>(bytes.size()));
    if (size < 0) {
        throw std::runtime_error("cannot encode value as Base64");
    }
    encoded.resize(static_cast<std::size_t>(size));
    return encoded;
}

std::vector<unsigned char> public_key_der(EVP_PKEY* key) {
    auto size = i2d_PUBKEY(key, nullptr);
    if (size <= 0) {
        throw std::runtime_error("cannot encode public key");
    }

    std::vector<unsigned char> der(static_cast<std::size_t>(size));
    auto* destination = der.data();
    if (i2d_PUBKEY(key, &destination) != size) {
        throw std::runtime_error("cannot encode public key");
    }
    return der;
}

std::string sha256_fingerprint(std::vector<unsigned char> const& value) {
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_size = 0;
    if (EVP_Digest(value.data(), value.size(), digest.data(), &digest_size,
                   EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("cannot calculate public key fingerprint");
    }
    digest.resize(digest_size);

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (auto byte : digest) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

void generate_keys(fs::path const& private_path, fs::path const& public_path) {
    require_new_file(private_path);
    require_new_file(public_path);

    KeyContext context(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                       &EVP_PKEY_CTX_free);
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1) {
        throw std::runtime_error("cannot initialize Ed25519 key generation");
    }

    EVP_PKEY* generated = nullptr;
    if (EVP_PKEY_keygen(context.get(), &generated) != 1) {
        throw std::runtime_error("cannot generate Ed25519 key pair");
    }
    Key key(generated, &EVP_PKEY_free);

    File private_file(std::fopen(private_path.c_str(), "w"));
    if (!private_file ||
        PEM_write_PrivateKey(private_file.get(), key.get(), nullptr, nullptr, 0,
                             nullptr, nullptr) != 1) {
        throw std::runtime_error("cannot write private key");
    }
    if (::chmod(private_path.c_str(), 0600) != 0) {
        throw std::runtime_error("cannot protect private key permissions");
    }

    File public_file(std::fopen(public_path.c_str(), "w"));
    if (!public_file || PEM_write_PUBKEY(public_file.get(), key.get()) != 1) {
        throw std::runtime_error("cannot write public key");
    }

}

Key load_private_key(fs::path const& path) {
    File input(std::fopen(path.c_str(), "r"));
    if (!input) {
        throw std::runtime_error("cannot open private key " + path.string());
    }

    Key key(PEM_read_PrivateKey(input.get(), nullptr, nullptr, nullptr),
            &EVP_PKEY_free);
    if (!key || EVP_PKEY_is_a(key.get(), "ED25519") != 1) {
        throw std::runtime_error("signing key must be an Ed25519 private key");
    }
    return key;
}

Key load_public_key(fs::path const& path) {
    File input(std::fopen(path.c_str(), "r"));
    if (!input) {
        throw std::runtime_error("cannot open public key " + path.string());
    }

    Key key(PEM_read_PUBKEY(input.get(), nullptr, nullptr, nullptr),
            &EVP_PKEY_free);
    if (!key || EVP_PKEY_is_a(key.get(), "ED25519") != 1) {
        throw std::runtime_error("root key must be an Ed25519 public key");
    }
    return key;
}

std::string sign_payload(std::string const& payload, EVP_PKEY* key) {
    DigestContext context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context ||
        EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key) != 1) {
        throw std::runtime_error("cannot initialize Ed25519 signing");
    }

    std::size_t signature_size = 0;
    auto const* data = reinterpret_cast<unsigned char const*>(payload.data());
    if (EVP_DigestSign(context.get(), nullptr, &signature_size, data,
                       payload.size()) != 1) {
        throw std::runtime_error("cannot determine signature size");
    }

    std::vector<unsigned char> signature(signature_size);
    if (EVP_DigestSign(context.get(), signature.data(), &signature_size, data,
                       payload.size()) != 1) {
        throw std::runtime_error("cannot sign license");
    }
    signature.resize(signature_size);
    return base64(signature);
}

std::string dns_txt_value(DnsKeyRecord const& record) {
    return "v=saslik1;issuer=" + record.issuer +
           ";not_before=" + std::to_string(record.not_before) +
           ";not_after=" + std::to_string(record.not_after) +
           ";key=" + record.key + ";signature=" + record.signature;
}

struct IssueOptions {
    fs::path private_key;
    fs::path output;
    License license;
    std::int64_t valid_days{};
};

IssueOptions parse_issue_options(int argc, char** argv) {
    IssueOptions options;
    options.license.issuer = "smithproxy";
    options.license.product = "saslik";
    options.license.issued_at = current_time();

    for (int index = 2; index < argc; ++index) {
        std::string option = argv[index];
        auto value = require_value(argc, argv, index, option.c_str());

        if (option == "--key") {
            options.private_key = value;
        } else if (option == "--output") {
            options.output = value;
        } else if (option == "--id") {
            options.license.id = value;
        } else if (option == "--issuer") {
            options.license.issuer = value;
        } else if (option == "--subject") {
            options.license.subject = value;
        } else if (option == "--issued-at") {
            options.license.issued_at = parse_time(value, "--issued-at");
        } else if (option == "--not-before") {
            options.license.not_before = parse_time(value, "--not-before");
        } else if (option == "--not-after") {
            options.license.not_after = parse_time(value, "--not-after");
        } else if (option == "--valid-days") {
            options.valid_days = parse_time(value, "--valid-days");
        } else if (option == "--support-until") {
            options.license.support_until =
                parse_time(value, "--support-until");
        } else if (option == "--feature") {
            options.license.features.insert(value);
        } else if (option == "--argument") {
            auto colon = value.find(':');
            auto equal = value.find('=', colon == std::string::npos
                                           ? 0
                                           : colon + 1);
            if (colon == std::string::npos || equal == std::string::npos) {
                throw std::invalid_argument(
                    "--argument expects COMPONENT:KEY=VALUE");
            }
            auto component = value.substr(0, colon);
            auto name = value.substr(colon + 1, equal - colon - 1);
            auto argument = value.substr(equal + 1);
            if (!options.license.arguments[component]
                     .emplace(name, argument)
                     .second) {
                throw std::invalid_argument("duplicate licensed argument");
            }
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }

    if (options.license.not_before == 0) {
        options.license.not_before = options.license.issued_at;
    }
    if (options.valid_days != 0) {
        if (options.valid_days < 1 || options.valid_days > 36500) {
            throw std::invalid_argument(
                "--valid-days must be between 1 and 36500");
        }
        if (options.license.not_after != 0) {
            throw std::invalid_argument(
                "use either --valid-days or --not-after, not both");
        }
        constexpr std::int64_t seconds_per_day = 24 * 60 * 60;
        options.license.not_after =
            options.license.not_before + options.valid_days * seconds_per_day;
    }
    if (options.license.support_until == 0) {
        options.license.support_until = options.license.not_after;
    }
    if (options.private_key.empty() || options.output.empty() ||
        options.license.id.empty() || options.license.subject.empty() ||
        options.license.not_after == 0) {
        throw std::invalid_argument(
            "issue requires --key, --output, --id, --subject and either "
            "--valid-days or --not-after");
    }

    return options;
}

void issue_license(IssueOptions options) {
    require_new_file(options.output);

    // Reuse the runtime parser as the single source of format validation.
    auto unsigned_payload = saslik::licensing::canonical_payload(options.license);
    auto validation_text = unsigned_payload + "signature=AAAA\n";
    saslik::licensing::parse_license(validation_text);

    auto key = load_private_key(options.private_key);
    options.license.signature = sign_payload(unsigned_payload, key.get());

    std::ofstream output(options.output, std::ios::binary | std::ios::trunc);
    if (!output ||
        !(output << unsigned_payload
                 << "signature=" << options.license.signature << '\n') ||
        !output.flush()) {
        throw std::runtime_error("cannot write license " +
                                 options.output.string());
    }
}

struct DnsSignOptions {
    fs::path root_private_key;
    fs::path operational_public_key;
    fs::path output;
    std::string issuer = "smithproxy";
    std::string dns_name = "_saslik-license.saslik.io";
    std::int64_t valid_days = 365;
};

DnsSignOptions parse_dns_sign_options(int argc, char** argv, int start = 2) {
    DnsSignOptions options;
    for (int index = start; index < argc; ++index) {
        std::string option = argv[index];
        auto value = require_value(argc, argv, index, option.c_str());
        if (option == "--root-key") {
            options.root_private_key = value;
        } else if (option == "--key") {
            options.operational_public_key = value;
        } else if (option == "--output") {
            options.output = value;
        } else if (option == "--issuer") {
            options.issuer = value;
        } else if (option == "--dns-name") {
            options.dns_name = value;
        } else if (option == "--valid-days") {
            options.valid_days = parse_time(value, "--valid-days");
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }
    if (options.root_private_key.empty() ||
        options.operational_public_key.empty()) {
        throw std::invalid_argument("dns-sign requires --root-key and --key");
    }
    if (options.valid_days < 1 || options.valid_days > 36500) {
        throw std::invalid_argument(
            "--valid-days must be between 1 and 36500");
    }
    return options;
}

std::string sign_dns_record(DnsSignOptions const& options) {
    auto operational_key = load_public_key(options.operational_public_key);
    auto root_key = load_private_key(options.root_private_key);

    constexpr std::int64_t seconds_per_day = 24 * 60 * 60;
    DnsKeyRecord record;
    record.issuer = options.issuer;
    record.not_before = current_time();
    record.not_after =
        record.not_before + options.valid_days * seconds_per_day;
    record.key = base64(public_key_der(operational_key.get()));
    record.signature = sign_payload(
        saslik::licensing::dns_key_payload(record), root_key.get());

    auto value = dns_txt_value(record);
    if (!options.output.empty()) {
        require_new_file(options.output);
        std::ofstream output(options.output, std::ios::binary | std::ios::trunc);
        if (!output || !(output << value << '\n') || !output.flush()) {
            throw std::runtime_error("cannot write DNS record");
        }
    }

    std::cout
        << "\nRoot-signed DNS TXT record:\n"
        << "  name:  " << options.dns_name << '\n'
        << "  value: " << value << "\n\n"
        << "Publish it, then inspect DNS with:\n"
        << "  dig +short TXT " << options.dns_name << '\n';
    if (!options.output.empty()) {
        std::cout << "\nRaw TXT value saved to " << options.output << '\n';
    }
    return value;
}

void verify_dns_command(int argc, char** argv) {
    fs::path root_public_key;
    fs::path input_path;
    for (int index = 2; index < argc; ++index) {
        std::string option = argv[index];
        auto value = require_value(argc, argv, index, option.c_str());
        if (option == "--root-key") {
            root_public_key = value;
        } else if (option == "--input") {
            input_path = value;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }
    if (root_public_key.empty() || input_path.empty()) {
        throw std::invalid_argument(
            "dns-verify requires --root-key and --input");
    }

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot read DNS record");
    }
    std::string value((std::istreambuf_iterator<char>(input)), {});
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }

    auto record = saslik::licensing::parse_dns_key_record(value);
    saslik::licensing::verify_dns_key_record(
        record, root_public_key, current_time());
    std::cout << "OK issuer=" << record.issuer
              << " not_after=" << record.not_after << '\n';
}

void print_usage() {
    std::cerr
        << "usage:\n"
        << "  saslik-license-issuer root-keygen --private FILE --public FILE\n"
        << "  saslik-license-issuer keygen --private FILE --public FILE "
           "--root-key FILE [--txt-output FILE] [options]\n"
        << "  saslik-license-issuer dns-sign --root-key FILE --key FILE "
           "[--output FILE] [--valid-days DAYS]\n"
        << "  saslik-license-issuer dns-verify --root-key FILE --input FILE\n"
        << "  saslik-license-issuer issue --key FILE --output FILE --id ID "
           "--subject TEXT --valid-days DAYS [options]\n\n"
        << "issue options:\n"
        << "  --issuer NAME           default: smithproxy\n"
        << "  --issued-at UNIX        default: now\n"
        << "  --not-before UNIX       default: issued-at\n"
        << "  --valid-days DAYS       relative validity period\n"
        << "  --not-after UNIX        exact expiry; alternative to valid-days\n"
        << "  --support-until UNIX    default: not-after\n"
        << "  --feature NAME          repeatable\n"
        << "  --argument C:K=VALUE    repeatable\n";
}

void keygen_command(int argc, char** argv) {
    fs::path private_path;
    fs::path public_path;
    fs::path root_private_key;
    fs::path txt_output;
    std::string issuer = "smithproxy";
    std::string dns_name = "_saslik-license.saslik.io";
    std::int64_t valid_days = 365;

    for (int index = 2; index < argc; ++index) {
        std::string option = argv[index];
        auto value = require_value(argc, argv, index, option.c_str());
        if (option == "--private") {
            private_path = value;
        } else if (option == "--public") {
            public_path = value;
        } else if (option == "--root-key") {
            root_private_key = value;
        } else if (option == "--txt-output") {
            txt_output = value;
        } else if (option == "--issuer") {
            issuer = value;
        } else if (option == "--dns-name") {
            dns_name = value;
        } else if (option == "--valid-days") {
            valid_days = parse_time(value, "--valid-days");
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }

    if (private_path.empty() || public_path.empty() ||
        root_private_key.empty()) {
        throw std::invalid_argument(
            "keygen requires --private, --public and --root-key");
    }
    generate_keys(private_path, public_path);

    DnsSignOptions dns_options;
    dns_options.root_private_key = root_private_key;
    dns_options.operational_public_key = public_path;
    dns_options.output = txt_output;
    dns_options.issuer = issuer;
    dns_options.dns_name = dns_name;
    dns_options.valid_days = valid_days;
    sign_dns_record(dns_options);
}

void root_keygen_command(int argc, char** argv) {
    fs::path private_path;
    fs::path public_path;
    for (int index = 2; index < argc; ++index) {
        std::string option = argv[index];
        auto value = require_value(argc, argv, index, option.c_str());
        if (option == "--private") {
            private_path = value;
        } else if (option == "--public") {
            public_path = value;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }
    if (private_path.empty() || public_path.empty()) {
        throw std::invalid_argument(
            "root-keygen requires --private and --public");
    }
    generate_keys(private_path, public_path);
    auto public_key = load_public_key(public_path);
    auto fingerprint = sha256_fingerprint(public_key_der(public_key.get()));
    std::cout
        << "Root key created. Keep " << private_path << " offline.\n"
        << "Pin " << public_path << " in Saslik releases.\n"
        << "Root public key SHA-256: " << fingerprint << '\n';
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            throw std::invalid_argument("missing command");
        }

        std::string command = argv[1];
        if (command == "keygen") {
            keygen_command(argc, argv);
        } else if (command == "root-keygen") {
            root_keygen_command(argc, argv);
        } else if (command == "dns-sign") {
            sign_dns_record(parse_dns_sign_options(argc, argv));
        } else if (command == "dns-verify") {
            verify_dns_command(argc, argv);
        } else if (command == "issue") {
            issue_license(parse_issue_options(argc, argv));
        } else {
            throw std::invalid_argument("unknown command: " + command);
        }
        return 0;
    } catch (std::exception const& error) {
        std::cerr << "saslik-license-issuer: " << error.what() << '\n';
        print_usage();
        return 1;
    }
}
