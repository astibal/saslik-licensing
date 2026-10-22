#include "saslik/dns_key.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct FileCloser {
    void operator()(FILE* file) const {
        if (file) {
            std::fclose(file);
        }
    }
};

std::int64_t parse_number(std::string const& value, char const* field) {
    std::size_t used = 0;
    try {
        auto number = std::stoll(value, &used);
        if (used != value.size()) {
            throw std::invalid_argument("trailing text");
        }
        return number;
    } catch (std::exception const&) {
        throw std::runtime_error(std::string("invalid ") + field);
    }
}

std::vector<unsigned char> decode_base64(std::string value) {
    if (value.empty() || value.size() % 4 != 0) {
        throw std::runtime_error("invalid Base64 value");
    }

    std::vector<unsigned char> decoded(value.size() / 4 * 3 + 1);
    auto size = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<unsigned char const*>(value.data()),
        static_cast<int>(value.size()));
    if (size < 0) {
        throw std::runtime_error("invalid Base64 value");
    }
    while (!value.empty() && value.back() == '=') {
        --size;
        value.pop_back();
    }
    decoded.resize(static_cast<std::size_t>(size));
    return decoded;
}

} // namespace

namespace saslik::licensing {

DnsKeyRecord parse_dns_key_record(std::string const& text) {
    std::map<std::string, std::string> fields;
    std::istringstream input(text);
    std::string field;
    while (std::getline(input, field, ';')) {
        auto split = field.find('=');
        if (split == std::string::npos ||
            !fields.emplace(field.substr(0, split), field.substr(split + 1))
                 .second) {
            throw std::runtime_error("malformed DNS key record");
        }
    }
    if (fields.size() != 6 || fields["v"] != "saslik1") {
        throw std::runtime_error("unsupported DNS key record");
    }

    DnsKeyRecord record;
    record.issuer = fields["issuer"];
    record.not_before = parse_number(fields["not_before"], "not_before");
    record.not_after = parse_number(fields["not_after"], "not_after");
    record.key = fields["key"];
    record.signature = fields["signature"];
    if (record.issuer.empty() || record.key.empty() || record.signature.empty()) {
        throw std::runtime_error("incomplete DNS key record");
    }
    return record;
}

std::string dns_key_payload(DnsKeyRecord const& record) {
    std::ostringstream payload;
    payload << "SASLIK-DNS-KEY/1\n"
            << "issuer=" << record.issuer << '\n'
            << "not_before=" << record.not_before << '\n'
            << "not_after=" << record.not_after << '\n'
            << "key=" << record.key << '\n';
    return payload.str();
}

void verify_dns_key_record(DnsKeyRecord const& record,
                           fs::path const& root_public_key,
                           std::int64_t now) {
    if (record.not_before > record.not_after || now < record.not_before ||
        now > record.not_after) {
        throw std::runtime_error("DNS key record is not currently valid");
    }

    std::unique_ptr<FILE, FileCloser> input(
        std::fopen(root_public_key.c_str(), "r"));
    if (!input) {
        throw std::runtime_error("license root public key is unavailable");
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> root_key(
        PEM_read_PUBKEY(input.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free);
    if (!root_key || EVP_PKEY_is_a(root_key.get(), "ED25519") != 1) {
        throw std::runtime_error("license root key must be Ed25519");
    }

    auto payload = dns_key_payload(record);
    auto signature = decode_base64(record.signature);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context ||
        EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr,
                             root_key.get()) != 1 ||
        EVP_DigestVerify(
            context.get(), signature.data(), signature.size(),
            reinterpret_cast<unsigned char const*>(payload.data()),
            payload.size()) != 1) {
        throw std::runtime_error("DNS key record signature is invalid");
    }
}

std::string dns_key_as_pem(DnsKeyRecord const& record) {
    auto der = decode_base64(record.key);
    auto const* cursor = der.data();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size())),
        &EVP_PKEY_free);
    if (!key || cursor != der.data() + der.size() ||
        EVP_PKEY_is_a(key.get(), "ED25519") != 1) {
        throw std::runtime_error("DNS operational key must be Ed25519");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()),
                                                     &BIO_free);
    if (!output || PEM_write_bio_PUBKEY(output.get(), key.get()) != 1) {
        throw std::runtime_error("cannot encode DNS operational key");
    }
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(output.get(), &memory);
    return {memory->data, memory->length};
}

} // namespace saslik::licensing
