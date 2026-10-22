#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace saslik::licensing {

struct DnsKeyRecord {
    std::string issuer;
    std::int64_t not_before{};
    std::int64_t not_after{};
    std::string key;
    std::string signature;
};

DnsKeyRecord parse_dns_key_record(std::string const& text);
std::string dns_key_payload(DnsKeyRecord const& record);
void verify_dns_key_record(DnsKeyRecord const& record,
                           std::filesystem::path const& root_public_key,
                           std::int64_t now);
std::string dns_key_as_pem(DnsKeyRecord const& record);

} // namespace saslik::licensing
