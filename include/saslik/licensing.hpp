#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace saslik::licensing {

struct License {
    std::string id;
    std::string issuer;
    std::string product;
    std::string subject;
    std::int64_t issued_at{};
    std::int64_t not_before{};
    std::int64_t not_after{};
    std::int64_t support_until{};
    std::set<std::string> features;
    std::map<std::string, std::map<std::string, std::string>> arguments;
    std::string signature;
};

struct LicenseState {
    std::vector<License> active;
    std::set<std::string> features;
    std::map<std::string, std::map<std::string, std::string>> arguments;
    std::int64_t support_until{};

    [[nodiscard]] bool has(std::string const& feature) const;
};

License parse_license(std::string const& text);
std::string canonical_payload(License const& license);
void verify_license(License const& license, std::filesystem::path const& issuers_dir,
                    std::int64_t now);

class Store {
public:
    Store(std::filesystem::path licenses_dir, std::filesystem::path issuers_dir);
    [[nodiscard]] LicenseState state(std::int64_t now) const;
    License install(std::string const& text, std::int64_t now) const;

private:
    std::filesystem::path licenses_dir_;
    std::filesystem::path issuers_dir_;
};

std::string query_socket(std::filesystem::path const& socket, std::string const& request,
                         std::string const& body = {});

} // namespace saslik::licensing

