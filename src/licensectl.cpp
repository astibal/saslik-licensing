#include "saslik/licensing.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string short_fingerprint(std::string const& value) {
    if (value == "-" || value.size() < 8) {
        return "unavailable";
    }
    return value.substr(0, 4) + "…" + value.substr(value.size() - 4);
}

std::pair<int, std::string> feature_label(std::string value) {
    constexpr std::pair<char const*, int> prefixes[] = {
        {"plan.", 0}, {"tier.", 0}, {"component.", 1}, {"feature.", 2},
    };
    for (auto const& [prefix, priority] : prefixes) {
        if (value.rfind(prefix, 0) == 0) {
            return {priority, value.substr(std::char_traits<char>::length(prefix))};
        }
    }
    return {3, value};
}

std::string format_report(std::string const& response) {
    std::istringstream input(response);
    std::string line;
    if (!std::getline(input, line) || line != "OK") {
        return response;
    }
    std::vector<std::string> trust;
    std::vector<std::pair<std::string, std::vector<std::string>>> licenses;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        std::vector<std::string> fields;
        std::istringstream row(line);
        std::string field;
        while (std::getline(row, field, '\t')) {
            fields.push_back(field);
        }
        if (fields.size() == 3 && fields[0] == "ROOT") {
            trust.push_back("  Root       " + fields[1] + " · " +
                            short_fingerprint(fields[2]));
        } else if (fields.size() == 4 && fields[0] == "SIGNING") {
            trust.push_back("  Signing    " + fields[1] + "/" + fields[2] +
                            " · " + short_fingerprint(fields[3]));
        } else if (fields.size() >= 2 && fields[0] == "LICENSE") {
            std::vector<std::pair<int, std::string>> labels;
            for (std::size_t index = 2; index < fields.size(); ++index) {
                labels.push_back(feature_label(fields[index]));
            }
            std::sort(labels.begin(), labels.end());
            std::vector<std::string> rendered;
            for (auto const& [_, label] : labels) {
                rendered.push_back(label);
            }
            licenses.emplace_back(fields[1], std::move(rendered));
        }
    }

    std::ostringstream output;
    output << "Licensing trust\n";
    for (auto const& entry : trust) {
        output << entry << '\n';
    }
    output << "\nValid licenses\n";
    if (licenses.empty()) {
        output << "  (none)\n";
    } else {
        std::sort(licenses.begin(), licenses.end(), [](auto const& left,
                                                       auto const& right) {
            return left.first < right.first;
        });
        std::size_t width = 0;
        for (auto const& [id, _] : licenses) {
            width = std::max(width, id.size());
        }
        for (auto const& [id, labels] : licenses) {
            output << "  " << std::left << std::setw(static_cast<int>(width + 4))
                   << id;
            for (std::size_t index = 0; index < labels.size(); ++index) {
                if (index) {
                    output << " · ";
                }
                output << labels[index];
            }
            output << '\n';
        }
    }
    return output.str();
}

} // namespace

int main(int argc, char** argv) {
    fs::path socket = "/run/saslik/licensing.sock";
    int index = 1;
    if (argc > 3 && std::string(argv[1]) == "--socket") {
        socket = argv[2];
        index = 3;
    }
    if (index >= argc) {
        std::cerr
            << "usage: saslik-licensectl [--socket PATH] "
               "status|has FEATURE|args COMPONENT|install FILE|"
               "install-issuer NAME FILE|install-signed-issuer FILE\n";
        return 2;
    }

    try {
        std::string action = argv[index++];
        std::string request;
        std::string body;

        if (action == "status") {
            request = "REPORT";
        } else if (action == "has" && index < argc) {
            request = "HAS " + std::string(argv[index]);
        } else if (action == "args" && index < argc) {
            request = "ARGS " + std::string(argv[index]);
        } else if (action == "install" && index < argc) {
            std::ifstream input(argv[index], std::ios::binary);
            if (!input) {
                throw std::runtime_error("cannot read license file");
            }
            body.assign(std::istreambuf_iterator<char>(input), {});
            request = "INSTALL " + std::to_string(body.size());
        } else if (action == "install-issuer" && index + 1 < argc) {
            auto name = std::string(argv[index++]);
            std::ifstream input(argv[index], std::ios::binary);
            if (!input) {
                throw std::runtime_error("cannot read issuer public key");
            }
            body.assign(std::istreambuf_iterator<char>(input), {});
            request = "INSTALL-ISSUER " + name + " " +
                      std::to_string(body.size());
        } else if (action == "install-signed-issuer" && index < argc) {
            std::ifstream input(argv[index], std::ios::binary);
            if (!input) {
                throw std::runtime_error("cannot read signed issuer record");
            }
            body.assign(std::istreambuf_iterator<char>(input), {});
            while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) {
                body.pop_back();
            }
            request = "INSTALL-SIGNED-ISSUER " + std::to_string(body.size());
        } else {
            throw std::runtime_error("invalid command");
        }

        auto response = saslik::licensing::query_socket(socket, request, body);
        std::cout << (action == "status" ? format_report(response) : response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    } catch (std::exception const& error) {
        std::cerr << "saslik-licensectl: " << error.what() << '\n';
        return 1;
    }
}
