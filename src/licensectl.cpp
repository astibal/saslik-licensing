#include "saslik/licensing.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace fs = std::filesystem;

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
               "install-issuer NAME FILE\n";
        return 2;
    }

    try {
        std::string action = argv[index++];
        std::string request;
        std::string body;

        if (action == "status") {
            request = "SUMMARY";
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
        } else {
            throw std::runtime_error("invalid command");
        }

        auto response = saslik::licensing::query_socket(socket, request, body);
        std::cout << response;
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    } catch (std::exception const& error) {
        std::cerr << "saslik-licensectl: " << error.what() << '\n';
        return 1;
    }
}
