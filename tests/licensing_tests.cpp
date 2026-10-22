#include "saslik/licensing.hpp"

#include <cassert>
#include <iostream>

int main() {
    auto license = saslik::licensing::parse_license(
        "SASLIK-LICENSE/1\n"
        "id=earlybird-1\nissuer=smithproxy\nproduct=saslik\nsubject=Example supporter\n"
        "issued_at=100\nnot_before=100\nnot_after=200\nsupport_until=190\n"
        "feature=component.spider\nfeature=component.viewer\n"
        "argument=spider:workers=4\nsignature=AAAA\n");
    assert(license.id == "earlybird-1");
    assert(license.features.contains("component.spider"));
    assert(license.arguments.at("spider").at("workers") == "4");
    auto canonical = saslik::licensing::canonical_payload(license);
    assert(canonical.find("signature=") == std::string::npos);
    assert(canonical.find("feature=component.viewer") != std::string::npos);
    std::cout << "licensing parser tests passed\n";
}

