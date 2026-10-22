# Saslik Licensing

Small local license storage and feature facade for Saslik components.

## Why this exists

Smithproxy, Saslik, Spider, Sift and the surrounding tooling require substantial
engineering, testing and user support. This component gives the project a clear
way to fund that work: a valid license can enable supported components, support
entitlements and carefully scoped runtime options.

This is **not designed as user harassment or hostile DRM**. It deliberately does
not contain obfuscation, anti-debugging, machine fingerprinting, online
activation, telemetry, or attempts to prevent a determined user from modifying
their own machine. The objective is honest feature management and a sustainable
support relationship, not a licensing maze.

The licensing module is itself a separate proprietary component. Open parts of
the Saslik ecosystem remain governed by their own licenses.

## Model

```text
signed license file
        │  Ed25519 / OpenSSL
        ▼
saslik-licensingd
  ├── validates and atomically stores licenses
  ├── merges active feature grants
  ├── exposes component arguments
  └── serves a local Unix socket
        │
        ├── saslik-licensectl status
        ├── saslik-licensectl has component.spider
        └── saslik-licensectl args spider
```

Defaults:

| Resource | Path |
|---|---|
| licenses | `/var/lib/saslik-licensing/licenses.d/*.license` |
| issuer public keys | `/etc/saslik/licensing/issuers.d/*.pem` |
| Unix socket | `/run/saslik/licensing.sock` |

Only public issuer keys are deployed. License creation and private keys belong
to a separate offline issuer tool and are intentionally outside this runtime.

## License format

The format is intentionally strict, canonical and dependency-free. Timestamps
are Unix seconds. Features and arguments are sorted before signature checking.

```text
SASLIK-LICENSE/1
id=earlybird-0001
issuer=smithproxy
product=saslik
subject=Example supporter
issued_at=1792627200
not_before=1792627200
not_after=1824163200
support_until=1824163200
feature=component.spider
feature=component.pcap-viewer
argument=spider:workers=4
signature=<base64 Ed25519 signature of the canonical preceding payload>
```

An installed license is accepted only after its signature, issuer, product and
validity window pass validation. Invalid files never enter the effective facade.

## Saslik integration contract

The guardian asks the facade before starting a licensed component:

```text
saslik-licensectl has component.pcap-viewer
```

Exit status `0` plus `OK 1` allows startup. Missing or unavailable licensing is
fail-closed for proprietary components and irrelevant to community components.
The UI should explain the missing entitlement; it must not pretend the component
crashed.

Some components may request arguments:

```text
saslik-licensectl args spider
# OK<TAB>workers=4<TAB>channel=earlybird
```

Saslik can provision a trusted issuer public key through the same local facade:

```bash
saslik-licensectl install-issuer smithproxy smithproxy-ed25519-public.pem
```

The daemon accepts only a parseable Ed25519 public key and stores it atomically.
Private issuer keys never belong on a Saslik machine.

Saslik owns the allow-list translating these values to actual process arguments.
License text is never appended directly to a command line. Unknown keys are
ignored and unsafe values are rejected by the component adapter.

Recommended component declaration:

```text
component            required feature          licensed argument adapter
───────────────────  ────────────────────────  ───────────────────────────
pcap-viewer-pro      component.pcap-viewer     viewer.*
spider-pro           component.spider          spider.*
support-tools        support.active            none
```

Community components should not acquire artificial license checks merely to
make the paid tier look larger.

## Storage facade semantics

- More than one active license may be installed.
- Effective features are the union of active grants.
- `support_until` is the greatest active support date.
- For an argument collision, the license with the later expiry wins; license ID
  provides deterministic tie-breaking.
- Expired and malformed licenses remain on disk for diagnosis but are excluded
  from the effective view.
- Installation goes through the daemon, is verified first, and is atomically
  renamed into storage.

## Build

Requires a C++20 compiler, CMake and OpenSSL 3 development headers.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

This initial implementation intentionally has no networking. Future commerce or
support portals deliver signed files; the runtime only consumes them locally.
