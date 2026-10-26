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

`saslik-licensectl status` renders the verified trust chain and active licenses
without exposing signatures or complete license payloads. These IDs and feature
names are illustrative; the command always reports the actual installed state:

```text
Licensing trust
  Root       v1 · A31F…92C0
  Signing    saslik.io-authority/v1 · 781B…04EF

Valid licenses
  earlybird-1    earlybird · tuntom
  lored-feed     lored
```

## License format

The format is intentionally strict, canonical and dependency-free. Timestamps
are Unix seconds. Features and arguments are sorted before signature checking.

```text
SASLIK-LICENSE/1
id=earlybird-0001
issuer=saslik.io-authority
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
saslik-licensectl install-issuer saslik.io-authority saslik-issuer-public.pem
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

## Offline issuer helper

Do not assemble or sort license files by hand. First create a long-lived root
key on an offline machine. The root signs operational public keys, not customer
licenses:

```bash
saslik-license-issuer root-keygen \
  --private saslik-root-private.pem \
  --public saslik-root-public.pem
```

Pin `saslik-root-public.pem` in Saslik releases. Keep the root private key
offline and use it to create a rotatable operational issuer key plus its signed
DNS record:

```bash
saslik-license-issuer keygen \
  --private issuer-private.pem \
  --public issuer-public.pem \
  --root-key saslik-root-private.pem \
  --txt-output saslik-license-dns.txt \
  --issuer saslik.io-authority \
  --dns-name _saslik-license.saslik.io \
  --valid-days 365
```

The command prints the complete TXT record and a `dig` reminder. Verify a saved
record against the pinned root before publishing or consuming it:

```bash
saslik-license-issuer dns-verify \
  --root-key saslik-root-public.pem \
  --input saslik-license-dns.txt
```

For rotation, sign an already generated operational public key with
`dns-sign --root-key ... --key ...`. The signed canonical payload includes the
issuer, operational key, `not_before` and `not_after`. A forged or stale DNS
answer therefore cannot introduce a trusted license-signing key.

All key-generation commands refuse to overwrite existing files. Private keys
are created with mode `0600`.

The runtime daemon pins the root public key at
`/etc/saslik/licensing/root.pem`. Saslik automatically queries the TXT record
at `_saslik-license.saslik.io`, sends it to the daemon for signature and
validity checks, and caches it only after acceptance. DNS failure falls back to
the last accepted record. If neither the root key nor a usable record exists,
Saslik simply runs in community mode.

The repository carries that trust anchor as
`packaging/keys/saslik-root-public.pem`. `cmake --install` installs the same
file as `/etc/saslik/licensing/root.pem`. Its SHA-256 fingerprint (DER public
key) is:

```text
5feeb49a8421498fb4c94024c7cbcc60f99f49b3858c2330c9901f36df829cc4
```

Issue a license for a relative validity period:

```bash
saslik-license-issuer issue \
  --key saslik-issuer-private.pem \
  --output earlybird-0001.license \
  --id earlybird-0001 \
  --subject "Example supporter" \
  --valid-days 365 \
  --feature component.lored \
  --feature support.active \
  --argument lored:workers=4
```

`issued_at` defaults to the current time, `not_before` to `issued_at`, and
`support_until` to the calculated `not_after`. For exact dates, replace
`--valid-days` with `--not-after UNIX`. The remaining timestamps can also be
overridden:

```bash
  --issued-at 1792627200 \
  --not-before 1792627200 \
  --support-until 1824163200
```

The helper validates the fields through the same parser as the runtime,
canonicalizes their order, signs the exact payload with Ed25519, Base64-encodes
the signature and writes the final plaintext `.license` file. It also refuses
to overwrite an existing output file.
