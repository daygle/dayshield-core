# DayShield Firewall Core

Backend orchestrator for DayShield Firewall.

This workspace contains a single Rust crate at `dayshield-core/` and exposes
the DayShield Firewall API/UI service. The default bind is `0.0.0.0:8443`.

## Workspace layout

```
dayshield-core/
|-- Cargo.toml                # workspace manifest
|-- rust-toolchain.toml       # pinned Rust toolchain
`-- dayshield-core/
    |-- Cargo.toml            # crate manifest
    `-- src/
        |-- main.rs           # app entrypoint + HTTP server bind
        |-- api/              # HTTP routes/handlers
        |-- auth/             # authentication/session storage
        |-- backup/           # backup + encryption subsystem
        |-- engine/           # service engine integration (acme, dns, etc.)
        |-- logs/             # firewall/suricata/system log APIs
        |-- nat/              # NAT model + nftables rendering
        |-- notify/           # SMTP notifications
        |-- ntp/              # NTP status/apply logic
        `-- state/            # shared app state
```

## Requirements

- Rust toolchain `1.88.0` (from `rust-toolchain.toml`)
- Linux userspace tools used by runtime features (nftables, kea, unbound,
  suricata, chrony, etc.) should be present in target rootfs when those APIs
  are exercised.

## Build

Local Rust builds are for development and validation. Production release
artifacts are built by GitHub Actions from a version tag in `-core`.

From workspace root:

```sh
cargo check -p -core
cargo build -p -core
```

Release binary for local testing:

```sh
cargo build -p -core --release
```

## Run

```sh
cargo run -p -core
```

On startup the server binds to:

- `http://0.0.0.0:8443` (default)

The management UI is built static assets served by `-core` from
`/usr/local/share/-ui`.

When building the installed rootfs, the default `-core` service unit
is configured to expose the management UI on port `8443`.

You can override the bind address with environment variables:

- `_BIND_ADDR` - full listen address, e.g. `127.0.0.1:8443`
- `_PORT` - listen port on `0.0.0.0`, e.g. `8443`

## Verification (Optional)

```sh
cargo test -p -core
```

## Releases

DayShield Firewall release artifacts are produced by
`.github/workflows/release-artifacts.yml`.

Release/update model is **manifest-driven (Option B)**:

1. `dayshield-core`, `dayshield-ui`, and `dayshield-rootfs` publish artifacts with
   independent tags/versions.
2. A central `manifest.json` is generated/updated with per-component metadata
   (`version`, `downloadUrl`, `checksumSha256`, optional signature/source fields).
3. Appliances consume that manifest in registry mode and evaluate updates per
   component.

Compatibility note: the updater still supports a legacy GitHub release fallback,
but manifest is the primary source of truth.
