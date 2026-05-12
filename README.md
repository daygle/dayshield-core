# DayShield Core

Backend orchestrator for DayShield Firewall OS.

This workspace contains a single Rust crate at `dayshield-core/` and exposes
the DayShield API/UI service. The default bind is `0.0.0.0:8443`.

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
artifacts are built by GitHub Actions from a version tag in `dayshield-core`.

From workspace root:

```sh
cargo check -p dayshield-core
cargo build -p dayshield-core
```

Release binary for local testing:

```sh
cargo build -p dayshield-core --release
```

## Run

```sh
cargo run -p dayshield-core
```

On startup the server binds to:

- `http://0.0.0.0:8443` (default)

The management UI is built static assets served by `dayshield-core` from
`/usr/local/share/dayshield-ui`.

When building the installed rootfs, the default `dayshield-core` service unit
is configured to expose the management UI on port `8443`.

You can override the bind address with environment variables:

- `DAYSHIELD_BIND_ADDR` - full listen address, e.g. `127.0.0.1:8443`
- `DAYSHIELD_PORT` - listen port on `0.0.0.0`, e.g. `8443`

## Verification (Optional)

```sh
cargo test -p dayshield-core
```

## Releases

DayShield release artifacts are produced by
`.github/workflows/release-artifacts.yml`.

Release flow:

1. Merge the required `dayshield-core`, `dayshield-ui`, and `dayshield-rootfs`
    changes.
2. Create and push a version tag from `dayshield-core`, for example `v1.2.3`.
3. GitHub Actions builds and publishes:
    - `core-vX.Y.Z.tar.zst`
    - `ui-vX.Y.Z.tar.zst`
    - `rootfs-vX.Y.Z.tar.zst`
    - `checksums.txt`

Installed appliances consume these prebuilt artifacts through the update
registry. They do not build core or UI on the appliance.
