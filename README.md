# DayShield Core

Backend orchestrator for DayShield Firewall OS.

This workspace contains a single Rust crate at `dayshield-core/` and exposes
the DayShield API/UI service. In production the service unit sets `DAYSHIELD_PORT=8443`
so it binds to `0.0.0.0:8443`. The development default is `0.0.0.0:3000`.

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

From workspace root:

```sh
cargo check -p dayshield-core
cargo build -p dayshield-core
```

Release binary:

```sh
cargo build -p dayshield-core --release
```

## Run

```sh
cargo run -p dayshield-core
```

On startup the server binds to:

- `http://0.0.0.0:8443` (production — set via `DAYSHIELD_PORT=8443` in the service unit)

The UI is assumed to run separately and defaults to `8443` when using the
frontend dev server.

When building the installed rootfs, the default `dayshield-core` service unit
is configured to expose the management UI on port `8443`.

You can override the bind address with environment variables:

- `DAYSHIELD_BIND_ADDR` - full listen address, e.g. `127.0.0.1:8443`
- `DAYSHIELD_PORT` - listen port on `0.0.0.0`, e.g. `8443`

## Tests

```sh
cargo test -p dayshield-core
```
