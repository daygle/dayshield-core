# DayShield Core

`dayshield-core` is the Rust backend for the DayShield appliance. It provides the management API, runtime orchestration, and service integration required to operate the DayShield firewall system.

## What this repo contains

This repository implements the core service that:

- exposes the DayShield HTTP API
- handles authentication and session state
- manages backup and restore workflows
- integrates with firewall, DNS, NTP, and notification subsystems
- collects and serves logs, metrics, and status information
- delivers the management UI assets in deployed environments

## Why it matters

The core service is the central runtime component of the DayShield appliance. It coordinates the underlying Linux platform and appliance services while providing a stable interface for the UI and automation components.

## Requirements

- Rust toolchain pinned in `rust-toolchain.toml` (currently `1.88.0`)
- Linux utilities available in the target environment for runtime features:
  - `nftables`
  - `unbound`
  - `suricata`
  - `chrony` / `ntp`
  - other platform services required by the appliance

## Build

From the repository root:

```sh
cargo check -p dayshield-core
cargo build -p dayshield-core
```

For an optimized build:

```sh
cargo build -p dayshield-core --release
```

## Run

Start the core service locally:

```sh
cargo run -p dayshield-core
```

Default listen address:

- `0.0.0.0:8443`

Override the address with environment variables:

- `DAYSHIELD_BIND_ADDR` — full listen address, e.g. `127.0.0.1:8443`
- `DAYSHIELD_PORT` — bind port on `0.0.0.0`, e.g. `8443`

## Test

Run the crate test suite:

```sh
cargo test -p dayshield-core
```

## Notes

- This repo focuses on core service behavior and API/runtime integration.
- The UI frontend and appliance root filesystem are maintained in separate repositories.
- Developers should validate changes with workspace build/test commands and ensure runtime integration compatibility.
