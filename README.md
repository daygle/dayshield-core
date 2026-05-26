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

## Test

Run the crate test suite:

```sh
cargo test -p dayshield-core
```

## Notes

- This repo focuses on core service behavior and API/runtime integration.
- The UI frontend and appliance root filesystem are maintained in separate repositories.
- Developers should validate changes with workspace build/test commands and ensure runtime integration compatibility.

## OSTree update workflow endpoints

`dayshield-core` now exposes a practical OSTree-focused backend slice:

- `GET  /system/ostree/status` - full OSTree workflow status for UI cards/views
- `POST /system/ostree/check` - query the configured DayShield OSTree remote
- `POST /system/ostree/stage` - stage the next OSTree deployment
- `POST /system/ostree/apply` - stage/apply the next OSTree deployment for reboot
- `GET  /system/ostree/reboot-required` - compact reboot-required payload for UX banners

### Assumptions

- The appliance image provides `ostree` and the DayShield helper at `/usr/local/lib/dayshield/ostree-update.sh`.
- `dayshield-core` uses the helper when present, falls back to native `ostree admin` commands, and keeps `rpm-ostree` only as a compatibility fallback.

### Production hardening in place

- `stage` and `apply` require the authenticated admin identity and emit audit-targeted tracing events.
- `check`, `stage`, and `apply` operations are serialized behind an in-process OSTree operation queue to avoid concurrent OSTree transactions.
- Status responses include explicit `transactionState` data and tolerate common OSTree text output plus rpm-ostree JSON variants.
- Mocked OSTree tests cover success, no-update, failure, command-missing, and transaction-serialization paths.
