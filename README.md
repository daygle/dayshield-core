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
- `POST /system/ostree/check` - run `rpm-ostree upgrade --check`
- `POST /system/ostree/stage` - run `rpm-ostree upgrade --download-only`
- `POST /system/ostree/apply` - run `rpm-ostree upgrade` (stages deployment for reboot)
- `GET  /system/ostree/reboot-required` - compact reboot-required payload for UX banners

### Assumptions

- The appliance image provides `rpm-ostree` and supports `rpm-ostree status --json`.
- OSTree operations are driven by CLI invocations in `dayshield-core` and are not yet mediated by a privileged helper/agent.

### TODOs for production hardening

- Gate `stage`/`apply` operations behind stricter authorization and audit policy hooks.
- Add operation locking/queueing to prevent concurrent OSTree transactions.
- Add stronger parsing for additional rpm-ostree JSON variants and explicit transaction-state reporting.
- Add integration tests with mocked `rpm-ostree` command outputs (success, no-update, failure, command-missing).
