# DayShield Core

`dayshield-core` is the Rust backend for the DayShield appliance. It provides the management API, runtime orchestration, and service integration required to operate the DayShield firewall system.

## What this repo contains

This repository implements the core service that:

- exposes the DayShield HTTP API
- handles authentication and session state
- manages backup and restore workflows
- integrates with firewall, DNS, NTP, and notification subsystems
- manages QoS / Smart Queue Management with Linux traffic control
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

## Caddy reverse proxy endpoints

`dayshield-core` exposes reverse-proxy management under `/caddy/`:

- `GET  /caddy/config` - current Caddy reverse-proxy configuration
- `POST /caddy/config` - update persisted config and render `/etc/caddy/Caddyfile`
- `GET  /caddy/status` - service runtime status (unit state, binary, version, site count)
- `POST /caddy/restart` - restart the Caddy service
- `GET  /caddy/logs` - recent Caddy journal lines

Each site maps a public `domain` to a backend `upstream` (an `http://` or
`https://` URL). Caddy provisions and renews TLS certificates automatically via
Let's Encrypt; the `acmeEmail` field is the ACME account contact address. The
`caddy.service` systemd unit is installed but stays disabled until a valid
configuration is saved, at which point `dayshield-core` enables and reloads it.

## QoS / Smart Queue Management endpoints

`dayshield-core` exposes interface-level QoS controls under `/qos/`:

- `GET  /qos/config` - current QoS configuration
- `PUT  /qos/config` - update persisted config and apply Linux `tc` qdiscs
- `GET  /qos/status` - live `tc -s qdisc` status for configured interfaces
- `POST /qos/apply` - re-apply the persisted config

The runtime engine supports CAKE (default, with optional bandwidth shaping,
diffserv mode, NAT awareness, and DSCP wash) and fq_codel.

## Rootfs update workflow endpoints

`dayshield-core` exposes an image-based rootfs update slice under `/system/rootfs/`:

- `GET  /system/rootfs/status` - full rootfs update status for UI cards/views
- `POST /system/rootfs/check` - query the GitHub release registry for a newer rootfs version
- `POST /system/rootfs/stage` - download and stage the rootfs squashfs artifact
- `POST /system/rootfs/apply` - mark the staged image for activation on next boot
- `GET  /system/rootfs/reboot-required` - compact reboot-required payload for UX banners
- `POST /system/rootfs/rollback` - schedule a revert to the previous known-good version

### How it works

- Version metadata is tracked in `/var/lib/dayshield/rootfs-update/` as `current.json`, `pending.json`, and `previous.json`.
- `stage` and `apply` require the authenticated admin identity and emit audit-targeted tracing events.
- All three operations are serialized behind an in-process lock to prevent concurrent transactions.
- The initramfs reads the `activate` or `rollback` marker on boot and switches to the correct squashfs image.
- After a successful boot the `dayshield-boot-success` systemd unit promotes `pending` → `current`.
