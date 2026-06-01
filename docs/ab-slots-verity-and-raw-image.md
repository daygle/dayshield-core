# A/B slots: dm-verity rootfs and raw-image dd delivery

**Status:** Deferred. Design only. No code changes from this doc.
**Owner:** dayshield-core
**Touches:** dayshield-rootfs (build), dayshield-installer-ui (install), dayshield-iso (CLI installer), dayshield-core (apply), GRUB/initramfs (boot).

## Why

Today each A/B slot is a r/w ext4 filesystem produced by `mkfs.ext4` on the
slot partition followed by `unsquashfs` from the released squashfs artifact.
This works but leaves two gaps versus the RAUC/ChromeOS gold standard:

1. **No runtime integrity for the rootfs.** A compromised running system
   can rewrite its own `/etc`, `/usr/bin`, etc. For a security appliance the
   rootfs should be a sealed, read-only, cryptographically-verified block
   device that fails-closed on tamper.
2. **`unsquashfs` is not byte-deterministic.** Each install produces a
   filesystem with different inode ordering and fragmentation than the
   build's canonical output, so we cannot hash the on-disk slot and compare
   it to a known-good value.

Fixing (1) requires (2) — dm-verity needs a fixed, byte-deterministic block
device to hash.

## Sequencing

These ship in order; (2) is a prerequisite for (1):

1. **Phase A — Raw ext4 image delivery (`#2`).** Build pipeline emits a
   `rootfs.ext4` image; installer/update writes it via `dd` instead of
   `mkfs.ext4 + unsquashfs`. Slot contents become byte-identical to build.
   No boot-path change. Safe to ship without dm-verity.
2. **Phase B — dm-verity (`#1`).** Build pipeline additionally emits a
   verity hash tree and signed root hash. GRUB cmdline + initramfs are
   updated to assemble the verity device. Slot mounts read-only.

Each phase is its own PR with its own hardware-validation gate.

---

## Phase A — Raw ext4 image delivery (`#2`)

### Build pipeline (`dayshield-rootfs`)

Replace the squashfs step in `scripts/build-rootfs.sh` with an ext4 image
build:

```sh
# Produce a deterministic, fixed-size ext4 image of the rootfs.
ROOTFS_IMG_BYTES=$((5 * 1024 * 1024 * 1024 - 16 * 1024 * 1024))  # 5GiB slot minus headroom
truncate -s "${ROOTFS_IMG_BYTES}" rootfs.ext4
mkfs.ext4 -F -L _BUILD_ -E lazy_itable_init=0,lazy_journal_init=0 \
    -O ^has_journal \
    -d "${ROOTFS_DIR}" rootfs.ext4
# Strip the build-time label so installer can set DS_ROOT_A / DS_ROOT_B
# without re-writing the rootfs contents (label is in the superblock only).
tune2fs -L "" rootfs.ext4
sha256sum rootfs.ext4 > rootfs.ext4.sha256
zstd -19 --rm rootfs.ext4 -o rootfs.ext4.zst   # ship compressed
```

Key points:
- `-O ^has_journal` makes the image deterministic across builds. The slot
  doesn't need a journal because dm-verity will mount it read-only in
  Phase B; in Phase A it's mounted r/w but with the existing IDENTITY_PATHS
  overlay flow, journal-less is fine for a slot that's rarely written.
- `-d "${ROOTFS_DIR}"` tells mke2fs to populate the image from the prepared
  rootfs directory in a single pass.
- `lazy_itable_init=0,lazy_journal_init=0` removes runtime initialization
  surprises and makes the image bit-identical run-to-run.
- Label is wiped so the installer can stamp the slot-specific label
  (`DS_ROOT_A` / `DS_ROOT_B`) post-write with `e2label`.

Release assets become:
- `rootfs.ext4.zst` — compressed image
- `rootfs.ext4.sha256` — digest of the uncompressed image
- `rootfs.ext4.sig` — ed25519 sig of the digest (paired with `#4` work)

### Installer (`dayshield-installer-ui`, `dayshield-iso`)

In `installer-ui/api/install-rootfs.sh` and `iso/config/installer/install.sh`,
replace the `extract_rootfs` calls with:

```sh
write_rootfs_image() {
    local img="$1" target_part="$2" slot_label="$3"
    zstdcat "${img}" | dd of="${target_part}" bs=4M status=progress conv=fsync
    e2label "${target_part}" "${slot_label}"
    # Optional: e2fsck -fy "${target_part}" for sanity.
}
write_rootfs_image rootfs.ext4.zst "$ROOT_A_PART" DS_ROOT_A
write_rootfs_image rootfs.ext4.zst "$ROOT_B_PART" DS_ROOT_B
```

The mount-and-customise step that currently runs after `unsquashfs`
(installer-finalize.sh: shadow, hostname, kea, network.conf, …) **stays
unchanged in Phase A**. We dd a generic image, then mount slot A and write
the install-time identity. The same identity is then mirrored to slot B by
the existing replication loop in `configure-system.sh`.

### Update apply (`dayshield-core` — `rootfs_update.rs`)

In `apply_staged_image`, replace the mkfs + unsquashfs branch:

```rust
// Phase A: write the raw ext4 image to the slot device.
run_status(
    Command::new("sh").arg("-c").arg(format!(
        "zstdcat {} | dd of={} bs=4M conv=fsync",
        shell_escape(image_path),
        shell_escape(slot_device.display())
    )),
    "dd rootfs.ext4 to slot",
).await?;
run_status(
    Command::new("e2label").arg(&slot_device).arg(slot.label()),
    "stamp slot label",
).await?;
```

Keep the existing IDENTITY_PATHS mount-then-copy step that runs after the
write — it's still needed because the dd'd image is the generic build
output without this appliance's hostname/shadow/etc.

### Acceptance criteria (Phase A)

- [ ] Two consecutive builds of the same git SHA produce byte-identical
      `rootfs.ext4` files (`sha256sum` matches).
- [ ] Fresh install via ISO produces slot A and slot B with identical
      `sha256sum` of the slot partitions (read raw partition, not mounted
      contents).
- [ ] In-place update from vN to vN+1 boots into the new slot.
- [ ] Rollback from N+1 to N still boots and preserves all DayShield
      persistent state under `/var/lib/dayshield/`.
- [ ] Update apply time on reference hardware does not regress more than
      20% vs current unsquashfs flow.

### Risks (Phase A)

- **Image size larger on disk than squashfs.** Mitigated by zstd
  compression of the artifact; on-disk size is the slot partition size
  either way.
- **Fixed image size constrains slot growth.** Build must assert
  `du -sb ${ROOTFS_DIR} < ROOTFS_IMG_BYTES * 0.85` so we have headroom for
  runtime writes (logs, package cache).
- **Per-slot tweaks at apply time still mutate /etc inside the slot.**
  Phase A does not seal the rootfs. That comes in Phase B.

---

## Phase B — dm-verity (`#1`)

### What dm-verity does

dm-verity creates a virtual read-only block device whose every 4 KiB block
is hashed in a Merkle tree at build time. Every read at runtime is
verified against the tree before the page enters the page cache. Any
tampering — by malware, disk corruption, or accidental write — produces
either an I/O error or kernel panic, depending on the cmdline mode. The
root of the hash tree (a single 32-byte SHA256) is what we sign and pass
to the kernel.

### Build pipeline (`dayshield-rootfs`)

After the Phase A `rootfs.ext4` is built:

```sh
veritysetup format rootfs.ext4 rootfs.verity > rootfs.verity.info
# rootfs.verity.info contains, among other things:
#   Root hash:      <64 hex chars>
#   Hash type:      1
#   Data blocks:    <N>
#   Data block size: 4096
#   Hash block size: 4096
ROOT_HASH=$(awk '/Root hash:/ {print $3}' rootfs.verity.info)
printf '%s' "${ROOT_HASH}" > rootfs.roothash
# Sign the root hash (uses the same ed25519 key as #4).
openssl pkeyutl -sign -inkey "${SIGNING_KEY}" -rawin -in rootfs.roothash \
    | base64 -w0 > rootfs.roothash.sig
```

Release assets gain:
- `rootfs.verity.zst` — compressed hash tree
- `rootfs.roothash` — hex root hash (single line)
- `rootfs.roothash.sig` — ed25519 signature of the root hash

### Partition layout

Two paths:

1. **Hash tree co-located in slot partition** (preferred). The slot
   partition is sized to hold both the ext4 image AND its hash tree at a
   fixed offset. The kernel cmdline points dm-verity at the same block
   device for both data and hash, with `hash_start_block=<N>`.
2. **Separate hash partitions.** Add ROOT_A_HASH and ROOT_B_HASH
   partitions. Cleaner conceptually, but doubles partition count and
   requires GPT rework.

Recommendation: option 1. The hash tree for a 5 GiB rootfs is roughly
40 MiB, easy to fit at the end of the slot partition. The build emits a
single combined `rootfs.combined.bin` = `rootfs.ext4 || padding ||
rootfs.verity`.

### Installer + update

Install/apply becomes:
```sh
dd if=rootfs.combined.bin of="$SLOT_DEVICE" bs=4M conv=fsync
# Stamp slot label on the ext4 portion (offset 0).
e2label "$SLOT_DEVICE" "DS_ROOT_A"   # still valid; label is in superblock
```

`dayshield-core` at apply time:
1. Download `rootfs.combined.bin.zst`, `rootfs.roothash`, `rootfs.roothash.sig`.
2. Verify signature on roothash against `update_trusted_signers` (the `#4`
   code path already in place).
3. `dd` the combined image to the standby slot.
4. Store the verified `roothash` in `/var/lib/dayshield/rootfs-update/slot-<X>.roothash`.
5. Update GRUB to pass the roothash on the kernel cmdline for that slot
   (see below).

### GRUB + initramfs

GRUB entries for each slot need an additional cmdline parameter:

```
linux  /dayshield/slot-a/vmlinuz \
       root=/dev/dm-0 \
       systemd.verity=1 \
       systemd.verity_root_data=PARTLABEL=DS_ROOT_A \
       systemd.verity_root_hash=PARTLABEL=DS_ROOT_A \
       systemd.verity_root_options=hash_start_block=<N>,panic_on_corruption \
       roothash=<HEX_ROOT_HASH_FROM_/var/lib/dayshield/...> \
       ro
```

systemd's verity generator (`systemd-veritysetup-generator`) reads the
`systemd.verity_*` cmdline arguments and emits a generator unit that
assembles dm-verity before `local-fs.target`.

The roothash itself must be on the kernel cmdline (or, with newer systemd,
in a `roothash=` parameter on the kernel cmdline). It cannot be in the
rootfs because that would be circular.

GRUB cmdline is written by `dayshield-core::rootfs_update::write_grubenv`
at apply time. We add a `slot_a_roothash` / `slot_b_roothash` to grubenv
and reference them in `40_dayshield_slots.cfg`:

```
set roothash=$slot_a_roothash
menuentry 'DayShield slot A' {
    linux /dayshield/slot-a/vmlinuz ... roothash=$roothash ...
}
```

### initramfs

The shipped initramfs already includes systemd; we need to ensure these
modules are present:

- `dm-mod`, `dm-verity` (kernel modules)
- `systemd-veritysetup` and its generator

For Debian, this means adding `cryptsetup-initramfs` (which pulls
`veritysetup` initramfs hooks) and ensuring `/etc/initramfs-tools/modules`
lists `dm-verity`.

In `dayshield-rootfs/scripts/chroot-setup.sh`:

```sh
chroot "${ROOTFS_DIR}" apt-get install -y --no-install-recommends \
    cryptsetup-initramfs
echo "dm-verity" >> "${ROOTFS_DIR}/etc/initramfs-tools/modules"
chroot "${ROOTFS_DIR}" update-initramfs -u -k all
```

### Read-only rootfs implications

Once the slot mounts r/o via dm-verity, every existing path that writes
into the rootfs at runtime breaks:

| Path that gets written today | Phase B fix |
|------------------------------|-------------|
| `/etc/shadow`, `/etc/passwd`, `/etc/group`, `/etc/gshadow` | Move to `/var/lib/dayshield/identity/` + bind-mount over `/etc/<file>` via systemd-tmpfiles or fstab. See the "stateful /etc" section below. |
| `/etc/ssh/ssh_host_*` | `sshd` config `HostKey` directives point at `/var/lib/dayshield/ssh/`. |
| `/etc/machine-id` | systemd already supports `/var/lib/dbus/machine-id` as a writable mirror; ensure it's seeded on first boot. |
| `/etc/hostname` | Same bind-mount pattern as `/etc/shadow`. |
| `/etc/fstab` | Becomes static — only `/var`, `/boot`, `/boot/efi` and `tmpfs` entries, all known at build time. |
| `/etc/resolv.conf` | Symlink to `/run/systemd/resolve/stub-resolv.conf` (default systemd-resolved layout). |
| Any `apt`/dpkg writes | Disabled at runtime. Package management happens only at build time. |
| Suricata rules, CrowdSec state, Kea, Unbound | Already on `/var` from the recent `/etc/dayshield → /var/lib/dayshield` migration. |

**Stateful `/etc` pattern.** A small set of files must remain writable.
Two viable options:

1. **`systemd-confext` overlay**: ship a confext image containing the
   default `/etc` and mount it as an overlay with the upper directory on
   `/var/lib/dayshield/etc/`. systemd-confext is designed for exactly
   this use case.
2. **Per-file bind mounts** declared in `/etc/fstab`:
   ```
   /var/lib/dayshield/identity/shadow    /etc/shadow    none  bind,defaults  0 0
   /var/lib/dayshield/identity/passwd    /etc/passwd    none  bind,defaults  0 0
   ...
   ```
   Each entry is mounted by systemd-fstab-generator after `local-fs.target`.
   The rootfs ship-time `/etc/shadow` becomes a placeholder that is hidden
   by the bind mount.

Recommendation: confext overlay. It's the modern systemd answer to
exactly this problem, and it composes cleanly with sysext for runtime
extensions later.

**First-boot seeding service.** A `dayshield-identity-seed.service`
oneshot:
- `Before=local-fs.target`, `RequiresMountsFor=/var`
- If `/var/lib/dayshield/identity/shadow` does not exist, copy from
  `/usr/share/dayshield/factory/shadow` (a build-time skeleton baked into
  the rootfs).
- Same for passwd, group, gshadow, ssh host keys (generate fresh via
  `ssh-keygen -A -f /var/lib/dayshield/ssh/`).

### Update flow under verity

`apply_staged_image` becomes:

```rust
// 1. Verify ed25519 signature on roothash (using #4 code path).
let roothash = verify_and_load_roothash(&signed_roothash, &trusted_signers)?;

// 2. Sanity-check the combined image hashes to the roothash before writing.
//    veritysetup --root-hash-file=- verify rootfs.combined.bin <roothash>
verify_combined_image(&combined_image, &roothash).await?;

// 3. Block-level write to standby slot.
dd_to_slot(&combined_image, target_slot).await?;

// 4. Persist roothash for GRUB to pick up.
fs::write(roothash_path_for(target_slot), &roothash)?;

// 5. Update GRUB cmdline via grub-editenv set slot_<x>_roothash=<value>.
grubenv_set(&format!("{}_roothash", target_slot.short()), &roothash).await?;

// 6. Existing boot-counter + slot-switch logic.
```

No more IDENTITY_PATHS copy step — `/etc` identity lives on `/var`,
already shared.

### Acceptance criteria (Phase B)

- [ ] Build emits deterministic `rootfs.combined.bin` and signed roothash.
- [ ] Tampering with a single byte of `rootfs.combined.bin` post-write
      causes the slot to fail to mount (kernel I/O error in `dmesg`).
- [ ] `/etc/shadow` change persists across an A→B→A rollback cycle (proves
      bind-mount or confext is working).
- [ ] Boot time does not regress more than 2s vs Phase A (verity adds
      hash-tree page-in latency on cold cache).
- [ ] Auto-revert still works: arming `boot_state=trying` then forcing a
      boot failure on the new slot results in revert to the old slot.

### Risks (Phase B)

- **Brickable.** If the GRUB cmdline / initramfs / roothash chain is
  wrong, the appliance loops on boot failure into auto-revert, but if
  BOTH slots get a broken verity setup (e.g., a bad
  `chroot-setup.sh` change that bakes a non-verity-capable initramfs into
  both slots), the only recovery is reinstall via ISO. **Mitigation:**
  ship Phase B as a single coordinated release; never let `apply_update`
  push a verity-capable image to a slot whose GRUB cmdline doesn't yet
  carry the `roothash=` parameter.
- **Kernel/initramfs size grows.** dm-verity module + cryptsetup hooks
  add a few MB to initrd. Boot partition must accommodate this for both
  slots' kernel directories.
- **Hash tree on slot partition wastes space.** ~40 MiB per slot of
  partition capacity is consumed by hash data. Acceptable for 5 GiB slots.

### Testing plan

1. Build pipeline change validated by comparing build outputs across two
   machines; SHA256 must match.
2. dd-from-image install validated in a VM (qemu) with the GRUB cmdline
   manually constructed.
3. Boot-corruption test: after install, deliberately overwrite a 4 KiB
   block in the middle of the slot; verify boot fails fast and revert
   triggers.
4. Hardware validation: at least one full update + boot cycle on the
   reference appliance before promoting the feature to default.

---

## File touch list (when these phases ship)

**Phase A:**
- `dayshield-rootfs/scripts/build-rootfs.sh` — emit ext4 image
- `dayshield-rootfs/.github/workflows/build-release.yml` — publish new
  artifacts
- `dayshield-installer-ui/installer-ui/api/install-rootfs.sh` — switch
  from `extract_rootfs` to `dd`
- `dayshield-iso/config/installer/install.sh` — same
- `dayshield-core/dayshield-core/src/rootfs_update.rs` — same in
  `apply_staged_image`

**Phase B (in addition):**
- `dayshield-rootfs/scripts/build-rootfs.sh` — `veritysetup format` step
- `dayshield-rootfs/scripts/chroot-setup.sh` — install
  `cryptsetup-initramfs`, ship factory `/etc` under
  `/usr/share/dayshield/factory/`, set up confext or bind-mount fstab,
  add `dayshield-identity-seed.service`
- `dayshield-rootfs/config/services/dayshield-identity-seed.service` — new
- `dayshield-installer-ui/installer-ui/api/install-bootloader.sh` — emit
  `roothash` in grubenv and GRUB menuentries
- `dayshield-installer-ui/installer-ui/api/install-rootfs.sh` — write
  combined image, persist roothash
- `dayshield-iso/config/installer/install.sh` — same
- `dayshield-core/dayshield-core/src/rootfs_update.rs` — verify roothash
  signature, drop IDENTITY_PATHS copy (no longer needed)
- `dayshield-core/dayshield-core/src/update.rs` — fetch `.verity.zst`,
  `.roothash`, `.roothash.sig` assets

## Out of scope

- **Sysext for runtime extension delivery.** Once verity + confext are in
  place, this becomes available essentially for free. Not part of this
  doc.
- **Secure Boot / shim.** A separate axis from dm-verity. dm-verity
  protects rootfs integrity at runtime; Secure Boot protects the
  bootloader and kernel signing chain. Phase B does not enable Secure
  Boot.
- **A/B for the kernel + initrd themselves.** Today both slots' kernels
  live under `/boot/dayshield/slot-{a,b}/`. That's already correct and
  unchanged by either phase.
