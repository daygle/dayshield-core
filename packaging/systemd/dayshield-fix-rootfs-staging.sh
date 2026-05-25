#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/dayshield-update-fixer.log
LOCK=/var/lock/dayshield-fix-rootfs.lock
STAGING_DIR=/var/lib/dayshield/update-staging
TARGET_DIR=/var/lib/dayshield/update/rootfs-slot/b/boot
TMPDIR=$(mktemp -d /tmp/dsf-XXXXXX)

log() { echo "$(date -Is) $*" | tee -a "$LOG"; }

# locking to avoid races with updater
exec 9>"$LOCK"
if ! flock -n 9; then
  log "Another instance running; exiting."
  exit 0
fi

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# find latest staged rootfs archive
archive=$(ls -1t "$STAGING_DIR"/*/rootfs-*.tar.zst 2>/dev/null | head -n1 || true)
if [ -z "$archive" ]; then
  log "No staged rootfs archive found in $STAGING_DIR."
  exit 0
fi
log "Using archive: $archive"

# detect kernel name inside archive
vmlinuz_path=$(tar -I zstd -tf "$archive" 2>/dev/null | awk -F/ '/^boot\/vmlinuz/ {print; exit}')
if [ -z "$vmlinuz_path" ]; then
  log "Archive does not contain boot/vmlinuz entry; nothing to do."
  exit 0
fi
vmlinuz_name=$(basename "$vmlinuz_path")

# if target already has kernel, nothing to do
if [ -f "$TARGET_DIR/$vmlinuz_name" ]; then
  log "Target already contains $vmlinuz_name — nothing to do."
  exit 0
fi

# quick free-space check (on same fs as target dir)
avail_kb=$(df --output=avail "$(dirname "$TARGET_DIR")" | tail -1 | tr -d ' ')
if [ -z "$avail_kb" ]; then avail_kb=0; fi
min_kb=5120
if [ "$avail_kb" -lt "$min_kb" ]; then
  log "Insufficient free space on target FS ($avail_kb KB). Aborting."
  exit 1
fi

# Extract only boot/ to temp, preserving ownership/perm when possible
mkdir -p "$TMPDIR/boot"
if tar -I zstd -xf "$archive" -C "$TMPDIR" --wildcards 'boot/*' 2>>"$LOG"; then
  log "Extracted boot/ to $TMPDIR"
else
  log "Failed extracting boot/ from $archive"
  exit 1
fi

# Ensure destination exists and has safe perms
mkdir -p "$TARGET_DIR"
chown root:root "$(dirname "$TARGET_DIR")" || true

# copy atomically using rsync if available, else cp
if command -v rsync >/dev/null 2>&1; then
  rsync -a --chmod=Du=rwx,Dg=rx,Do=rx,Fu=rw,Fg=r,Fo=r "$TMPDIR/boot/" "$TARGET_DIR/" 2>>"$LOG" || {
    log "rsync failed"
    exit 1
  }
else
  cp -a "$TMPDIR/boot/." "$TARGET_DIR/" 2>>"$LOG" || {
    log "cp failed"
    exit 1
  }
fi

sync
log "Copied boot files to $TARGET_DIR (including $vmlinuz_name)."
