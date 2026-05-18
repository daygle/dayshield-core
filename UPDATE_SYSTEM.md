# DayShield Update System - Manifest-Driven Registry Architecture

## Overview

DayShield updates are manifest-first. The updater consumes a central `manifest.json` that tracks the latest published artifact for each component (`core`, `ui`, `rootfs`) independently.

This supports **Option B**:
- independent repos/tags/versions for `dayshield-core`, `dayshield-ui`, and `dayshield-rootfs`
- component-by-component update discovery
- runtime (`core`/`ui`) atomic apply
- rootfs A/B staging as a separate transaction

## Architecture

1. **Component build/publish pipelines**
   - `dayshield-core`, `dayshield-ui`, `dayshield-rootfs` can publish independently
   - each component artifact has its own version/tag cadence

2. **Central manifest registry**
   - updater reads `manifest.json` as the primary source of truth
   - each component entry includes:
     - `component`
     - `version`
     - `downloadUrl`
     - `checksumSha256`
     - optional `signatureUrl`
     - optional source metadata (`sourceRepo`, `sourceTag`, `sourceReleaseUrl`)
   - top-level field: `generatedAt`

3. **Appliance update engine (`dayshield-core`)**
   - default mode: `registry`
   - checks central manifest first
   - GitHub release parsing is retained as a backward-compatible fallback path
   - missing component entries are treated as "not published", not hard errors
   - runtime updates (`core`/`ui`) stay atomic
   - rootfs updates stay separate and staged into inactive A/B slot

## Example manifest

```json
{
  "generatedAt": "2026-05-18T11:00:00Z",
  "components": [
    {
      "component": "core",
      "version": "1.4.2",
      "downloadUrl": "https://github.com/daygle/dayshield-core/releases/download/v1.4.2/core-v1.4.2.tar.zst",
      "checksumSha256": "...",
      "signatureUrl": "https://github.com/daygle/dayshield-core/releases/download/v1.4.2/core-v1.4.2.tar.zst.sig",
      "sourceRepo": "daygle/dayshield-core",
      "sourceTag": "v1.4.2",
      "sourceReleaseUrl": "https://github.com/daygle/dayshield-core/releases/tag/v1.4.2"
    },
    {
      "component": "ui",
      "version": "2.1.0",
      "downloadUrl": "https://github.com/daygle/dayshield-ui/releases/download/v2.1.0/ui-v2.1.0.tar.zst",
      "checksumSha256": "...",
      "sourceRepo": "daygle/dayshield-ui",
      "sourceTag": "v2.1.0"
    },
    {
      "component": "rootfs",
      "version": "2026.05.10",
      "downloadUrl": "https://github.com/daygle/dayshield-rootfs/releases/download/v2026.05.10/rootfs-v2026.05.10.tar.zst",
      "checksumSha256": "...",
      "sourceRepo": "daygle/dayshield-rootfs",
      "sourceTag": "v2026.05.10"
    }
  ]
}
```

## Appliance update flow

### Check for updates

1. User triggers check (`/system/updates/check`)
2. Updater fetches manifest and compares local vs remote version per component
3. `core`, `ui`, and `rootfs` availability is evaluated independently
4. Components omitted from manifest are simply treated as unavailable

### Apply runtime updates (atomic)

- runtime apply target is `both` (`core` + `ui`)
- if runtime artifacts are selected and present, they are downloaded/verified/applied atomically
- post-apply service health checks still gate success
- rollback behavior remains unchanged

### Apply rootfs updates (A/B staged)

- rootfs update is always separate from runtime apply
- updater stages rootfs artifact into inactive slot
- schedules one-shot boot to trial slot
- confirms or rolls back based on health

Single-root appliances still show rebuild required for rootfs updates.

## Configuration

Use registry mode with a manifest URL (or a GitHub API repo URL that hosts `manifest.json` at repo root):

```json
{
  "updateMode": "registry",
  "registryUrl": "https://updates.example.com/manifest.json"
}
```

Git-based mode remains available as fallback.

## Release checklist (Option B)

- [ ] Publish updated artifact(s) from the component repo(s)
- [ ] Generate SHA256 checksums
- [ ] Update central `manifest.json` with latest per-component entries
- [ ] Verify `generatedAt` and component metadata
- [ ] Verify appliance check/apply behavior

## Troubleshooting

### No updates shown

Validate manifest contents and URLs:

```bash
curl -s https://updates.example.com/manifest.json | jq
```

### Checksum mismatch

- recompute artifact SHA256
- update `checksumSha256` in manifest
- republish manifest atomically

### Registry unavailable

Switch to git-based updates temporarily:

```json
{
  "updateMode": "git",
  "coreRepoUrl": "https://github.com/daygle/dayshield-core",
  "uiRepoUrl": "https://github.com/daygle/dayshield-ui",
  "rootfsRepoUrl": "https://github.com/daygle/dayshield-rootfs"
}
```
