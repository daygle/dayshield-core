# DayShield Update System - GitHub Releases Architecture

## Overview

The redesigned update system eliminates the need for build tools (cargo, npm) on the production appliance. All components are prebuilt and hosted on GitHub Releases, which the appliance downloads and applies atomically.

## Architecture

### Components

1. **CI/Build Pipeline** (GitHub Actions)
   - Builds core binary via `cargo build --release`
   - Builds UI dist via `npm run build`
   - Builds rootfs image via shell scripts
   - Creates `.tar.zst` artifacts for each component
   - Generates SHA256 checksums
   - Uploads to GitHub Releases

2. **Artifact Storage** (GitHub Releases)
   - Registry: `https://api.github.com/repos/daygle/dayshield-core` (or use any repo)
   - Release format: `v1.2.3` semantic versioning
   - Assets: `core-v1.2.3.tar.zst`, `ui-v1.2.3.tar.zst`, `rootfs-v1.2.3.tar.zst`, `checksums.txt`

3. **Appliance Update Engine** (dayshield-core)
   - Default mode: `registry` (automatic)
   - Default registry: GitHub Releases API
   - Fetches latest release via `GET /repos/{owner}/{repo}/releases/latest`
   - Downloads artifacts to `/var/lib/dayshield/update-staging/{transaction-id}/`
   - Verifies SHA256 checksums
   - Applies runtime artifacts atomically (core/UI all or nothing)
   - Stages rootfs artifacts into the inactive A/B slot when the appliance layout supports it
   - Verifies services health
   - Records runtime versions, rootfs slot state, and confirmed rootfs image baselines

## Setup

### 1. Create Release Repository

Option A: Use existing `dayshield-core` repository
```bash
# In dayshield-core repo
git tag v1.0.0
git push origin v1.0.0
# GitHub Actions workflow triggers automatically
```

Option B: Create dedicated release repository
```bash
git clone https://github.com/<org>/<release-repo>.git
cd <release-repo>
# No code needed, only workflows and releases
```

### 2. Configure GitHub Actions Workflow

The `.github/workflows/release-artifacts.yml` workflow:
- Triggers on tag push (`git tag v1.2.3 && git push origin v1.2.3`)
- Builds all three components in parallel (or sequence)
- Generates checksums
- Creates GitHub Release with all artifacts attached
- Automatically accessible via GitHub Releases API

### 3. Configure Appliance

Default configuration automatically uses GitHub Releases. Update settings:

```json
{
  "updateMode": "registry",
  "registryUrl": "https://api.github.com/repos/daygle/dayshield-core"
}
```

Alternative: Use git-based updates (legacy fallback)
```json
{
  "updateMode": "git",
  "coreRepoUrl": "https://github.com/daygle/dayshield-core",
  "uiRepoUrl": "https://github.com/daygle/dayshield-ui",
  "rootfsRepoUrl": "https://github.com/daygle/dayshield-rootfs"
}
```

## Release Process

### Manual Release (one-time)

```bash
# In any of the dayshield-* repos
git tag v1.2.3
git push origin v1.2.3

# GitHub Actions automatically:
# 1. Checks out dayshield-core, dayshield-ui, dayshield-rootfs
# 2. Builds core: cargo build --release
# 3. Builds ui: npm ci && npm run build
# 4. Builds rootfs: shell scripts
# 5. Creates artifacts: core-v1.2.3.tar.zst, etc.
# 6. Generates checksums.txt
# 7. Creates GitHub Release with all assets
# 8. Appliance discovers via GitHub Releases API
```

### Automated Release (recommended)

Create a scheduled workflow or integrate with your CI/CD:

```bash
#!/bin/bash
# scripts/release.sh

VERSION=$(date +%Y.%m.%d)
git tag "v${VERSION}"
git push origin "v${VERSION}"
echo "Released v${VERSION}"
```

## Appliance Update Flow

### Check for Updates

1. User clicks "Check for Updates" in web console
2. Appliance queries: `GET https://api.github.com/repos/daygle/dayshield-core/releases/latest`
3. Parses response to find:
   - `core-v*.tar.zst`
   - `ui-v*.tar.zst`
   - `rootfs-v*.tar.zst`
   - `checksums.txt`
4. Displays runtime updates for core/UI and rootfs A/B slot readiness

### Apply Runtime Updates (Atomic Transaction)

```
User clicks "Apply Runtime Updates"
    |
Create transaction ID: /var/lib/dayshield/update-staging/{transaction-id}/
    |
Download phase:
  - GET {release_url}/core-v1.2.4.tar.zst
  - GET {release_url}/ui-v1.2.4.tar.zst
  - GET {release_url}/checksums.txt
    |
Verify phase:
  - SHA256 each artifact against checksums.txt
  - If any fails -> abort (no changes)
    |
Backup phase:
  - Snapshot current /usr/local/sbin/dayshield-core
  - Snapshot current /usr/local/share/dayshield-ui/
    |
Deploy phase:
  - Extract core-v1.2.4.tar.zst -> deploy to /usr/local/sbin/dayshield-core
  - Extract ui-v1.2.4.tar.zst -> deploy to /usr/local/share/dayshield-ui/
    |
Health check phase:
  - Verify systemctl is-active dayshield.service
  - Verify systemctl is-active nftables.service
  - Verify systemctl is-active unbound.service
  - If any unhealthy -> rollback from backups
    |
Finalize:
  - Mark transaction complete
  - Update state: current_version = 1.2.4
  - Cleanup staging dir
```

### Apply Rootfs Updates (A/B Slot Transaction)

New installs use an A/B root layout:

- `DAYSHIELD_BOOT` mounted at `/boot`
- `DAYSHIELD_ROOT_A` mounted as the active `/`
- `DAYSHIELD_ROOT_B` kept as the inactive root slot

When `rootfs-vX.Y.Z.tar.zst` is available, the updater:

1. Downloads and verifies the rootfs artifact.
2. Formats the inactive root slot with its stable slot label.
3. Extracts the rootfs artifact into the inactive slot.
4. Copies persistent appliance state into the inactive slot (`/etc/dayshield`, `/var/lib/dayshield`, WireGuard, Cloudflared, host identity, SSH host keys, and network state).
5. Writes the inactive slot fstab for `/`, `/boot`, and `/boot/efi`.
6. Copies the inactive slot kernel/initrd into `/boot/dayshield/slot-{a,b}/`.
7. Regenerates GRUB entries `dayshield-a` and `dayshield-b`.
8. Runs `grub-reboot` for a one-shot trial boot into the new slot.
9. On the next boot, DayShield waits for critical service health, then runs `grub-set-default` to confirm the slot.
10. If health confirmation fails while DayShield is running, it schedules the previous slot and reboots. The rootfs image also includes a small systemd watchdog that reboots to the previous slot if confirmation never happens.

Single-root appliances cannot use in-place rootfs updates. They will continue to show a rebuild/reinstall requirement until migrated to the A/B partition layout.

## Release Checklist

- [ ] Update version in `Cargo.toml` (core)
- [ ] Update version in `package.json` (ui)
- [ ] Update version in rootfs build config
- [ ] Commit changes to all repos
- [ ] Tag with `v{VERSION}`
- [ ] Push tag: `git push origin v{VERSION}`
- [ ] Wait for GitHub Actions to complete
- [ ] Verify release assets on GitHub
- [ ] Verify checksums are present
- [ ] Announce release to users

## Troubleshooting

### Release Build Failed

Check GitHub Actions logs:
```
GitHub > Actions > release-artifacts > View run
```

Common issues:
- Node.js version mismatch (use 18+)
- Missing apt packages (cargo, node)
- Insufficient disk space

### Appliance Update Failed

Check appliance logs:
```bash
root@dayshield:~# journalctl -u dayshield.service -n 50
# Look for error in update transaction
```

Common issues:
- Network unreachable (can't reach GitHub)
- Checksum mismatch (corrupted download)
- Disk full (no space to extract artifacts)
- Service health check failed (rollback triggered)

### Rollback After Failed Update

Automatic: If any service health check fails, automatically rolls back from backups.

Manual: If appliance is in bad state:
```bash
root@dayshield:~# systemctl restart dayshield.service
# Check if service recovers

# Or apply via git (fallback):
export DAYSHIELD_UPDATE_MODE=git
systemctl restart dayshield.service
```

## Fallback to Git-Based Updates

If GitHub is unavailable:
```json
{
  "updateMode": "git",
  "coreRepoUrl": "https://github.com/daygle/dayshield-core",
  "uiRepoUrl": "https://github.com/daygle/dayshield-ui"
}
```

Appliance will use existing git repos in `/opt/dayshield-*/` instead of downloading prebuilt artifacts.

## API Endpoints

- `GET /system/updates/status` - Get current versions + available updates
- `GET /system/updates/settings` - View update configuration
- `PUT /system/updates/settings` - Change registry URL / update mode
- `POST /system/updates/check` - Force check against registry
- `POST /system/updates/apply` - Download and apply runtime updates atomically
- `POST /system/updates/rollback` - Revert to previous versions (if available)

## Security Considerations

- SHA256 checksums verify artifact integrity
- GitHub HTTPS ensures transport security
- Atomic transactions prevent partial/corrupted updates
- Service health checks catch broken deployments
- Automatic rollback protects against bad updates
- No build tools = reduced attack surface on appliance

## Future Enhancements

1. **GPG Signatures** - Sign artifacts with release key
2. **Update Scheduling** - Schedule updates during maintenance windows
3. **A/B Rootfs Updates** - Add inactive-root deployment with boot-health rollback
4. **Staged Rollout** - Deploy to subset of appliances first
5. **Differential Updates** - Only download changed components
6. **Version Pinning** - Lock to specific version instead of latest
