# Quick Start: GitHub Releases Update System

## TL;DR

**No build tools on appliance anymore!** Components are prebuilt and resolved by appliances from a central manifest.

## One-Time Setup

### 1. Enable GitHub Actions (if not already)

In `.github/workflows/release-artifacts.yml` (or your equivalent pipelines):
- Components can be built/published independently
- Central `manifest.json` is updated with latest artifact pointers per component

### 2. Publish first manifest-backed artifacts

```bash
# Publish artifact(s) from component repo(s), then publish manifest.json
# with core/ui/rootfs entries that include version/url/checksum.
```

You should have a manifest similar to:
- `core` entry (independent version/tag)
- `ui` entry (independent version/tag)
- `rootfs` entry (independent version/tag)
- top-level `generatedAt`

## Appliance Update (User/Admin)

### Via Web Console

1. Go to **System** > **Updates**
2. Click **Check for Updates** -> Reads manifest and shows per-component availability
3. Click **Apply Runtime Updates** -> Downloads and applies core/UI atomically
4. If all OK -> Shows success
5. If any service fails -> Auto-rollback to previous version
6. If rootfs changed, click **Stage Rootfs Update** -> writes inactive root slot and schedules a one-shot trial boot
7. Reboot to trial the new rootfs; DayShield confirms it after service health checks or schedules rollback to the previous slot

### Via API

```bash
# Check
curl -X POST https://192.168.50.1:8443/system/updates/check \
  -H "Authorization: Bearer $TOKEN"

# Apply runtime artifacts
curl -X POST https://192.168.50.1:8443/system/updates/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"component":"both","forcePartialApply":false}'

# Stage rootfs into inactive A/B slot
curl -X POST https://192.168.50.1:8443/system/updates/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"component":"rootfs","forcePartialApply":false}'

# Result: Runtime components are updated atomically or none are changed
```

## Configuration

### Default (Manifest Registry - Recommended)

Already configured in code. In `updates_settings.json`:
```json
{
  "autoCheckEnabled": true,
  "checkIntervalMinutes": 60,
  "updateMode": "registry",
  "registryUrl": "https://updates.example.com/manifest.json",
  "verifyArtifactSignatures": true
}
```

**Note**: You may still point at a GitHub API repo URL if that repo publishes `manifest.json`:
```json
{
  "registryUrl": "https://api.github.com/repos/daygle/dayshield-core"
}
```

### Fallback (Git-Based - Legacy)

If GitHub is unavailable or you prefer git:
```json
{
  "updateMode": "git",
  "coreRepoUrl": "https://github.com/daygle/dayshield-core",
  "uiRepoUrl": "https://github.com/daygle/dayshield-ui",
  "rootfsRepoUrl": "https://github.com/daygle/dayshield-rootfs"
}
```

## Release Schedule

### Monthly Release

```bash
# 1st of each month, create release
VERSION="2026.$(date +%m).01"
git tag "v${VERSION}"
git push origin "v${VERSION}"
```

### On-Demand Release

```bash
git tag "v1.2.4"
git push origin "v1.2.4"
```

Pipelines update artifacts and publish a new manifest. Appliances auto-discover on next check.

## Deployment Options

| Approach | Pros | Cons |
|----------|------|------|
| **GitHub Releases (NEW)** | No build tools on appliance, atomic updates, automatic discovery | Depends on GitHub availability |
| **Git Repos (Legacy)** | Self-hosted possible, no GitHub dependency | Requires cargo/npm on appliance, slower |
| **Hybrid** | Best of both, fallback support | More complex |

**Recommended**: Use GitHub Releases as primary, git as fallback.

## Troubleshooting

### Appliance shows "No updates available"

Check if manifest is reachable:
```bash
curl -s https://updates.example.com/manifest.json | jq
```

If missing expected entries, republish artifacts and regenerate manifest.

### Update failed - can't reach GitHub

Appliance automatically falls back to git-based updates:
```json
{
  "updateMode": "git"
}
```

### Checksum mismatch error

Release artifacts were corrupted during upload. Re-run workflow:
1. Delete the problematic release
2. Re-push the tag:
```bash
git tag -d v1.0.1
git push origin :v1.0.1
git tag v1.0.1
git push origin v1.0.1
```

## See Also

- [Full Documentation](UPDATE_SYSTEM.md) - Complete architecture guide
- [GitHub Actions Workflow](.github/workflows/release-artifacts.yml) - CI/CD pipeline
- [Update API](dayshield-core/src/api/system.rs) - HTTP endpoints
