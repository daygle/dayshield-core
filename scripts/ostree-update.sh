#!/bin/sh
# ostree-update.sh — DayShield system image update helper
#
# Fetches rootfs OSTree repo artifacts from GitHub Releases and applies them
# via 'ostree pull-local', avoiding the need for a hosted OSTree HTTP server.
#
# Actions: status | check | stage | apply | rollback
#
# Environment (all optional):
#   DAYSHIELD_GITHUB_REPO   GitHub repo for rootfs releases  (default: daygle/dayshield-rootfs)
#   DAYSHIELD_OSTREE_OS     OSTree OS name                   (default: dayshield)
#   DAYSHIELD_OSTREE_REF    OSTree ref to pull               (default: dayshield/<arch>)

set -eu

GITHUB_REPO="${DAYSHIELD_GITHUB_REPO:-daygle/dayshield-rootfs}"
OSTREE_OS="${DAYSHIELD_OSTREE_OS:-dayshield}"
OSTREE_SYSROOT="${DAYSHIELD_OSTREE_SYSROOT:-/sysroot}"
OSTREE_REPO="${OSTREE_SYSROOT}/ostree/repo"
OSTREE_DEPLOY="${OSTREE_SYSROOT}/ostree/deploy"
BUILD_MANIFEST="/usr/local/share/dayshield-updates/ostree-build-manifest.json"

# Derive architecture for the default OSTree ref
_arch="$(uname -m)"
case "${_arch}" in
    x86_64)  _arch="amd64" ;;
    aarch64) _arch="arm64" ;;
    armv7l)  _arch="armhf" ;;
esac
OSTREE_REF="${DAYSHIELD_OSTREE_REF:-dayshield/${_arch}}"

action="${1:-status}"

# ── Helpers ──────────────────────────────────────────────────────────────────

_wget_github_api() {
    wget -q -O - \
        --header "Accept: application/vnd.github+json" \
        --header "X-GitHub-Api-Version: 2022-11-28" \
        "$1"
}

# Extract a simple string field from JSON ("field": "value")
_json_str() {
    printf '%s' "$1" \
        | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 \
        | sed 's/.*:[[:space:]]*"\(.*\)"/\1/'
}

# Version recorded in the build manifest embedded in this rootfs image
_installed_version() {
    if [ -f "${BUILD_MANIFEST}" ]; then
        _json_str "$(cat "${BUILD_MANIFEST}")" "version"
    fi
}

# Print a normalized OSTree admin status payload. Fresh or partially
# bootstrapped installs may not have an ostree/deploy directory yet; treat that
# as a valid "no deployments yet" state instead of surfacing a sysroot error.
_status_output() {
    if [ ! -d "${OSTREE_REPO}" ] || [ ! -d "${OSTREE_DEPLOY}" ]; then
        printf 'No deployments.\n'
        return 0
    fi

    status_out="$(ostree admin --sysroot="${OSTREE_SYSROOT}" status 2>&1)" || {
        case "${status_out}" in
            *"fstatat(ostree/deploy)"*|*"opendir(objects)"*)
                printf 'No deployments.\n'
                return 0
                ;;
        esac
        printf '%s\n' "${status_out}" >&2
        return 1
    }

    printf '%s\n' "${status_out}"
}

# Ensure the target sysroot has enough OSTree layout for the first deployment.
_ensure_sysroot_layout() {
    mkdir -p "${OSTREE_DEPLOY}" "${OSTREE_REPO}"

    if [ ! -f "${OSTREE_REPO}/config" ]; then
        ostree --repo="${OSTREE_REPO}" init --mode=bare
    fi

    if [ ! -d "${OSTREE_DEPLOY}/${OSTREE_OS}" ]; then
        ostree admin --sysroot="${OSTREE_SYSROOT}" os-init "${OSTREE_OS}"
    fi
}

# Perform the initial (no prior deployments) ostree deploy, passing through
# kernel args from /proc/cmdline.  --karg-proc is not supported on all ostree
# builds, so we expand /proc/cmdline into individual --karg= flags instead.
_initial_deploy() {
    set --
    while IFS= read -r _karg; do
        [ -n "${_karg}" ] && set -- "$@" "--karg=${_karg}"
    done << _KARGS_
$(tr ' ' '\n' < /proc/cmdline)
_KARGS_
    ostree admin --sysroot="${OSTREE_SYSROOT}" deploy \
        --os="${OSTREE_OS}" \
        "$@" \
        "${OSTREE_REF}"
}

# True if at least one OSTree deployment exists
_has_deployments() {
    status="$(_status_output 2>/dev/null || true)"
    case "${status}" in
        "No deployments."*|"") return 1 ;;
        *) return 0 ;;
    esac
}

# Cleanup temp dir on exit
_WORK_DIR=""
_cleanup() { [ -z "${_WORK_DIR}" ] || rm -rf "${_WORK_DIR}"; }
trap _cleanup EXIT INT TERM

# ── Actions ──────────────────────────────────────────────────────────────────

case "${action}" in

    status)
        _status_output
        ;;

    check)
        installed="$(_installed_version)"
        printf 'Installed version : %s\n' "${installed:-unknown}"

        release_json="$(_wget_github_api \
            "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")"
        latest_tag="$(_json_str "${release_json}" "tag_name")"

        if [ -z "${latest_tag}" ]; then
            printf 'ERROR: could not resolve latest release from %s\n' "${GITHUB_REPO}" >&2
            exit 1
        fi

        printf 'Latest available  : %s\n' "${latest_tag}"

        if [ -n "${installed}" ] && [ "${installed}" = "${latest_tag}" ]; then
            printf 'System image is up to date.\n'
        else
            printf 'System image update available: %s -> %s\n' \
                "${installed:-unknown}" "${latest_tag}"
        fi
        ;;

    stage|apply)
        # Resolve latest release
        release_json="$(_wget_github_api \
            "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")"
        latest_tag="$(_json_str "${release_json}" "tag_name")"

        if [ -z "${latest_tag}" ]; then
            printf 'ERROR: could not resolve latest release from %s\n' "${GITHUB_REPO}" >&2
            exit 1
        fi

        artifact="rootfs-${latest_tag}-ostree-repo.tar.zst"
        base_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_tag}"

        # Work directory (persistent storage preferred over tmpfs for 300+ MB download)
        mkdir -p /var/lib/dayshield-updates 2>/dev/null || true
        _WORK_DIR="$(mktemp -d /var/lib/dayshield-updates/ostree-update.XXXXXX \
                        2>/dev/null \
                    || mktemp -d)"
        artifact_path="${_WORK_DIR}/${artifact}"
        extract_dir="${_WORK_DIR}/src"

        printf 'Downloading %s ...\n' "${artifact}"
        wget -q --show-progress -O "${artifact_path}" "${base_url}/${artifact}"
        printf 'Download complete.\n'

        # Verify SHA256 (best-effort; skip if checksum asset is absent)
        if wget -q -O "${artifact_path}.sha256" \
                "${base_url}/${artifact}.sha256" 2>/dev/null; then
            expected="$(awk '{print $1}' "${artifact_path}.sha256")"
            actual="$(sha256sum "${artifact_path}" | awk '{print $1}')"
            if [ "${expected}" != "${actual}" ]; then
                printf 'ERROR: SHA256 mismatch for %s\n' "${artifact}" >&2
                printf '  expected : %s\n' "${expected}" >&2
                printf '  actual   : %s\n' "${actual}" >&2
                exit 1
            fi
            printf 'SHA256 verified: %s\n' "${expected}"
        else
            printf 'WARNING: checksum file unavailable; skipping verification.\n'
        fi

        # Extract the archive-z2 OSTree repo
        printf 'Extracting OSTree repo ...\n'
        mkdir -p "${extract_dir}"
        tar -I 'zstd -d' -xf "${artifact_path}" -C "${extract_dir}"
        printf 'Extraction complete.\n'

        _ensure_sysroot_layout

        # Pull the ref into the sysroot OSTree repo (writable; /ostree/repo is
        # part of the immutable deployment checkout and is read-only at runtime).
        printf 'Pulling %s into %s ...\n' "${OSTREE_REF}" "${OSTREE_REPO}"
        ostree pull-local --repo="${OSTREE_REPO}" "${extract_dir}" "${OSTREE_REF}"
        printf 'Pull complete.\n'

        # Stage the deployment (initial deploy or upgrade)
        if _has_deployments; then
            printf 'Staging upgrade for %s ...\n' "${OSTREE_OS}"
            ostree admin --sysroot="${OSTREE_SYSROOT}" deploy \
                --os="${OSTREE_OS}" \
                --retain-rollback \
                "${OSTREE_REF}"
        else
            printf 'Creating initial deployment for %s ...\n' "${OSTREE_OS}"
            _initial_deploy
        fi
        printf 'Deployment staged. Reboot to activate the new image.\n'
        ;;

    rollback)
        exec ostree admin --sysroot="${OSTREE_SYSROOT}" rollback --os="${OSTREE_OS}"
        ;;

    *)
        printf 'Usage: %s [status|check|stage|apply|rollback]\n' "$0" >&2
        exit 1
        ;;
esac
