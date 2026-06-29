#!/bin/sh
# Best-effort runtime hardening applied before the hub starts, then exec the hub.
#
# Both steps need a Linux capability the container may not have been granted; if
# so we log and continue rather than refuse to start, so a plain `docker run`
# still works (the in-app argv lint and per-user UID sandbox remain in force
# regardless). Grant CAP_SYS_ADMIN (hidepid) and CAP_NET_ADMIN (egress) to
# enable them — e.g. compose `cap_add:` or k8s `securityContext.capabilities`.
set -eu

log() { echo "entrypoint: $*" >&2; }

# --- 1. Hide other UIDs' /proc entries (closes the argv-via-/proc leak) -------
# hidepid=2 makes a process unable to even see another UID's /proc/<pid>, so a
# sandbox UID can't read another user's backend cmdline/environ/fd. Root (the
# hub) still sees everything.
if [ "${HUB_HIDEPID:-1}" != "0" ]; then
    if mount -o remount,hidepid=2 /proc 2>/dev/null; then
        log "remounted /proc with hidepid=2"
    else
        log "could not remount /proc with hidepid=2 (needs CAP_SYS_ADMIN); skipping"
    fi
fi

# --- 2. Restrict sandbox-UID network egress -----------------------------------
# Drop, for sandbox UIDs only (skuid >= HUB_SANDBOX_UID_BASE), traffic to
# link-local/cloud-metadata and to the hub's own listen port on loopback.
# Everything else — including RFC1918 — stays allowed so internal backends keep
# working. The hub itself (root / low UIDs) is never restricted.
if [ "${HUB_EGRESS_HARDENING:-1}" != "0" ]; then
    base="${HUB_SANDBOX_UID_BASE:-20000}"
    # Port is the trailing :PORT of HUB_LISTEN (default 0.0.0.0:8080).
    port="$(printf '%s' "${HUB_LISTEN:-0.0.0.0:8080}" | sed 's/.*://')"
    case "$port" in ''|*[!0-9]*) port=8080 ;; esac

    if command -v nft >/dev/null 2>&1; then
        if nft -f - <<EOF 2>/dev/null
table inet hub_egress {
    chain output {
        type filter hook output priority 0; policy accept;
        # The hub and system UIDs are never restricted.
        meta skuid < $base accept
        # Cloud metadata / link-local.
        ip daddr 169.254.0.0/16 drop
        ip6 daddr fe80::/10 drop
        ip6 daddr fd00:ec2::254 drop
        # The hub's own web/OAuth surface on loopback.
        ip daddr 127.0.0.0/8 tcp dport $port drop
        ip6 daddr ::1 tcp dport $port drop
    }
}
EOF
        then
            log "installed sandbox-UID egress rules (skuid >= $base; metadata + loopback:$port blocked)"
        else
            log "could not load nftables egress rules (needs CAP_NET_ADMIN); skipping"
        fi
    else
        log "nft not found; skipping egress hardening"
    fi
fi

exec /usr/local/bin/mcp_hub "$@"
