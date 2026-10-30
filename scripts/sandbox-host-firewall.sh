#!/usr/bin/env bash
# Keep sandboxes from reaching services on the Docker host.
#
# Docker's internal networks stop a container from reaching anything beyond its
# own bridge -- but the bridge's gateway address belongs to the host, and
# traffic to it is delivered locally rather than forwarded, so Docker's
# isolation rules never see it.  A sandbox can therefore still open a connection
# to any port the host has listening on 0.0.0.0, including Open WebUI, a
# database, a Docker socket proxy or the Open Terminal proxy itself.
#
# This closes that hole with two rules per address family: let replies to
# host-initiated connections through (the proxy talks *to* the sandboxes), drop
# everything else the sandbox range sends to the host.
#
#   ./sandbox-host-firewall.sh install 10.88.0.0/16     # OTPROXY_NET_SUPERNET
#   ./sandbox-host-firewall.sh status  10.88.0.0/16
#   ./sandbox-host-firewall.sh remove  10.88.0.0/16
#
# Run it on the Docker host, as root, after each boot -- or put the two rules in
# whatever manages the host's firewall (nftables, firewalld, ufw-before rules).
# The proxy checks at startup whether a sandbox can still reach it and says so
# in its log, so a forgotten rule does not stay quiet.
set -euo pipefail

CHAIN="OTPROXY-SANDBOX"
action="${1:-}"
supernet="${2:-10.88.0.0/16}"

if [[ -z "$action" || ! "$supernet" =~ ^[0-9./]+$ ]]; then
    echo "usage: $0 install|remove|status <supernet, e.g. 10.88.0.0/16>" >&2
    exit 64
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables is not installed on this host" >&2
    exit 69
fi

jump_exists() { iptables -C INPUT -s "$supernet" -j "$CHAIN" 2>/dev/null; }

case "$action" in
install)
    iptables -N "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN"
    # The proxy connects to the sandbox; the answers must come back.
    iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN" -j DROP
    jump_exists || iptables -I INPUT 1 -s "$supernet" -j "$CHAIN"
    echo "installed: traffic from $supernet to this host is dropped (replies still pass)"
    ;;
remove)
    while jump_exists; do iptables -D INPUT -s "$supernet" -j "$CHAIN"; done
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    echo "removed"
    ;;
status)
    if jump_exists; then
        echo "active for $supernet:"
        iptables -S "$CHAIN"
    else
        echo "NOT active for $supernet -- sandboxes can reach services on this host"
        exit 1
    fi
    ;;
*)
    echo "usage: $0 install|remove|status <supernet>" >&2
    exit 64
    ;;
esac
