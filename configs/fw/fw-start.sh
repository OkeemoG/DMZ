#!/bin/sh
rules="${1:-/etc/nftables.nft}"
if nft -f "$rules"; then
  exit 0
fi
nft -f - <<'RULES'
flush ruleset
table inet failsafe {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy drop;
        oif "lo" accept
    }
}
RULES
logger -t fw-start -p daemon.crit "rule set ${rules} failed to load, all traffic dropped" 2>/dev/null
echo "fw-start: rule set ${rules} failed to load, all traffic dropped" >&2
exit 1
