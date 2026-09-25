# AntiScan production evidence fixtures

Provenance for the closed evidence allowlist described in
`.kiro/specs/antidpi-evidence-contraction/`.

Captured from the live HYDRA deployment on `gr33nimax.ru` (HYDRA `2.5.5`,
repo commit `dd353cf`) on 2026-09-16 with read-only commands only
(`journalctl`, `grep`, `tail`). Nothing on the host was modified.

Redactions applied before storing:

- every external address replaced with a documentation address
  (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`);
- inbound tag hashes replaced with stable placeholders of the same shape;
- `Proxy-Authorization` values and `user_id` values replaced with `REDACTED`;
- no password, UUID, token, private key or secret is stored here.

## Files

| File | Purpose | Verdict |
| --- | --- | --- |
| `snell-cipher-auth-failure.txt` | Real Snell record-header authentication failure on a direct TCP listener. | **enabled** |
| `decoy-scanner-paths.jsonl` | Real scanner requests for credential/version-control paths on decoy sites. | **enabled** |
| `negatives.jsonl` | Real inputs that must never produce evidence. | rejection fixtures |

## Per-protocol verdicts (evidence-driven)

| Protocol | Observed production signal | Verdict |
| --- | --- | --- |
| Snell | `inbound/snell[...]: process connection from <peer>: snell: serve <peer>: read request: open record header: cipher: message authentication failed` — direct external TCP peer, 49 events / 14 days / 5 source IPs. | **enabled** |
| Decoy sites | `/.env`, `/.env.*`, `/.git/config`, `/.git/HEAD` and neighbouring scanner paths in `decoy-access.log`. | **enabled** |
| Naive | 20 days of `caddy-naive` access log contain statuses `200/404/405/308` only — **no `407`**. Unauthenticated callers are served the decoy page, so a wrong credential leaves no attributable protocol reject. | **unsupported** |
| VLESS | 20 days of journal contain no `unknown UUID`/`authenticate:` reject; XHTTP requests terminate in Caddy, so the native service never reports a wrong UUID. | **unsupported** |
| AnyTLS | 20 days of journal contain no AnyTLS error record; wrong passwords are absorbed by the fallback handler. | **unsupported** |
| TrustTunnel | 7 days of `trusttunnel-access.log` contain zero `"status":407`. | **unsupported** |
| ShadowTLS, Hysteria2, Mieru, Telemt, AmneziaWG, qWDTT, Calls | No attributable protocol reject exists in production logs. | **unsupported** |

## How the snapshots were taken

```bash
# Snell record-header authentication failures (direct TCP peer attribution)
journalctl -u sing-box --since "14 days ago" --no-pager \
  | grep "cipher: message authentication failed"

# Decoy scanner-path requests
grep -E '"uri":"/(\.env|\.git)' /var/log/caddy-l4/decoy-access.log

# Negative: generic TCP/443 noise that must never become evidence
grep "no certificate available" /var/log/caddy-l4/antidpi.jsonl
```

## Maintenance

A fixture may only be replaced by a fresh capture from the same deployed
implementation. Synthetic strings invented for unit tests are not acceptable
proof for enabling an adapter.
