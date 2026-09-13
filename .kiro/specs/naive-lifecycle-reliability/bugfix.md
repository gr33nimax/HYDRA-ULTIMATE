# Naive lifecycle reliability — Bugfix Spec

## Current behavior

- With a disabled Naive plugin, `set_domain` persists `network.domain` and the settings menu reports that the domain changed, but TLS is intentionally deferred until enable. The result is easily read as a working server despite no certificate.
- `NaivePlugin.install()` treats the presence of a binary (or any `caddy-naive` in `PATH`) as a complete installation. A missing systemd unit or an incompatible binary can therefore yield a successful install result.
- An enabled Naive plugin without TLS material clears its pending Caddyfile and later fails through a generic `apply returned false` path.

## Expected behavior

1. WHEN the domain is changed while Naive is disabled, THEN the UI SHALL state that the domain is saved and the TLS certificate will be obtained on enable.
2. WHEN Naive is installed or reinstalled, THEN it SHALL be considered installed only when the managed binary and managed systemd unit exist.
3. WHEN an enabled Naive instance has no resolved certificate/key pair, THEN configuration SHALL raise a clear TLS error before runtime apply.
4. WHEN a managed binary exists but its unit is missing, THEN install SHALL restore and enable the unit without rebuilding the binary.
5. Existing activation semantics SHALL remain unchanged: certificate provisioning happens through `ProtocolSetupService` before enable/apply, and a failure rolls state/runtime back.

## Regression coverage

- Disabled-domain UI result distinguishes deferred TLS from applied runtime.
- Install repairs a missing unit when the managed binary exists.
- A PATH-only binary is not a completed Naive installation.
- Missing TLS material for an enabled Naive configuration raises a domain-specific error.

## Out of scope

- Changing the selected forwardproxy fork or Caddy version.
- Downloading prebuilt fork releases.
- Adding a new certificate issuance path outside `ProtocolSetupService`.
