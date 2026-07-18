# E-B21 Keycloak 26.7 SSF smoke test

This smoke test checks the independently implemented Keycloak 26.7.0 SSF
transmitter on its RFC 8935 PUSH path. It creates two receiver streams, emits
a native CAEP `session-revoked` event through a real Keycloak login/logout,
then returns HTTP 503 only for receiver B. The checks require receiver A to
keep receiving, receiver B to remain undelivered while selected, the Keycloak
outbox row to remain pending, and the native retry to deliver the identical
signed SET after recovery. The runner verifies each recorded RS256 signature
against the realm's published JWKS rather than merely decoding the JWT.

The 500 ms outbox drainer interval follows Keycloak's own integration-test
configuration and only accelerates this smoke test. The native retry curve and
attempt budget are not changed. No latency result from this run is paper
evidence.

Run from the repository root:

```bash
python3 artifact/experiments/e_b21_keycloak_ssf_smoke/run_smoke.py \
  --output-dir artifact/data/run_2026_07_15_e_b21_keycloak_ssf_smoke
```

Requires Docker and host ports 18080 and 19001.
