# E-B16 Synchronous Status Outage Baselines Report

Raw rows: 240
Aggregate rows: 24
Strategies: ['revprop-hybrid', 'sync-fail-closed', 'sync-fail-open', 'sync-status-cache-ttl']
Fault scenarios: ['none', 'status-outage', 'status-partition']
Integration success rate: 1.0000
Status error count: 2400
Max availability loss rate: 1.0000
Max stale capability window: 60.0000
Mean outage prevented fraction: 0.7345

## Baseline Aggregates

| strategy | fault | n | rate | runs | availability loss | stale max | prevented | status errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| revprop-hybrid | none | 30 | 1.00 | 10 | 0.0000 | 0.0500 | 0.9992 | 0.00 |
| revprop-hybrid | none | 30 | 10.00 | 10 | 0.0000 | 0.0500 | 0.9992 | 0.00 |
| revprop-hybrid | status-outage | 30 | 1.00 | 10 | 0.0000 | 0.5500 | 0.9908 | 0.00 |
| revprop-hybrid | status-outage | 30 | 10.00 | 10 | 0.0000 | 0.5500 | 0.9908 | 0.00 |
| revprop-hybrid | status-partition | 30 | 1.00 | 10 | 0.0000 | 0.9000 | 0.9850 | 0.00 |
| revprop-hybrid | status-partition | 30 | 10.00 | 10 | 0.0000 | 0.9000 | 0.9850 | 0.00 |
| sync-fail-closed | none | 30 | 1.00 | 10 | 0.0000 | 0.0000 | 1.0000 | 0.00 |
| sync-fail-closed | none | 30 | 10.00 | 10 | 0.0000 | 0.0000 | 1.0000 | 0.00 |
| sync-fail-closed | status-outage | 30 | 1.00 | 10 | 1.0000 | 0.0000 | 1.0000 | 30.00 |
| sync-fail-closed | status-outage | 30 | 10.00 | 10 | 1.0000 | 0.0000 | 1.0000 | 30.00 |
| sync-fail-closed | status-partition | 30 | 1.00 | 10 | 1.0000 | 0.0000 | 1.0000 | 30.00 |
| sync-fail-closed | status-partition | 30 | 10.00 | 10 | 1.0000 | 0.0000 | 1.0000 | 30.00 |
| sync-fail-open | none | 30 | 1.00 | 10 | 0.0000 | 0.0000 | 1.0000 | 0.00 |
| sync-fail-open | none | 30 | 10.00 | 10 | 0.0000 | 0.0000 | 1.0000 | 0.00 |
| sync-fail-open | status-outage | 30 | 1.00 | 10 | 0.0000 | 2.0000 | 0.9667 | 30.00 |
| sync-fail-open | status-outage | 30 | 10.00 | 10 | 0.0000 | 2.0000 | 0.9667 | 30.00 |
| sync-fail-open | status-partition | 30 | 1.00 | 10 | 0.0000 | 4.0000 | 0.9333 | 30.00 |
| sync-fail-open | status-partition | 30 | 10.00 | 10 | 0.0000 | 4.0000 | 0.9333 | 30.00 |
| sync-status-cache-ttl | none | 30 | 1.00 | 10 | 0.0000 | 60.0000 | 0.0000 | 0.00 |
| sync-status-cache-ttl | none | 30 | 10.00 | 10 | 0.0000 | 60.0000 | 0.0000 | 0.00 |
| sync-status-cache-ttl | status-outage | 30 | 1.00 | 10 | 0.0000 | 60.0000 | 0.0000 | 0.00 |
| sync-status-cache-ttl | status-outage | 30 | 10.00 | 10 | 0.0000 | 60.0000 | 0.0000 | 0.00 |
| sync-status-cache-ttl | status-partition | 30 | 1.00 | 10 | 0.0000 | 60.0000 | 0.0000 | 0.00 |
| sync-status-cache-ttl | status-partition | 30 | 10.00 | 10 | 0.0000 | 60.0000 | 0.0000 | 0.00 |

## Interpretation

E-B16 compares RevProp against synchronous status-check baselines under local status-service outages. Fail-closed minimizes stale authorization but loses availability during outages; fail-open preserves availability but admits stale authority until recovery; TTL cache remains bounded by the token lifetime.
