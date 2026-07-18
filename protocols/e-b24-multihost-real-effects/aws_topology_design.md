# E-B24 AWS Topology Design

## Status

- Verification Status: DESIGN — NOT DEPLOYED
- Version: e-b24-aws-topology-design-v1
- Date: 2026-07-16
- Scope: infrastructure planning only; not a preregistration

AWS is a convenient implementation choice, not a scientific requirement. Any
environment with at least eight real VM/physical gateway hosts in three
independently faultable zones can satisfy the topology requirement if the
placement, network, clocks, and external fault evidence are equivalent.

## Account Prerequisites

If AWS is selected, prepare a billable AWS account with:

1. a non-root IAM provisioning identity with MFA;
2. EC2, VPC, IAM instance-profile, ECR, S3, CloudWatch, and Systems Manager
   permissions scoped to an `e-b24` project tag;
3. an AWS Budget and actual/forecast alerts before provisioning;
4. an EC2 On-Demand Standard-instance vCPU quota of at least 40 for the smoke
   and preferably 64 for the strict topology and temporary replacements;
5. one region with three available Availability Zones for the chosen instance
   type; and
6. an ECR repository and S3 evidence bucket with versioning.

New accounts may have a low Standard-instance vCPU quota. Check Service Quotas
and request an increase before scheduling the experiment.

Do not place long-lived access keys in the repository. Use AWS SSO or a
short-lived assumed role locally and instance profiles on EC2.

## Deployment Stages

### Stage A — Three-Host Infrastructure Smoke

This smoke validates remote transport, TLS, image architecture, Systems
Manager access, and external network/process fault control. It is excluded
from paper outcomes.

| Host | Temporary roles |
|---|---|
| smoke-1 | Keycloak + Keycloak PostgreSQL |
| smoke-2 | durable receiver + persistent gateway |
| smoke-3 | Filesystem/PostgreSQL effects + workload/fault driver |

Use one host in each Availability Zone. A successful smoke does not satisfy
the eight-gateway-host gate.

### Stage B — Strict Confirmatory-Candidate Topology

| Role | Count | Suggested pilot type | Placement |
|---|---:|---|---|
| gateway | 8 | `t3.small` | 3/3/2 across AZ-a/b/c |
| Keycloak | 1 | `t3.medium` | AZ-a |
| Keycloak PostgreSQL | 1 | `t3.medium` | AZ-b |
| durable receiver A/B | 2 | `t3.small` | AZ-a / AZ-c |
| Filesystem MCP effect service | 1 | `t3.small` | AZ-b |
| PostgreSQL MCP + effect DB | 1 | `t3.medium` | AZ-c |
| workload driver | 1 | `t3.small` | AZ-a |
| independent fault controller | 1 | `t3.small` | AZ-b |

Total: 16 EC2 instances and 32 vCPUs for the listed T3 sizes. Request at
least 40 vCPUs; 64 leaves room for failed-node replacement and an optional
validator.

T3 is acceptable for infrastructure qualification but is burstable. Before
confirmatory latency/throughput measurement, either:

- move every measured gateway/receiver role to one identical non-burstable
  instance family; or
- freeze T3 mode, record CPU-credit metrics, and invalidate any cluster run
  with credit throttling.

No GPU is required because E-B24 replays frozen call identities and does not
repeat model inference.

## Network

Create one VPC, for example `10.24.0.0/16`, with one subnet in each of three
Availability Zones. For a short-lived research deployment, the lower-cost
layout is:

- public subnets with public IPv4 only for outbound package/image access;
- no SSH ingress;
- administration through Systems Manager Session Manager;
- service security groups allowing only the exact experiment role graph; and
- all experiment traffic using private IP addresses except the narrow
  Keycloak-to-receiver PUSH front door described below.

This avoids NAT Gateway cost. A private-subnet alternative is acceptable but
requires NAT or the relevant VPC endpoints for SSM, ECR, S3, and logs.

Keycloak 26.7 rejects a PUSH target that resolves to an RFC1918/private address
even when that target uses HTTPS with a trusted private CA. The strict topology
therefore uses one internet-facing Application Load Balancer as a narrow HTTPS
front door. Its 443 and 8443 listeners route one-to-one to receiver A and B over
private VPC HTTPS. Ingress is restricted to the Keycloak host's stable public
EIP `/32`; receiver instances accept ingress only from the ALB security group.
The ALB certificate is issued by the short-lived experiment CA for the exact
AWS-assigned ALB DNS name and imported into ACM, and Keycloak trusts that CA.
This avoids `allow-insecure-push-targets` while keeping every downstream edge
private. Exact URLs and certificate fingerprints must be frozen before
confirmation.

Minimum security-group edges:

- Keycloak -> receiver A/B HTTPS PUSH;
- receiver A/B -> assigned gateway MCP/TLS ports;
- workload driver -> gateway MCP/TLS ports;
- gateway hosts -> Filesystem/PostgreSQL effect services;
- Keycloak -> Keycloak PostgreSQL 5432;
- PostgreSQL MCP service -> effect PostgreSQL 5432; and
- SSM-managed outbound HTTPS from every managed node.

Do not open gateway, receiver, database, or SSH ports to `0.0.0.0/0`.

## TLS and Images

- Build one receiver image and one gateway image for the chosen architecture.
- Push to ECR and deploy by digest, not mutable tag.
- Continue pinning the Keycloak and PostgreSQL upstream digests.
- Use HTTPS for Keycloak PUSH and gateway handoff in the formal deployment.
- A private experiment CA is sufficient: install its trust anchor in
  Keycloak, receiver, gateway, and driver images and record certificate
  fingerprints. AWS Private CA is not required.
- Do not use Keycloak's local `allow-insecure-push-targets` option in the
  confirmatory deployment.

## Fault Control

The fault controller uses Systems Manager Run Command to install and remove
pre-frozen `nftables` and `tc netem` rules, or to stop/restart only the receiver
worker service. Save:

- command document and parameters;
- start/end timestamps;
- rule listings before, during, and after treatment;
- packet counters;
- service PID/status evidence; and
- recovery evidence.

Security-group or subnet changes are too slow and control-plane-dependent for
fine-grained timing. Use them for coarse isolation only, not the primary timed
fault.

Mechanism, receiver, and gateway images must be byte-identical between healthy
and treatment arms and must contain no condition-specific drop branch.

## Time and Ordering

- Use Amazon Time Sync through `chrony` on every host.
- Save `chronyc tracking` and source output before and after every cluster run.
- Freeze a maximum acceptable clock-error bound before confirmation.
- Use signed/hashed event and sequence identifiers for causal order.
- Invalidate wall-clock latency for a run that violates the clock bound;
  retain its categorical state/effect outcome if causal ordering remains
  unambiguous and the preregistration allows it.

## Persistent Evidence

Every cluster run uploads to a versioned S3 prefix:

- topology and placement manifest;
- AMI, package, source commit, and container digests;
- Keycloak outbox and SET metadata;
- receiver inbox and enforcement receipt exports;
- gateway decision logs;
- Filesystem Merkle manifest;
- PostgreSQL effect-row export and digest;
- fault-controller and packet-counter evidence;
- clock measurements;
- raw replay rows; and
- a SHA-256 manifest over the complete run.

Do not upload credentials, refresh tokens, raw secrets, or stable cloud account
identifiers into the paper artifact.

## Cost Control

Use On-Demand instances for confirmatory runs so Spot interruption is not a
confound. Stop all EC2 instances between scheduled runs and destroy the VPC
after artifact export. Costs depend on region, instance family, EBS, public
IPv4, data transfer, and logging; calculate them with the AWS Pricing
Calculator after choosing the region rather than freezing a guessed amount in
the protocol.

Set budget alerts before provisioning. Tag every resource with at least:

```text
Project=paper-b-e-b24
Stage=smoke|pilot|confirmatory
Owner=<researcher>
Expiry=<date>
```

## Go/No-Go Checklist Before Deployment

- [ ] AWS account and MFA-protected non-root provisioning identity ready
- [ ] Budget and alerts active
- [ ] EC2 Standard-instance quota >= 40 vCPUs
- [ ] selected instance types available in three AZs
- [ ] ECR images built and digest-pinned
- [ ] S3 evidence bucket and lifecycle policy ready
- [ ] SSM access verified without SSH ingress
- [ ] private CA and all service certificates pinned
- [ ] three-host smoke manifest frozen
- [ ] local E-B24 qualification remains reproducible
- [ ] no confirmatory result will be observed before `e-b24-prereg-v1`
