# E-B24 AWS Deployment

This directory implements the AWS qualification route stored in
`artifact/protocols/e-b24-multihost-real-effects/`.  It has three state
boundaries:

- `bootstrap/` owns persistent, non-experimental resources: the versioned
  evidence bucket, immutable ECR repository, and EC2 instance profile.
- `smoke/` owns the disposable three-AZ VPC and exactly three EC2 instances.
- `strict/` owns the disposable 16-host, eight-gateway pilot topology and its
  Keycloak-only HTTPS PUSH front door.

The smoke and first strict deployments are infrastructure qualification only.
They must not be used as paper outcome evidence. Only the strict topology can
satisfy the eight-gateway-host placement gate, and it does not authorize a
confirmatory claim before `e-b24-prereg-v1` is frozen.

## Safety invariants

1. No SSH key or port 22 is created.
2. The smoke creates no NAT Gateway, load balancer, RDS instance, or Elastic
   IP. The strict topology creates exactly one ALB and one Keycloak EIP, but no
   NAT Gateway, RDS, Spot instance, SSH key, or other public service ingress.
3. Instances use On-Demand T3 with CPU credits frozen to Standard mode.
4. The three nodes occupy three distinct Availability Zones.
5. Administration uses Systems Manager; experiment traffic uses private IPs.
6. `enable_compute` defaults to `false` so an unreviewed apply cannot start EC2.
7. The evidence bucket is outside the disposable smoke state.
8. Secrets and private keys never enter Terraform variables or state.
9. Strict Keycloak PUSH uses a public-resolving ALB endpoint with a private-CA
   certificate imported into ACM. ALB ingress is restricted to the Keycloak
   EIP `/32`; its two HTTPS listeners map one-to-one to receiver A/B over the
   private VPC.
10. The Keycloak strict startup command contains no relaxed PUSH-target option.

## Order

```bash
cd infra/e_b24/bootstrap
terraform init
terraform plan -out=bootstrap.tfplan
# Review before apply.

cd ../smoke
terraform init
terraform plan \
  -var-file=terraform.tfvars \
  -var='enable_compute=true' \
  -var='runtime_image=<account>.dkr.ecr.us-east-1.amazonaws.com/paper-b-e-b24/runtime@sha256:<digest>' \
  -out=smoke.tfplan
terraform show -json smoke.tfplan > smoke.tfplan.json
python3 ../scripts/check_smoke_plan.py smoke.tfplan.json
# Apply only the exact checked plan after all preflight gates pass.
```

Do not commit `.tfvars`, Terraform state, plans, account IDs, secrets, or AWS
session material.  The checked-in `.tfvars.example` files contain no account
identity.

## Strict pilot order

The strict route is deliberately two-phase because the exact public ALB DNS
name must exist before its short-lived private-CA certificate can be issued.

First update the persistent bootstrap stack so the strict SSM parameter prefix
and dedicated fault-controller profile exist. Review and apply that bootstrap
plan separately.

Then create and check a front-door-only plan. Compute and listeners stay off:

```bash
cd infra/e_b24/strict
terraform init
terraform plan \
  -var-file=terraform.tfvars \
  -var='enable_push_front_door=true' \
  -out=strict-frontdoor.tfplan
terraform show -json strict-frontdoor.tfplan > strict-frontdoor.tfplan.json
python3 ../scripts/check_strict_plan.py \
  --mode front-door-bootstrap strict-frontdoor.tfplan.json
# Apply only this exact checked plan. It creates 0 EC2 and 0 listeners.
```

After that apply, generate the ephemeral PKI and import the ALB certificate.
This command mutates ACM, SSM, and the evidence bucket, so run it only after the
front-door output has been reviewed:

```bash
python3 ../scripts/prepare_strict_materials.py \
  --profile paper-b-eb24 \
  --region us-east-1 \
  --expiry 2026-07-20T23:59:59Z \
  --output-dir <ignored-local-evidence-directory>
```

Use the returned real ACM ARN in a new complete plan:

```bash
terraform plan \
  -var-file=terraform.tfvars \
  -var='enable_compute=true' \
  -var='enable_push_front_door=true' \
  -var='enable_push_listeners=true' \
  -var='push_certificate_arn=<real-imported-acm-arn>' \
  -out=strict-full.tfplan
terraform show -json strict-full.tfplan > strict-full.tfplan.json
python3 ../scripts/check_strict_plan.py --mode full-pilot strict-full.tfplan.json
# Apply only the exact checked plan. Never apply the repository's dummy-ARN
# dry-run plan.
```

Once all 16 instances are SSM-online, start services in dependency waves:

```bash
python3 ../scripts/bootstrap_strict_services.py \
  --profile paper-b-eb24 \
  --region us-east-1 \
  --output-dir <ignored-local-evidence-directory>
```

The dispatcher does not retry failures. Before any service wave, it first
requires SSM `Online` and then one 16-of-16 host readiness command proving that
cloud-init is done, the Docker CLI and daemon are usable, and chrony reports a
normal leap status. It records the per-host readiness output and SSM command ID,
stops before dependent waves on any failure, and writes the status observed so
far. Service bootstrap is still an outcome-blind infrastructure operation; do
not execute the confirmatory workload before the pilot and preregistration gates
pass.
