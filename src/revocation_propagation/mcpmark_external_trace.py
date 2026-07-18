"""Frozen E-B20 MCPMark trace instrumentation and replay analysis.

The preregistration is ``protocols/e-b20-mcpmark-external-trace/protocol.md``.
This module deliberately keeps benchmark trace collection separate from the
propagation replay so held-out traces cannot update the calibrated risk or the
repair allocation.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import re
import stat
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence


PROTOCOL_VERSION = "e-b20-prereg-v1"
MCPMARK_COMMIT = "cd45b7f57923b9b3985467f5139927575f83141c"
SERVICES: tuple[str, ...] = ("filesystem", "postgres")
CALIBRATION_RUNS: tuple[int, ...] = (1, 2)
HELDOUT_RUNS: tuple[int, ...] = (3, 4)
PROPAGATION_SEEDS: tuple[int, ...] = tuple(range(30))
SUPPRESSION_FRACTION = 0.20
ATTEMPTS_PER_TARGET = 5
HORIZON = 60.0
POLL_INTERVAL = 10.0
MESSAGE_BUDGET = 8.1
BYTE_BUDGET = 8192.0


@dataclass(frozen=True)
class CalibrationRisk:
    gateway_id: str
    service: str
    calls_run1: int
    calls_run2: int
    mutations_run1: int
    mutations_run2: int

    @property
    def call_rate(self) -> float:
        return (self.calls_run1 + self.calls_run2) / 2.0

    @property
    def mutation_fraction(self) -> float:
        calls = self.calls_run1 + self.calls_run2
        return (self.mutations_run1 + self.mutations_run2) / calls if calls else 0.0

    @property
    def risk(self) -> float:
        return self.call_rate * self.mutation_fraction


@dataclass(frozen=True)
class ReplayContribution:
    gateway_id: str
    seed: int
    policy: str
    weighted_harm: float
    accepted_mutating_calls: int


def canonical_json_hash(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def filesystem_merkle_digest(root: str | Path) -> str:
    """Return a normalized digest that excludes volatile filesystem times."""

    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(root_path)

    digest = hashlib.sha256()
    for path in sorted(root_path.rglob("*"), key=lambda item: item.relative_to(root_path).as_posix()):
        relative = path.relative_to(root_path).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            kind = "symlink"
            content = path.readlink().as_posix().encode("utf-8")
        elif path.is_dir():
            kind = "directory"
            content = b""
        elif path.is_file():
            kind = "file"
            content = path.read_bytes()
        else:
            kind = "other"
            content = b""
        header = json.dumps(
            {"path": relative, "kind": kind, "mode": mode},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _sql_words(sql: str) -> list[str]:
    """Tokenize SQL words/parentheses while discarding comments and literals."""

    words: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < length else ""
        if char == "-" and next_char == "-":
            index += 2
            while index < length and sql[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            depth = 1
            while index < length and depth:
                if sql[index : index + 2] == "/*":
                    depth += 1
                    index += 2
                elif sql[index : index + 2] == "*/":
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue
        if char == "'":
            index += 1
            while index < length:
                if sql[index] == "'":
                    if index + 1 < length and sql[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                if sql[index] == "\\" and index + 1 < length:
                    index += 2
                else:
                    index += 1
            continue
        if char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[index:])
            if match:
                delimiter = match.group(0)
                index += len(delimiter)
                end = sql.find(delimiter, index)
                index = length if end < 0 else end + len(delimiter)
                continue
        if char == '"':
            index += 1
            while index < length:
                if sql[index] == '"':
                    if index + 1 < length and sql[index + 1] == '"':
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (sql[end].isalnum() or sql[end] in "_$"):
                end += 1
            words.append(sql[index:end].upper())
            index = end
            continue
        if char in "();":
            words.append(char)
        index += 1
    return words


def postgres_sql_is_mutating(sql: str) -> bool:
    """Apply the frozen E-B20 accepted-mutation SQL classifier."""

    words = _sql_words(sql)
    mutation_words = {
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "CREATE",
        "ALTER",
        "DROP",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "COMMENT",
        "CALL",
        "DO",
        "REFRESH",
        "REINDEX",
        "CLUSTER",
        "VACUUM",
        "ANALYZE",
    }
    if any(word in mutation_words for word in words):
        return True
    for left, right in zip(words, words[1:]):
        if (left, right) in {("SECURITY", "LABEL"), ("SELECT", "INTO")}:
            return True
    for position, word in enumerate(words):
        if word == "COPY":
            depth = 0
            for token in words[position + 1 :]:
                if token == "(":
                    depth += 1
                elif token == ")":
                    depth = max(0, depth - 1)
                elif token == ";" and depth == 0:
                    break
                elif token in {"FROM", "TO"} and depth == 0:
                    return token == "FROM"
    return False


def extract_sql(arguments: Mapping[str, object]) -> str | None:
    """Find the SQL string in a Postgres MCP argument object."""

    preferred = ("sql", "query", "statement", "command")
    for key in preferred:
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    for value in arguments.values():
        if isinstance(value, Mapping):
            nested = extract_sql(value)
            if nested is not None:
                return nested
    return None


def discover_mcpmark_tasks(mcpmark_root: str | Path) -> list[dict[str, str]]:
    root = Path(mcpmark_root)
    rows: list[dict[str, str]] = []
    for service in SERVICES:
        task_root = root / "tasks" / service / "standard"
        for meta_path in sorted(task_root.glob("*/*/meta.json")):
            category = meta_path.parent.parent.name
            task = meta_path.parent.name
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            category = str(metadata.get("category_id", category))
            task = str(metadata.get("task_id", task))
            gateway_id = f"{service}/{category}/{task}"
            rows.append(
                {
                    "gateway_id": gateway_id,
                    "service": service,
                    "category_id": category,
                    "task_id": task,
                    "meta_path": meta_path.relative_to(root).as_posix(),
                }
            )
    rows.sort(key=lambda row: row["gateway_id"])
    return rows


def write_benchmark_manifest(mcpmark_root: str | Path, output_path: str | Path) -> dict[str, object]:
    tasks = discover_mcpmark_tasks(mcpmark_root)
    service_counts = Counter(row["service"] for row in tasks)
    manifest: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "mcpmark_commit": MCPMARK_COMMIT,
        "services": list(SERVICES),
        "task_count": len(tasks),
        "service_counts": dict(sorted(service_counts.items())),
        "tasks": tasks,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def load_trace_events(trace_dir: str | Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for path in sorted(Path(trace_dir).glob("*.jsonl")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError(f"{path}:{line_number}: trace event is not an object")
            event["_source_file"] = path.name
            event["_source_line"] = line_number
            events.append(event)
    return events


def calibrate_risks(
    events: Sequence[Mapping[str, object]],
    expected_tasks: Sequence[Mapping[str, str]],
) -> list[CalibrationRisk]:
    calls: Counter[tuple[str, int]] = Counter()
    mutations: Counter[tuple[str, int]] = Counter()
    completed: Counter[tuple[str, int]] = Counter()
    for event in events:
        event_type = event.get("event_type")
        gateway_id = str(event.get("gateway_id", ""))
        run = int(event.get("run", 0) or 0)
        if run not in CALIBRATION_RUNS:
            continue
        if event_type == "tool_call":
            calls[(gateway_id, run)] += 1
            if event.get("mutating") is True:
                mutations[(gateway_id, run)] += 1
            if event.get("mutating") is None:
                raise ValueError(f"missing mutation label for {gateway_id} run {run}")
        elif event_type == "task_end":
            completed[(gateway_id, run)] += 1

    risks: list[CalibrationRisk] = []
    for task in sorted(expected_tasks, key=lambda row: row["gateway_id"]):
        gateway_id = task["gateway_id"]
        for run in CALIBRATION_RUNS:
            if completed[(gateway_id, run)] != 1:
                raise ValueError(
                    f"expected exactly one task_end for {gateway_id} run {run}, "
                    f"found {completed[(gateway_id, run)]}"
                )
        risks.append(
            CalibrationRisk(
                gateway_id=gateway_id,
                service=task["service"],
                calls_run1=calls[(gateway_id, 1)],
                calls_run2=calls[(gateway_id, 2)],
                mutations_run1=mutations[(gateway_id, 1)],
                mutations_run2=mutations[(gateway_id, 2)],
            )
        )
    return risks


def select_top_risk_targets(risks: Sequence[CalibrationRisk]) -> frozenset[str]:
    count = int(round(SUPPRESSION_FRACTION * len(risks)))
    ordered = sorted(risks, key=lambda item: (-item.risk, item.gateway_id))
    return frozenset(item.gateway_id for item in ordered[:count])


def repair_allocations(
    risks: Sequence[CalibrationRisk],
    targets: frozenset[str],
    policy: str,
) -> dict[str, int]:
    target_risks = [risk for risk in risks if risk.gateway_id in targets]
    total = ATTEMPTS_PER_TARGET * len(target_risks)
    if policy == "uniform":
        return {risk.gateway_id: ATTEMPTS_PER_TARGET for risk in target_risks}
    if policy != "risk-aware":
        raise ValueError(f"unsupported policy: {policy}")
    if not target_risks or all(risk.risk <= 0.0 for risk in target_risks):
        raise ValueError("risk-aware allocation requires positive targeted risk")

    allocations = {risk.gateway_id: 1 for risk in target_risks}
    remaining = total - len(target_risks)
    weights = {risk.gateway_id: math.sqrt(risk.risk) for risk in target_risks}
    weight_total = sum(weights.values())
    raw = {gateway_id: remaining * weight / weight_total for gateway_id, weight in weights.items()}
    floors = {gateway_id: int(math.floor(value)) for gateway_id, value in raw.items()}
    for gateway_id, value in floors.items():
        allocations[gateway_id] += value
    leftovers = remaining - sum(floors.values())
    order = sorted(raw, key=lambda gateway_id: (-(raw[gateway_id] - floors[gateway_id]), gateway_id))
    for gateway_id in order[:leftovers]:
        allocations[gateway_id] += 1
    if sum(allocations.values()) != total or min(allocations.values()) < 1:
        raise AssertionError("repair allocation violated the frozen budget")
    return allocations


def _stable_unit(label: str) -> float:
    digest = hashlib.blake2b(label.encode("utf-8"), digest_size=8).digest()
    return (int.from_bytes(digest, "big") + 0.5) / 2**64


def enforcement_delay(
    *,
    gateway_id: str,
    seed: int,
    targeted: bool,
    attempts: int,
) -> float:
    direct = 0.02 + 0.03 * _stable_unit(
        f"{PROTOCOL_VERSION}:direct:{seed}:{gateway_id}"
    )
    if not targeted:
        return direct
    log_delay = 0.05 + POLL_INTERVAL * _stable_unit(
        f"{PROTOCOL_VERSION}:log:{seed}:{gateway_id}"
    )
    repair = min(
        0.10
        + 0.40
        * _stable_unit(f"{PROTOCOL_VERSION}:repair:{seed}:{gateway_id}:{attempt}")
        for attempt in range(attempts)
    )
    return min(log_delay, repair)


def validate_trace_population(
    events: Sequence[Mapping[str, object]],
    expected_tasks: Sequence[Mapping[str, str]],
) -> None:
    ends: Counter[tuple[str, int]] = Counter()
    invalid: list[str] = []
    for event in events:
        if event.get("event_type") == "task_end":
            gateway_id = str(event.get("gateway_id"))
            run = int(event.get("run", 0) or 0)
            ends[(gateway_id, run)] += 1
            if event.get("trace_valid") is not True:
                invalid.append(f"{gateway_id} run {run}")
    for task in expected_tasks:
        for run in (*CALIBRATION_RUNS, *HELDOUT_RUNS):
            count = ends[(task["gateway_id"], run)]
            if count != 1:
                raise ValueError(
                    f"expected exactly one task_end for {task['gateway_id']} run {run}, found {count}"
                )
    if invalid:
        raise ValueError("invalid infrastructure traces: " + ", ".join(sorted(invalid)))


def replay_contributions(
    events: Sequence[Mapping[str, object]],
    risks: Sequence[CalibrationRisk],
    targets: frozenset[str],
) -> list[ReplayContribution]:
    risk_by_id = {risk.gateway_id: risk for risk in risks}
    calls_by_trace: dict[tuple[str, int], list[Mapping[str, object]]] = defaultdict(list)
    for event in events:
        run = int(event.get("run", 0) or 0)
        if event.get("event_type") == "tool_call" and run in HELDOUT_RUNS:
            calls_by_trace[(str(event.get("gateway_id")), run)].append(event)

    allocations = {
        policy: repair_allocations(risks, targets, policy)
        for policy in ("uniform", "risk-aware")
    }
    contributions: list[ReplayContribution] = []
    for gateway_id, risk in sorted(risk_by_id.items()):
        for seed in PROPAGATION_SEEDS:
            for policy in ("uniform", "risk-aware"):
                targeted = gateway_id in targets
                attempts = allocations[policy].get(gateway_id, 0)
                delay = enforcement_delay(
                    gateway_id=gateway_id,
                    seed=seed,
                    targeted=targeted,
                    attempts=attempts,
                )
                accepted = 0
                for run in HELDOUT_RUNS:
                    trace = sorted(
                        calls_by_trace.get((gateway_id, run), []),
                        key=lambda event: int(event.get("call_started_monotonic_ns", 0) or 0),
                    )
                    if len(trace) < 2:
                        continue
                    first = int(trace[0]["call_started_monotonic_ns"])
                    last = int(trace[-1]["call_started_monotonic_ns"])
                    revoke = first + int(
                        (last - first)
                        * _stable_unit(
                            f"{PROTOCOL_VERSION}:revoke:{seed}:{gateway_id}:{run}"
                        )
                    )
                    enforce = revoke + int(delay * 1_000_000_000)
                    accepted += sum(
                        1
                        for event in trace
                        if event.get("mutating") is True
                        and bool(event.get("success"))
                        and revoke < int(event["call_started_monotonic_ns"]) < enforce
                    )
                contributions.append(
                    ReplayContribution(
                        gateway_id=gateway_id,
                        seed=seed,
                        policy=policy,
                        weighted_harm=risk.risk * delay,
                        accepted_mutating_calls=accepted,
                    )
                )
    return contributions


def _percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _exact_sign_test(differences: Sequence[float]) -> float:
    positives = sum(value > 0 for value in differences)
    negatives = sum(value < 0 for value in differences)
    total = positives + negatives
    if total == 0:
        return 1.0
    smaller = min(positives, negatives)
    tail = sum(math.comb(total, index) for index in range(smaller + 1)) / 2**total
    return min(1.0, 2.0 * tail)


def analyze_replay(
    contributions: Sequence[ReplayContribution],
    *,
    bootstrap_samples: int = 10_000,
) -> dict[str, object]:
    by_task_seed_policy: dict[tuple[str, int, str], ReplayContribution] = {
        (item.gateway_id, item.seed, item.policy): item for item in contributions
    }
    tasks = sorted({item.gateway_id for item in contributions})
    seeds = sorted({item.seed for item in contributions})
    if not tasks or seeds != list(PROPAGATION_SEEDS):
        raise ValueError("replay contributions do not contain the frozen population")

    def totals(metric: str, sampled_tasks: Sequence[str] = tasks) -> dict[str, list[float]]:
        output = {"uniform": [], "risk-aware": []}
        for policy in output:
            for seed in seeds:
                output[policy].append(
                    sum(
                        float(getattr(by_task_seed_policy[(task, seed, policy)], metric))
                        for task in sampled_tasks
                    )
                )
        return output

    rng = random.Random(int.from_bytes(hashlib.sha256(PROTOCOL_VERSION.encode()).digest()[:8], "big"))
    analyses: dict[str, dict[str, object]] = {}
    for metric, label in (
        ("weighted_harm", "H"),
        ("accepted_mutating_calls", "U"),
    ):
        observed = totals(metric)
        uniform_mean = statistics.fmean(observed["uniform"])
        policy_mean = statistics.fmean(observed["risk-aware"])
        differences = [
            policy - baseline
            for policy, baseline in zip(observed["risk-aware"], observed["uniform"], strict=True)
        ]
        bootstrap_differences: list[float] = []
        for _ in range(bootstrap_samples):
            sample = [tasks[rng.randrange(len(tasks))] for _ in tasks]
            sampled = totals(metric, sample)
            bootstrap_differences.append(
                statistics.fmean(sampled["risk-aware"])
                - statistics.fmean(sampled["uniform"])
            )
        if uniform_mean > 0.0:
            relative_reduction: float | None = 1.0 - policy_mean / uniform_mean
        else:
            relative_reduction = None
        standard_deviation = statistics.stdev(differences) if len(differences) > 1 else 0.0
        analyses[label] = {
            "uniform_mean": uniform_mean,
            "risk_aware_mean": policy_mean,
            "relative_reduction": relative_reduction,
            "mean_difference": statistics.fmean(differences),
            "ci95_low": _percentile(bootstrap_differences, 0.025),
            "ci95_high": _percentile(bootstrap_differences, 0.975),
            "sign_test_p": _exact_sign_test(differences),
            "paired_cohen_dz": (
                statistics.fmean(differences) / standard_deviation
                if standard_deviation > 0.0
                else None
            ),
            "zero_baseline_seed_rate": sum(value == 0.0 for value in observed["uniform"])
            / len(observed["uniform"]),
            "per_seed_relative_reduction": [
                1.0 - policy / baseline if baseline > 0.0 else None
                for policy, baseline in zip(
                    observed["risk-aware"], observed["uniform"], strict=True
                )
            ],
        }
        analyses[label]["gate_pass"] = bool(
            relative_reduction is not None
            and relative_reduction >= 0.30
            and float(analyses[label]["ci95_high"]) < 0.0
        )

    analyses["overall_gate_pass"] = bool(
        analyses["H"]["gate_pass"] and analyses["U"]["gate_pass"]
    )
    return analyses


def cost_contract(n_gateways: int, target_count: int) -> dict[str, object]:
    attempts = ATTEMPTS_PER_TARGET * target_count
    attempts_per_gateway = attempts / n_gateways
    append_share = 1.0 / n_gateways
    messages = 1.0 + HORIZON / POLL_INTERVAL + attempts_per_gateway + append_share
    bytes_per_gateway = (
        1200.0
        + HORIZON / POLL_INTERVAL * 256.0
        + attempts_per_gateway * 1200.0
        + append_share * 1200.0
    )
    return {
        "repair_attempts_total": attempts,
        "control_messages_per_gateway": messages,
        "control_bytes_per_gateway": bytes_per_gateway,
        "message_budget_pass": messages <= MESSAGE_BUDGET,
        "byte_budget_pass": bytes_per_gateway <= BYTE_BUDGET,
        "explicit_event_completeness": 1.0,
        "audit_evidence_rate": 1.0,
        "availability_loss_rate": 0.0,
        "exact_policy_cost_match": True,
    }


def _write_csv(rows: Sequence[Mapping[str, object]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({field for row in rows for field in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def analyze_e_b20(
    *,
    manifest_path: str | Path,
    trace_dir: str | Path,
    output_dir: str | Path,
    bootstrap_samples: int = 10_000,
) -> dict[str, object]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("mcpmark_commit") != MCPMARK_COMMIT:
        raise ValueError("manifest does not match the frozen MCPMark commit")
    tasks = manifest["tasks"]
    if len(tasks) != 51:
        raise ValueError(f"frozen E-B20 population requires 51 tasks, found {len(tasks)}")
    events = load_trace_events(trace_dir)
    validate_trace_population(events, tasks)
    risks = calibrate_risks(events, tasks)
    if not any(risk.risk > 0.0 for risk in risks):
        raise ValueError("all calibrated risks are zero")
    targets = select_top_risk_targets(risks)
    if len(targets) != 10:
        raise AssertionError(f"frozen E-B20 target count is 10, found {len(targets)}")
    allocations = {
        policy: repair_allocations(risks, targets, policy)
        for policy in ("uniform", "risk-aware")
    }
    contributions = replay_contributions(events, risks, targets)
    analysis = analyze_replay(contributions, bootstrap_samples=bootstrap_samples)
    costs = cost_contract(len(risks), len(targets))
    overall = bool(
        analysis["overall_gate_pass"]
        and costs["exact_policy_cost_match"]
        and costs["message_budget_pass"]
        and costs["byte_budget_pass"]
    )
    verdict = (
        "EXTERNAL_WORKLOAD_SUPPORTS_PIVOT"
        if overall
        else "MODEL_ONLY_NOT_EXTERNAL"
        if analysis["H"]["gate_pass"] and not analysis["U"]["gate_pass"]
        else "EXTERNAL_REPRODUCTION_NOT_SUPPORTED"
    )
    summary: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "mcpmark_commit": MCPMARK_COMMIT,
        "task_count": len(tasks),
        "target_count": len(targets),
        "calibration_runs": list(CALIBRATION_RUNS),
        "heldout_runs": list(HELDOUT_RUNS),
        "propagation_seeds": list(PROPAGATION_SEEDS),
        "analysis": analysis,
        "cost_contract": costs,
        "overall_gate_pass": overall,
        "verdict": verdict,
    }

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    risk_rows = [
        {
            "gateway_id": risk.gateway_id,
            "service": risk.service,
            "calls_run1": risk.calls_run1,
            "calls_run2": risk.calls_run2,
            "mutations_run1": risk.mutations_run1,
            "mutations_run2": risk.mutations_run2,
            "lambda": risk.call_rate,
            "mutation_fraction": risk.mutation_fraction,
            "risk": risk.risk,
            "targeted": risk.gateway_id in targets,
        }
        for risk in risks
    ]
    allocation_rows = [
        {
            "gateway_id": gateway_id,
            "policy": policy,
            "attempts": attempts,
        }
        for policy, policy_allocations in allocations.items()
        for gateway_id, attempts in sorted(policy_allocations.items())
    ]
    contribution_rows = [
        {
            "gateway_id": item.gateway_id,
            "seed": item.seed,
            "policy": item.policy,
            "weighted_harm": item.weighted_harm,
            "accepted_mutating_calls": item.accepted_mutating_calls,
        }
        for item in contributions
    ]
    _write_csv(risk_rows, output / "e_b20_calibration_risk.csv")
    _write_csv(allocation_rows, output / "e_b20_allocations.csv")
    _write_csv(contribution_rows, output / "e_b20_heldout_replay.csv")
    (output / "e_b20_targets.json").write_text(
        json.dumps({"targets": sorted(targets)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "e_b20_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "e_b20_report.md").write_text(_markdown_report(summary) + "\n", encoding="utf-8")
    return summary


def _markdown_report(summary: Mapping[str, object]) -> str:
    analysis = summary["analysis"]
    assert isinstance(analysis, Mapping)
    lines = [
        "# E-B20 MCPMark External-Trace Replay",
        "",
        "## Material Passport",
        "",
        "- Origin Skill: academic-research-suite / experiment-agent",
        "- Origin Mode: validate",
        "- Verification Status: ANALYZED",
        f"- Version Label: {PROTOCOL_VERSION}",
        f"- MCPMark Commit: `{MCPMARK_COMMIT}`",
        "",
        "## Frozen-Gate Results",
        "",
        "| Outcome | Uniform mean | Risk-aware mean | Reduction | 95% diff CI | Pass |",
        "|---|---:|---:|---:|---:|:---:|",
    ]
    for label in ("H", "U"):
        item = analysis[label]
        assert isinstance(item, Mapping)
        reduction = item["relative_reduction"]
        reduction_text = "undefined" if reduction is None else f"{100 * float(reduction):.2f}%"
        lines.append(
            f"| {label} | {float(item['uniform_mean']):.6f} | "
            f"{float(item['risk_aware_mean']):.6f} | {reduction_text} | "
            f"[{float(item['ci95_low']):.6f}, {float(item['ci95_high']):.6f}] | "
            f"{'yes' if item['gate_pass'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Decision",
            "",
            f"**{summary['verdict']}**",
            "",
            "The decision uses the frozen ratio-of-means 30% threshold, paired "
            "task-cluster bootstrap, exact equal-cost contract, and the full 51-task population.",
        ]
    )
    return "\n".join(lines)
