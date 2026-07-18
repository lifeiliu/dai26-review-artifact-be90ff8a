"""Stale-authority damage accounting for Paper B evaluations."""

from __future__ import annotations


def worst_case_window(ttl: float, delta_prop: float) -> float:
    """Worst-case stale window: credential lifetime plus propagation delay."""

    return max(0.0, ttl + delta_prop)


def expected_window(ttl: float, delta_prop: float) -> float:
    """Expected stale window when revocation time is uniform in the TTL period."""

    return max(0.0, ttl / 2.0 + delta_prop)


def unauthorized_ops_worst(ttl: float, velocity: float, delta_prop: float) -> float:
    return velocity * worst_case_window(ttl, delta_prop)


def unauthorized_ops_expected(ttl: float, velocity: float, delta_prop: float) -> float:
    return velocity * expected_window(ttl, delta_prop)
