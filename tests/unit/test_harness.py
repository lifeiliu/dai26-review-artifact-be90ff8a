from revocation_propagation.byzantine_harness import TrialParams, run_baseline_matrix


def test_baseline_matrix_reports_hybrid_completeness_under_push_suppression() -> None:
    metrics = run_baseline_matrix(TrialParams(n_parties=5, suppressed_push_fraction=0.4, max_time=2.0))
    by_strategy = {metric.strategy: metric for metric in metrics}

    assert by_strategy["push"].completeness < 1.0
    assert by_strategy["push"].unauthorized_ops_worst is None
    assert by_strategy["hybrid"].completeness == 1.0
    assert by_strategy["gossip"].suppression_detected_at is None
    assert by_strategy["ttl-rcc"].max_delta == 60.0
