PYTHON ?= python3

.PHONY: test audit claim-boundaries data-check checksums smoke p0-validate verify

test:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m pytest -q -p no:cacheprovider

audit:
	$(PYTHON) scripts/check_release_surface.py

claim-boundaries:
	$(PYTHON) scripts/check_claim_boundaries.py

data-check:
	$(PYTHON) scripts/check_saved_data.py

checksums:
	$(PYTHON) scripts/verify_checksums.py

smoke:
	$(PYTHON) experiments/e_b_research_suite.py --experiment all --profile smoke --output-dir _outputs/all_smoke

p0-validate:
	$(PYTHON) scripts/validate_e_b17.py data/run_2026_07_14_e_b17_p0_matched
	$(PYTHON) scripts/replay_e_b18.py data/run_2026_07_14_e_b18_real_llm_mcp
	$(PYTHON) scripts/decide_p0.py --e-b17-dir data/run_2026_07_14_e_b17_p0_matched --e-b18-dir data/run_2026_07_14_e_b18_real_llm_mcp --output-dir _outputs/p0_verdict
	$(PYTHON) experiments/e_b27_completion_monitor/validate_run.py data/run_2026_07_18_e_b27_completion_monitor_confirmatory

verify: test audit claim-boundaries data-check checksums
