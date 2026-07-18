# E-B7 Reproducibility and Sensitivity Report

Raw rows: 180
Aggregate rows: 18
Config IDs: ['baseline', 'delay_scale=0.5', 'delay_scale=2.0', 'fanout=16', 'fanout=4', 'jitter=0.0', 'jitter=0.4', 'poll_interval=0.25', 'poll_interval=1.0']
Minimum completeness: 1.0000
Maximum p99 delta: 0.5296
Maximum p99/baseline ratio: 1.325

## Run Config

- `delay_scale_values`: `(0.5, 1.0, 2.0)`
- `fanout_values`: `(4, 8, 16)`
- `jitter_values`: `(0.0, 0.2, 0.4)`
- `n_parties_values`: `(100, 300)`
- `poll_interval_values`: `(0.25, 0.5, 1.0)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)`

## Sensitivity Aggregates

| n | config | axis | runs | fanout | poll | jitter | delay scale | completeness | p99 delta | messages |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | baseline | baseline | 10 | 8 | 0.50 | 0.20 | 1.00 | 1.0000 | 0.3914 | 26447.4 |
| 100 | delay_scale=0.5 | delay_scale | 10 | 8 | 0.50 | 0.20 | 0.50 | 1.0000 | 0.3172 | 26660.3 |
| 100 | delay_scale=2.0 | delay_scale | 10 | 8 | 0.50 | 0.20 | 2.00 | 1.0000 | 0.5180 | 25874.5 |
| 100 | fanout=16 | fanout | 10 | 16 | 0.50 | 0.20 | 1.00 | 1.0000 | 0.3795 | 51223.6 |
| 100 | fanout=4 | fanout | 10 | 4 | 0.50 | 0.20 | 1.00 | 1.0000 | 0.4101 | 14040.8 |
| 100 | jitter=0.0 | jitter | 10 | 8 | 0.50 | 0.00 | 1.00 | 1.0000 | 0.4000 | 26588.0 |
| 100 | jitter=0.4 | jitter | 10 | 8 | 0.50 | 0.40 | 1.00 | 1.0000 | 0.3864 | 26433.7 |
| 100 | poll_interval=0.25 | poll_interval | 10 | 8 | 0.25 | 0.20 | 1.00 | 1.0000 | 0.2702 | 28106.6 |
| 100 | poll_interval=1.0 | poll_interval | 10 | 8 | 1.00 | 0.20 | 1.00 | 1.0000 | 0.3914 | 25620.9 |
| 300 | baseline | baseline | 10 | 8 | 0.50 | 0.20 | 1.00 | 1.0000 | 0.3957 | 78774.3 |
| 300 | delay_scale=0.5 | delay_scale | 10 | 8 | 0.50 | 0.20 | 0.50 | 1.0000 | 0.3219 | 79515.6 |
| 300 | delay_scale=2.0 | delay_scale | 10 | 8 | 0.50 | 0.20 | 2.00 | 1.0000 | 0.5242 | 77135.5 |
| 300 | fanout=16 | fanout | 10 | 16 | 0.50 | 0.20 | 1.00 | 1.0000 | 0.3841 | 152681.2 |
| 300 | fanout=4 | fanout | 10 | 4 | 0.50 | 0.20 | 1.00 | 1.0000 | 0.4314 | 41863.7 |
| 300 | jitter=0.0 | jitter | 10 | 8 | 0.50 | 0.00 | 1.00 | 1.0000 | 0.4000 | 79268.0 |
| 300 | jitter=0.4 | jitter | 10 | 8 | 0.50 | 0.40 | 1.00 | 1.0000 | 0.3954 | 78843.4 |
| 300 | poll_interval=0.25 | poll_interval | 10 | 8 | 0.25 | 0.20 | 1.00 | 1.0000 | 0.2721 | 83818.0 |
| 300 | poll_interval=1.0 | poll_interval | 10 | 8 | 1.00 | 0.20 | 1.00 | 1.0000 | 0.3957 | 76410.4 |

## Reproducibility Manifest

- Python: `3.11.9 (v3.11.9:de54cf5be3, Apr  2 2024, 07:12:50) [Clang 13.0.0 (clang-1300.0.29.30)]`
- Platform: `macOS-15.7.4-arm64-arm-64bit`
- Commands:
  - `e_b6_smoke`: `python3 experiments/e_b_research_suite.py --experiment e-b6 --profile smoke --output-dir data/run_e_b6_smoke`
  - `e_b6_paper`: `python3 experiments/e_b_research_suite.py --experiment e-b6 --profile paper --seeds 0:10 --n-parties 10,30,100 --output-dir data/run_e_b6_paper`
  - `e_b7_smoke`: `python3 experiments/e_b_research_suite.py --experiment e-b7 --profile smoke --output-dir data/run_e_b7_smoke`
  - `e_b7_paper`: `python3 experiments/e_b_research_suite.py --experiment e-b7 --profile paper --seeds 0:10 --n-parties 100,300 --output-dir data/run_e_b7_paper`

## Interpretation

E-B7 turns hidden simulator assumptions into explicit reproducibility and sensitivity variables. It uses a single-factor design around the paper baseline so each changed parameter has a clear interpretation.
