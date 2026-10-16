# Architecture and workflow

```text
Synthetic simulator or approved labeled CSV
                 |
                 v
      CSV schema and value validation
                 |
                 v
    Numeric network-flow feature matrix
          /                      \
         v                        v
 Random Forest classifier    Isolation Forest
 supervised attack label    fit to benign flows
          \                      /
           v                    v
          Probability + anomaly flag
                      |
                      v
     Alert, severity, reason, and scored CSV
                      |
              +-------+-------+
              v               v
        alerts.csv      summary PNG + metrics
```

## Modules

- `simulation.py`: creates deterministic, labeled **synthetic** records for benign,
  denial-of-service (DoS), brute-force, port-scan, and data-exfiltration patterns.
- `data.py`: loads a CSV, checks required columns and labels, and rejects invalid features.
- `models.py`: trains a Random Forest classifier, tests it on a stratified holdout, and
  fits an Isolation Forest using only benign training rows.
- `reporting.py`: writes scored records, alert-only records, a chart, and optional metrics.
- `cli.py`: connects the stages as `generate`, `train`, `detect`, or `demo`.

## Important interpretation

This is a local educational simulation, not a production IDS or a substitute for a SOC.
Its generated data uses deliberately learnable patterns. Metrics on synthetic data do
not establish real-world detection performance. The Isolation Forest is trained only on
normal examples, but its outlier flag is combined with the classifier into the final
`alert`; review alert volume and false positives before interpreting output.

`attack_type` is retained for evaluation and explanation, but is excluded from model
features. A custom dataset must map its labels into the documented schema.
