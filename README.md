# AI-Powered Cybersecurity Threat Detection System

A beginner-friendly, reproducible project that trains and runs a machine-learning
pipeline over **synthetic network-flow telemetry**. It combines a Random Forest
classifier with an Isolation Forest anomaly detector and writes reviewable CSV, JSON,
and PNG outputs.

> **Scope and safety:** This is an educational offline simulation, not a production
> intrusion-detection system. It creates no network traffic and does not scan or attack
> any system. Synthetic-data metrics are not evidence of real-world security efficacy.

## Problem and industry relevance

Security teams receive more network, endpoint, and identity events than they can
manually inspect. Detection systems help prioritize suspicious events, surface unusual
behavior, and give analysts evidence to investigate. Banks may use related analytics
for account abuse and fraud; IT and product companies use monitoring for intrusion
detection, abuse prevention, and service reliability. Real organizations combine
telemetry, threat intelligence, rules, machine learning, analyst review, and response
controls; this project demonstrates a small offline version of the detection and
triage workflow.

## What the demo does

1. Generates benign and simulated DoS, brute-force, port-scan, and data-exfiltration
   flow records.
2. Validates feature columns and binary ground-truth labels.
3. Trains a Random Forest classifier and evaluates it on a stratified holdout.
4. Fits an Isolation Forest using benign training records.
5. Creates alerts when either model flags traffic, then saves scores and a chart.

`attack_type` is not provided as a model feature. The model sees numeric flow features;
the label is used only for training/evaluation and for the synthetic report context.

## Architecture

```text
Synthetic telemetry / labeled CSV
        -> validation and feature matrix
        -> Random Forest + benign-only Isolation Forest
        -> probability + anomaly flag
        -> alert, severity, reason
        -> CSV reports + metrics JSON + PNG chart
```

See [docs/architecture.md](docs/architecture.md) and
[docs/dataset-format.md](docs/dataset-format.md). The detailed beginner guide, build
phases, and portfolio checklist are in [docs/project-guide.md](docs/project-guide.md).

## Tech stack

| Option | Stack | Difficulty | GPU |
|---|---|---|---|
| A — starter | Python, Pandas, scikit-learn, CSV | Beginner; rules + one classifier | No |
| B — selected | Python, NumPy, Pandas, scikit-learn, Matplotlib; Random Forest + Isolation Forest | Beginner/intermediate; this repository | No |
| C — advanced | CICIDS/UNSW-NB15, streaming broker, feature store, XGBoost/deep learning, SIEM integration | Advanced; infrastructure and data handling required | Usually not for tree models; may help for deep learning |

Option B is selected: the whole demo runs locally without a GPU or a corporate system,
and it produces inspectable, reproducible artifacts suitable for a GitHub portfolio.
Possible real public datasets include UNSW-NB15 and CICIDS; this repository uses
synthetic data by default and does not redistribute third-party data.

## Project layout

```text
AI-Powered Cybersecurity Threat Detection/
├── data/
│   ├── raw/                  # Optional approved public datasets; not committed
│   └── processed/            # Generated example CSV; ignored by Git
├── docs/                     # Architecture and external dataset schema
├── images/                   # Optional portfolio screenshots
├── models/                   # Locally trained model bundle; ignored by Git
├── outputs/                  # CSV, JSON, and PNG demo reports; ignored by Git
├── src/threat_detection/     # Simulation, validation, models, reporting, CLI
├── tests/                    # Pipeline and validation tests
├── main.py                   # Project command entry point
├── requirements.txt
└── README.md
```

## Requirements and installation

- Python 3.10–3.12 recommended
- No GPU required
- Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use the virtual environment interpreter directly:
`.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

VS Code can recommend the Python and Pylance extensions after opening the project.

## Run the full demo

From the project root:

```bash
python main.py demo
```

Optional deterministic larger run:

```bash
python main.py demo --samples 10000 --seed 17
```

The command generates the dataset, trains and saves both models, scores the records,
and writes:

- `data/processed/synthetic_traffic.csv`
- `models/threat_detector.joblib`
- `outputs/detection_results.csv` — all records with scores and alert reasons
- `outputs/alerts.csv` — rows where the classifier or anomaly detector raised an alert
- `outputs/detection_summary.png` — alert counts and simulated attack categories
- `outputs/dashboard.html` — local browser-friendly dashboard for the latest run
- `outputs/metrics.json` — held-out classifier metrics and confusion matrix

Open `outputs/dashboard.html` in a browser to review the chart, model metrics, alert
sample, and links to generated files.

Model bundles use Joblib/pickle serialization. Load only model files you trust.

## Run each stage separately

```bash
python main.py generate --samples 5000 --seed 42
python main.py train
python main.py detect --input data/processed/synthetic_traffic.csv
```

Use `python main.py --help` or `python main.py detect --help` to see command options.
Detection accepts the nine feature columns without ground-truth labels. Training requires
both `is_attack` and `attack_type`. For a custom labeled CSV:

```bash
python main.py train --data data/processed/your_labeled_flows.csv
python main.py detect --input data/processed/your_labeled_flows.csv
```

If your dataset has different names, units, labels, or encoding, map them deliberately
to the schema in [docs/dataset-format.md](docs/dataset-format.md) and retain a record of
the transformation. Training and evaluating on the same dataset can produce optimistic
metrics; the displayed classifier scores come from a held-out split, while the demo's
alert report scores the generated rows for demonstration.

## Evaluation and interpretation

The train command reports accuracy, precision, recall, F1, and a confusion matrix in
`[[true negatives, false positives], [false negatives, true positives]]` order. In
security triage, examine recall (missed attacks) alongside precision (false alarms),
class balance, and the cost of each error; accuracy alone can be misleading. The saved
metrics evaluate the supervised classifier only. Final alerts combine its prediction
with an anomaly flag and therefore are not the same metric.

The simulator deliberately embeds patterns such as high connection rates for DoS,
repeated failed logins for brute force, many destination ports for scanning, and large
outbound transfer volume for exfiltration. This makes the exercise explainable, not a
realistic substitute for validation on independent telemetry.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests verify deterministic simulation, data validation, model training/loading,
detection output, and report creation.

## Screenshots and portfolio proof

After a demo, open `outputs/detection_summary.png`, `outputs/alerts.csv`, and
`outputs/metrics.json`. Capture screenshots of the terminal command and chart, and add
them under `images/` if you want them committed. Explain the dataset source, schema
mapping, limitations, metrics, and one investigated false positive or false negative.
Do not present simulated alerts or metrics as production results.

## Learning outcomes

- Building a deterministic dataset simulator and validating a data contract
- Avoiding label leakage by excluding attack type from model features
- Splitting labeled data for evaluation and reporting security-relevant metrics
- Comparing supervised classification and unsupervised anomaly detection
- Turning model outputs into explainable, reviewable alerts and artifacts
- Documenting dataset limits, reproducibility, and ethical boundaries

## GitHub publishing checklist

1. Create an empty public GitHub repository with a clear description and Python topic.
2. Check `git status`; do not add `.venv/`, private or licensed datasets, model bundles,
   secrets, or unreviewed output.
3. Run the demo and tests locally. Add only screenshots or small, non-sensitive examples
   you intend to publish.
4. Initialize Git if needed, commit the source and documentation, and push to GitHub.
5. Add a concise repository description, topics such as `cybersecurity`, `machine-learning`,
   `python`, and `network-security`, then pin the repository to your profile.
6. In applications, describe what you implemented and the synthetic-data limitation
  honestly; never claim production SOC deployment.

## License and dataset note

No third-party dataset is bundled. Check the license and acceptable-use terms for any
dataset you download before using or publishing it. Add a project license only after
choosing terms you are comfortable applying to your original code.
