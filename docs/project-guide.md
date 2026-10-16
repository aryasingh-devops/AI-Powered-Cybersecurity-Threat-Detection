# Beginner-to-portfolio project guide

This guide explains the implementation in practical stages. Run commands from the
project root folder.

## A. What threat detection means

### In simple language

Cybersecurity threat detection is the process of noticing activity that may harm a
computer system, network, account, or data. An AI-assisted detector learns patterns
from examples and helps sort a large stream of events into ordinary and suspicious
activity. It helps a person decide what to investigate; it does not prove an attack or
replace security analysts.

### In technical language

An intrusion detection pipeline ingests telemetry, transforms it into features,
evaluates rules or statistical/ML models, and emits prioritized events for investigation.
Supervised classification learns from labeled benign/attack examples. Anomaly detection
learns a baseline and identifies observations that differ from it. Production detection
usually combines multiple data sources, rules, identity and asset context, threat
intelligence, human review, and response controls.

### Problems and example use cases

- **Intrusion detection:** prioritize events that resemble known malicious behavior.
- **Fraud and account abuse:** flag unusual transactions or sign-in patterns for review.
- **Anomaly detection:** detect meaningful deviations from a user, host, or service
  baseline.
- **Malware detection:** classify suspicious file or process behavior (not implemented
  in this network-flow project).
- **Network monitoring:** summarize flows and identify unusual connection behavior.

Banks may apply related analytics to payment risk, account takeover, and network
monitoring. IT providers may use it to triage endpoint and network events. Product
companies may use it for abuse prevention, service protection, and account security.
These are industry use cases, not claims that this small demo is deployed or equivalent
to a commercial security product.

## B. Workflow in this repository

1. **Collection:** the simulator creates offline flow records; alternatively, supply an
   approved labeled CSV.
2. **Preprocessing:** validate the CSV columns, numeric values, labels, and non-negative
   feature values.
3. **Feature engineering:** use duration, byte counts, packets, destination port,
   protocol, failed logins, connection rate, and distinct destination ports.
4. **Training:** split labeled records into stratified training and holdout sets. Fit
   the Random Forest using labels; fit Isolation Forest only on benign training rows.
5. **Prediction:** compute attack probability, classifier output, and anomaly flag.
6. **Alerting:** alert if either model flags a record; attach severity and a short
   explanation. Severity here is a probability-based demo heuristic, not an incident
   response priority policy.
7. **Visualization:** write scored and alert-only CSV files, held-out metrics JSON, and
   a PNG chart plus a browser-friendly HTML dashboard.

The simulator deliberately marks traffic categories, but labels are never included in
the model feature matrix. Inference-only CSVs may omit labels; they appear as `unknown`
in the report and are not used to explain why the model raised an alert.

## C. Stack options

| Option | Libraries and data | Difficulty | Output | GPU |
|---|---|---|---|---|
| A — easiest | Python, Pandas, scikit-learn; small synthetic CSV or one public dataset | Beginner | One model, metrics, and CSV alerts | No |
| B — selected here | Python, NumPy, Pandas, scikit-learn, Matplotlib; synthetic telemetry or schema-mapped UNSW-NB15/CICIDS flows | Beginner/intermediate | Classifier + anomaly scores, CSV/JSON reports, PNG chart | No |
| C — advanced | Stream broker, SIEM, enriched CICIDS/UNSW-NB15 or authorized enterprise telemetry, boosted trees or deep models | Advanced; infrastructure and safe data access required | Streaming detections, enrichment, dashboards, monitored deployment | Generally no for tree models; often useful for deep learning |

Option B is a practical student balance: the default demo runs locally on a CPU without
access to corporate infrastructure, but the code still demonstrates data validation,
holdout metrics, model persistence, alerting, and reporting. Public datasets are not
downloaded automatically; check licensing and dataset documentation.

## Phase-by-phase implementation plan

| Phase | What to do | Why | Expected output | Common mistake | Verify it |
|---|---|---|---|---|---|
| 1 — Setup | Install Python, create `.venv`, install `requirements.txt` | Isolate project dependencies | Working Python environment | Installing into a different interpreter | `python --version` and `python -c "import pandas, sklearn"` |
| 2 — Dataset loading | Run `generate`, or map a reviewed public CSV to the documented schema | Make telemetry available in a consistent format | `data/processed/synthetic_traffic.csv` | Assuming dataset columns or labels match without checking | Open CSV and check required fields and row count |
| 3 — Data cleaning | Use `load_dataset` schema and value validation | Reject malformed, missing, or invalid feature data | Validated DataFrame or explicit error | Silently coercing bad values or dropping labels | `python main.py train` succeeds on valid labeled input and fails clearly on invalid input |
| 4 — Feature engineering | Use the nine network flow features | Convert raw records into numeric model inputs | Feature matrix, without labels or attack type | Leaking `attack_type` into model features | Review `FEATURE_COLUMNS` and model feature selection |
| 5 — Model building | Train Random Forest and benign-only Isolation Forest | Combine known-label classification and normal-baseline anomaly scoring | `models/threat_detector.joblib` | Fitting anomaly model on attacks, or training on inference-only CSV | `python main.py train` and check that model file is created |
| 6 — Model evaluation | Check holdout precision, recall, F1, accuracy, and confusion matrix | Understand errors and avoid relying on accuracy alone | Metrics printed and saved in demo `metrics.json` | Reporting training-set score as test performance | Confirm stratified holdout split and confusion-matrix ordering |
| 7 — Threat detection | Score traffic, combine classifier/anomaly flags, review severity and reason | Turn scores into analyst-reviewable events | Scored CSV and alert-only CSV | Treating every anomaly as a confirmed incident | Compare classifier probability and anomaly flag in `detection_results.csv` |
| 8 — Visualization | Review summary plot and metrics JSON | Make alert volume and model behavior easy to inspect | `outputs/detection_summary.png` and `metrics.json` | Treating chart counts as a complete evaluation | Check chart and compare counts to CSV and held-out metrics |
| 9 — GitHub publishing | Check ignore rules, publish code/docs/tests and selected screenshots | Make the work reproducible and reviewable | GitHub source repository with README | Committing secrets, private traffic, or generated model/data by accident | `git status --short` before adding and committing |
| 10 — Final proof | Re-run demo/tests and capture genuine terminal/chart/alert evidence | Show that the project actually runs and state its limits | Reproducible demo artifacts and honest portfolio summary | Claiming simulated data as a real SOC deployment | `python main.py demo`, `python -m unittest discover -s tests -v`, and review proof checklist |

## D. Architecture

```text
Synthetic simulator / reviewed labeled CSV
                  |
                  v
          CSV schema validation
                  |
                  v
             Flow features
              /         \
             v           v
       Random Forest   Isolation Forest
       labeled data    benign training rows
              \         /
               v       v
         prediction + anomaly score
                  |
                  v
          alert + severity + reason
                  |
                  v
     CSV reports + metrics JSON + PNG chart
```

The implementation details are in [architecture.md](architecture.md).

## E. Folder structure

- `data/raw/`: place an approved external dataset here locally; it is not committed.
- `data/processed/`: generated example traffic CSV; ignored by Git.
- `src/threat_detection/`: simulation, data checks, model training/scoring, reports, CLI.
- `models/`: trained local Joblib model; ignored by Git.
- `outputs/`: generated reports and chart; ignored by Git.
- `tests/`: repeatability, validation, unlabeled inference, training, and reporting tests.
- `docs/`: architecture, data schema, and this guide.
- `images/`: optional screenshots for the portfolio README.
- `.vscode/extensions.json`: recommends the Microsoft Python and Pylance extensions.

## F. Installation

Python 3.10–3.12 is recommended; the demo needs no GPU.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If activation is blocked by policy, run
`.\.venv\Scripts\python.exe -m pip install -r requirements.txt` instead.

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

VS Code's extension recommendation is optional; the runtime only needs the Python
packages in `requirements.txt`.

## G. Code map

| File | Responsibility |
|---|---|
| `main.py` | Root entry point |
| `src/threat_detection/simulation.py` | Repeatable, safe synthetic traffic generation |
| `src/threat_detection/data.py` | Feature and label schema validation |
| `src/threat_detection/models.py` | Train, evaluate, load, and score the two models |
| `src/threat_detection/reporting.py` | CSV, JSON, and chart output |
| `src/threat_detection/cli.py` | `demo`, `generate`, `train`, and `detect` commands |
| `tests/test_pipeline.py` | Automated checks for the end-to-end behavior |

Run the source files via `main.py`; copying code into a notebook is not necessary.

## H. Safe virtual simulation

The generated CSV is simulated **network-flow metadata**, not packet capture and not
real corporate traffic. DoS-like rows have high packet/connection rates; brute-force
rows have repeated failed logins and target port 22; scans touch many destination ports;
exfiltration-like rows have unusually high outbound bytes. The simulator uses fixed
random seeds so the run can be reproduced.

1. Generate the data: `python main.py generate --samples 5000 --seed 42`.
2. Check the row count, class counts, and attack types in
   `data/processed/synthetic_traffic.csv`.
3. Train and inspect holdout metrics: `python main.py train`.
4. Score traffic: `python main.py detect`.
5. Review `outputs/alerts.csv`; compare `attack_probability`, `anomaly_flag`, `severity`,
   and `alert_reason`.
6. Open `outputs/detection_summary.png` and `outputs/metrics.json`.
   You can also open `outputs/dashboard.html` in a browser for a combined run summary.
7. For inference without known labels, provide a CSV with only the nine numeric feature
   columns to `detect`.
8. Capture screenshots of the successful terminal run, chart, and a few sanitized alert
   rows; explain one false positive or false negative as a learning reflection.

The demo's full data has labels so it can be trained and evaluated. Its `alerts.csv`
shows the combined detector output; it can include benign outliers, so alert count is
not the same as true attack count. Classifier metrics are measured on a held-out
supervised split, while anomaly and combined alert accuracy are not claimed by those
metrics.

## I. Run and verify

Complete demo:

```bash
python main.py demo
```

Separate steps:

```bash
python main.py generate --samples 5000
python main.py train
python main.py detect --input data/processed/synthetic_traffic.csv
python -m unittest discover -s tests -v
```

Successful execution creates `models/threat_detector.joblib` and the three detection
files and `dashboard.html` in `outputs/`; the demo also creates `metrics.json`. The held-out metric values can
vary if the sample size or seed changes. A positive alert with nonzero probability or an
anomaly flag is an example of detection, not proof of an actual compromise.

## J. GitHub publishing steps

1. Create a new empty GitHub repository, for example
   `ai-cybersecurity-threat-detection`.
2. Open PowerShell in this folder and review `git status --short`; confirm generated
   datasets, model files, virtual environments, and secrets are not staged.
3. If this folder is not already a Git repository, initialize and make the first commit:

   ```powershell
   git init
   git add README.md requirements.txt .gitignore .vscode data docs images src tests main.py
   git status --short
   git commit -m "Build simulated AI threat detection project"
   ```

4. Add the repository's GitHub URL as `origin` and push the branch shown by `git branch
   --show-current` (often `main`). The exact URL is provided by GitHub when creating the
   repository.
5. Add a clear description and topics such as `cybersecurity`, `machine-learning`,
   `python`, and `network-security`. Pin the repository to your profile.
6. Add genuine screenshots and a short explanation of your contribution and project
   limitations. Do not claim employment-grade SOC deployment.

This environment is not currently a Git repository, so the above GitHub steps are
instructions only; no repository or remote was created.

## K. README

The root [README.md](../README.md) is the recruiter-facing project overview with setup,
commands, output artifacts, evaluation notes, tests, and publishing checklist.

## L. Suggested commit plan

Use small, truthful commits when developing the project:

1. `Add reproducible synthetic network traffic generator`
2. `Validate labeled and inference-only flow datasets`
3. `Train supervised and anomaly detection models`
4. `Write alert reports and detection visualization`
5. `Document workflow and add end-to-end tests`

Do not create these commits retroactively just to make activity look larger; commit only
work that actually exists at that point.

## M. Proof checklist

- [ ] Public repository has a clear title, description, topics, and license decision.
- [ ] README explains synthetic data and does not imply production deployment.
- [ ] `python main.py demo` runs from a clean environment.
- [ ] `python -m unittest discover -s tests -v` passes.
- [ ] A terminal screenshot shows the command and metrics.
- [ ] A chart screenshot shows alert summaries.
- [ ] A sanitized example alert is explained, including probability and reason.
- [ ] Dataset source, license, schema mapping, and limitations are documented if using
  external data.
- [ ] No secrets, private traffic, personal information, generated model, or oversized
  output files are committed.
- [ ] Reflection discusses false positives, false negatives, class balance, and why
  synthetic results cannot establish production readiness.
