"""Write detection reports and simple visual summaries."""

from pathlib import Path
from html import escape
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def write_detection_outputs(
    results: pd.DataFrame,
    output_dir: str | Path,
    metrics: dict[str, object] | None = None,
) -> dict[str, Path]:
    """Save scored traffic, alert-only CSV, a chart, and optional model metrics."""
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)

    results_path = folder / "detection_results.csv"
    alerts_path = folder / "alerts.csv"
    chart_path = folder / "detection_summary.png"
    metrics_path = folder / "metrics.json"
    dashboard_path = folder / "dashboard.html"

    results.to_csv(results_path, index=False)
    results.loc[results["alert"] == 1].to_csv(alerts_path, index=False)
    _plot_summary(results, chart_path)
    _write_dashboard(results, dashboard_path, metrics)
    paths = {
        "results": results_path,
        "alerts": alerts_path,
        "chart": chart_path,
        "dashboard": dashboard_path,
    }
    if metrics is not None:
        pd.Series(metrics).to_json(metrics_path, indent=2)
        paths["metrics"] = metrics_path
    return paths


def _write_dashboard(
    results: pd.DataFrame,
    path: Path,
    metrics: dict[str, object] | None,
) -> None:
    metric_cards = ""
    if metrics is not None:
        metric_cards = "".join(
            f'<article class="metric"><span>{label}</span><strong>{metrics[key]:.1%}</strong></article>'
            for key, label in (
                ("accuracy", "Accuracy"),
                ("precision", "Precision"),
                ("recall", "Recall"),
                ("f1", "F1 score"),
            )
        )
    else:
        metric_cards = (
            '<article class="metric"><span>Model evaluation</span>'
            '<strong>Not supplied</strong></article>'
        )

    alert_count = int(results["alert"].sum())
    attack_count = int((results["is_attack"] == 1).sum())
    confusion = ""
    if metrics is not None:
        confusion = (
            "<p>Held-out confusion matrix (TN, FP / FN, TP): "
            f"<code>{escape(json.dumps(metrics['confusion_matrix']))}</code></p>"
        )

    columns = ("attack_type", "attack_probability", "anomaly_score", "severity", "alert_reason")
    alert_rows = results.loc[results["alert"] == 1].sort_values(
        ["attack_probability", "anomaly_score"], ascending=False
    )
    table_rows = []
    for _, row in alert_rows.head(12).iterrows():
        cells = []
        for column in columns:
            value = row[column]
            if column in ("attack_probability", "anomaly_score"):
                value = f"{value:.4f}"
            cells.append(f"<td>{escape(str(value))}</td>")
        table_rows.append("<tr>" + "".join(cells) + "</tr>")
    if not table_rows:
        table_rows.append('<tr><td colspan="5">No alerts in this input.</td></tr>')

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Detection | Run Dashboard</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, "Segoe UI", Arial, sans-serif; background: #0b1220; color: #e5edf8; }}
    body {{ max-width: 1120px; margin: 36px auto; padding: 0 22px 48px; }}
    h1 {{ margin-bottom: 8px; font-size: clamp(1.8rem, 4vw, 2.6rem); }}
    .subtle {{ color: #9fb0c8; }}
    .notice {{ padding: 14px 16px; border: 1px solid #725c31; border-radius: 12px; background: #2b2519; color: #f4d28a; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(165px, 1fr)); gap: 14px; margin: 22px 0; }}
    .metric, section {{ background: #121d2e; border: 1px solid #24344d; border-radius: 14px; }}
    .metric {{ padding: 18px; }} .metric span {{ display: block; color: #9fb0c8; font-size: .9rem; }}
    .metric strong {{ display: block; margin-top: 8px; font-size: 1.65rem; }}
    section {{ margin-top: 18px; padding: 18px; overflow: hidden; }}
    section h2 {{ margin-top: 0; font-size: 1.15rem; }}
    .chart {{ display: block; max-width: 100%; margin: 0 auto; border-radius: 8px; }}
    .links {{ display: flex; flex-wrap: wrap; gap: 12px; }}
    a {{ color: #8fc8ff; }} .links a {{ padding: 9px 12px; border-radius: 8px; background: #1b2b42; text-decoration: none; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #293a52; text-align: left; }}
    th {{ color: #a9bfdc; white-space: nowrap; }}
    code {{ color: #b8d6ff; }}
  </style>
</head>
<body>
  <p class="subtle">AI-POWERED CYBERSECURITY · LOCAL SIMULATION</p>
  <h1>Threat Detection Run</h1>
  <p class="subtle">A review dashboard for this offline run. Alerts are model flags, not confirmed incidents.</p>
  <div class="notice"><strong>Educational simulation:</strong> this report uses synthetic telemetry;
  its metrics do not demonstrate production detection performance.</div>
  <div class="metrics">
    <article class="metric"><span>Traffic records</span><strong>{len(results):,}</strong></article>
    <article class="metric"><span>Alert records</span><strong>{alert_count:,}</strong></article>
    <article class="metric"><span>Known simulated attacks</span><strong>{attack_count:,}</strong></article>
    {metric_cards}
  </div>
  <section><h2>Detection overview</h2><img class="chart" src="detection_summary.png" alt="Detection outcomes and alert categories"></section>
  <section><h2>Highest-scoring alerts</h2>
    <div class="table-wrap"><table><thead><tr>
      <th>Label</th><th>Attack probability</th><th>Anomaly score</th><th>Severity</th><th>Reason</th>
    </tr></thead><tbody>{''.join(table_rows)}</tbody></table></div>
  </section>
  <section><h2>Run artifacts</h2><div class="links">
    <a href="alerts.csv">Alert CSV</a><a href="detection_results.csv">Scored traffic CSV</a>
    <a href="metrics.json">Metrics JSON</a>
  </div>{confusion}</section>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def _plot_summary(results: pd.DataFrame, path: Path) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    alert_counts = results["alert"].map({0: "No alert", 1: "Alert"}).value_counts()
    axes[0].bar(alert_counts.index, alert_counts.values, color=["#4c9f70", "#d9534f"])
    axes[0].set_title("Detection outcomes")
    axes[0].set_ylabel("Traffic records")

    alerted = results.loc[results["alert"] == 1]
    labeled_alerts = alerted.loc[alerted["attack_type"] != "unknown", "attack_type"]
    if not alerted.empty and labeled_alerts.empty:
        severity_counts = alerted["severity"].value_counts()
        axes[1].bar(severity_counts.index, severity_counts.values, color="#e49b3f")
        axes[1].set_ylabel("Alerted records")
        axes[1].set_title("Alert records by severity (no labels supplied)")
    elif alerted.empty:
        axes[1].text(0.5, 0.5, "No alerts in this input", ha="center", va="center")
        axes[1].set_xticks([])
        axes[1].set_yticks([])
    else:
        attack_counts = labeled_alerts.value_counts()
        axes[1].bar(attack_counts.index, attack_counts.values, color="#e49b3f")
        axes[1].tick_params(axis="x", rotation=25)
        axes[1].set_ylabel("Alerted records")
        axes[1].set_title("Alert records by supplied label")
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)
