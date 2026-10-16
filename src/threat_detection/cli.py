"""Command-line interface for the complete detection workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from threat_detection.data import load_dataset
from threat_detection.models import load_models, score_traffic, train_models
from threat_detection.reporting import write_detection_outputs
from threat_detection.simulation import generate_traffic

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA = ROOT / "data" / "processed" / "synthetic_traffic.csv"
DEFAULT_MODEL = ROOT / "models" / "threat_detector.joblib"
DEFAULT_OUTPUTS = ROOT / "outputs"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train and run an educational network threat detection pipeline."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("demo", help="Generate data, train, detect, and report.")
    demo.add_argument("--samples", type=int, default=5000)
    demo.add_argument("--seed", type=int, default=42)

    generate = commands.add_parser("generate", help="Generate safe synthetic traffic CSV.")
    generate.add_argument("--samples", type=int, default=5000)
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--output", type=Path, default=DEFAULT_DATA)

    train = commands.add_parser("train", help="Train models from a labeled CSV.")
    train.add_argument("--data", type=Path, default=DEFAULT_DATA)
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL)

    detect = commands.add_parser("detect", help="Score a CSV using a trained model.")
    detect.add_argument("--input", type=Path, default=DEFAULT_DATA)
    detect.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    detect.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUTS)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "generate":
        traffic = generate_traffic(args.samples, args.seed)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        traffic.to_csv(args.output, index=False)
        print(f"Generated {len(traffic):,} rows: {args.output}")
        print(f"Attack rows: {int(traffic['is_attack'].sum()):,}")
    elif args.command == "train":
        data = load_dataset(args.data)
        metrics = train_models(data, args.model)
        print(f"Saved model: {args.model}")
        _print_metrics(metrics)
    elif args.command == "detect":
        data = load_dataset(args.input, require_labels=False)
        bundle = load_models(args.model)
        results = score_traffic(data, bundle)
        paths = write_detection_outputs(results, args.output_dir)
        print(f"Scored {len(results):,} rows; generated {int(results['alert'].sum()):,} alerts.")
        _print_paths(paths)
    elif args.command == "demo":
        traffic = generate_traffic(args.samples, args.seed)
        DEFAULT_DATA.parent.mkdir(parents=True, exist_ok=True)
        traffic.to_csv(DEFAULT_DATA, index=False)
        metrics = train_models(traffic, DEFAULT_MODEL, seed=args.seed)
        bundle = load_models(DEFAULT_MODEL)
        results = score_traffic(traffic, bundle)
        paths = write_detection_outputs(results, DEFAULT_OUTPUTS, metrics=metrics)
        print(f"Generated {len(traffic):,} records, including {int(traffic['is_attack'].sum()):,} simulated attacks.")
        _print_metrics(metrics)
        print(f"Alerts generated: {int(results['alert'].sum()):,}")
        _print_paths(paths)


def _print_metrics(metrics: dict[str, object]) -> None:
    print("Held-out classifier metrics:")
    for key in ("accuracy", "precision", "recall", "f1"):
        print(f"  {key.capitalize():<10} {metrics[key]:.3f}")
    print("  Confusion matrix [[TN, FP], [FN, TP]]:")
    print(f"  {json.dumps(metrics['confusion_matrix'])}")


def _print_paths(paths: dict[str, Path]) -> None:
    print("Output files:")
    for name, path in paths.items():
        print(f"  {name:<8} {path}")


if __name__ == "__main__":
    main()
