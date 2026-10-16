import tempfile
import unittest
from pathlib import Path
import sys

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_detection.data import load_dataset
from threat_detection.models import load_models, score_traffic, train_models
from threat_detection.reporting import write_detection_outputs
from threat_detection.simulation import generate_traffic


class ThreatDetectionPipelineTests(unittest.TestCase):
    def test_simulation_is_repeatable_and_labeled(self):
        first = generate_traffic(300, seed=7)
        second = generate_traffic(300, seed=7)
        pd.testing.assert_frame_equal(first, second)
        self.assertEqual(set(first["is_attack"].unique()), {0, 1})
        self.assertTrue((first.loc[first["attack_type"] == "benign", "is_attack"] == 0).all())

    def test_training_detection_and_report_outputs(self):
        traffic = generate_traffic(600, seed=19)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            csv_path = folder / "traffic.csv"
            model_path = folder / "model.joblib"
            traffic.to_csv(csv_path, index=False)

            loaded = load_dataset(csv_path)
            metrics = train_models(loaded, model_path, seed=19)
            results = score_traffic(loaded.head(80), load_models(model_path))
            paths = write_detection_outputs(results, folder / "outputs", metrics)

            self.assertGreaterEqual(metrics["recall"], 0.8)
            self.assertEqual(len(results), 80)
            self.assertTrue(set(results["alert"].unique()).issubset({0, 1}))
            self.assertGreater(int(results["alert"].sum()), 0)
            self.assertTrue(all(path.is_file() for path in paths.values()))
            dashboard = paths["dashboard"].read_text(encoding="utf-8")
            self.assertIn("Threat Detection Run", dashboard)
            self.assertIn("Educational simulation", dashboard)

    def test_loader_rejects_missing_feature_columns(self):
        with tempfile.TemporaryDirectory() as temporary:
            csv_path = Path(temporary) / "bad.csv"
            pd.DataFrame({"is_attack": [0, 1], "attack_type": ["benign", "dos"]}).to_csv(
                csv_path, index=False
            )
            with self.assertRaisesRegex(ValueError, "missing required feature columns"):
                load_dataset(csv_path)

    def test_detection_accepts_unlabeled_feature_csv(self):
        traffic = generate_traffic(300, seed=23)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            model_path = folder / "model.joblib"
            train_models(traffic, model_path, seed=23)
            inference_input = folder / "unlabeled.csv"
            traffic.drop(columns=["is_attack", "attack_type"]).head(20).to_csv(
                inference_input, index=False
            )

            data = load_dataset(inference_input, require_labels=False)
            results = score_traffic(data, load_models(model_path))

            self.assertEqual(len(results), 20)
            self.assertTrue(results["is_attack"].isna().all())
            self.assertTrue((results["attack_type"] == "unknown").all())
            self.assertFalse(
                results.loc[results["alert"] == 1, "alert_reason"]
                .str.contains("simulated label", case=False)
                .any()
            )


if __name__ == "__main__":
    unittest.main()
