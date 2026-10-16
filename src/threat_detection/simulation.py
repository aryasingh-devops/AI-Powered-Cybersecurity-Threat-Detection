"""Generate deterministic, labeled network telemetry for safe local demos."""

from __future__ import annotations

import numpy as np
import pandas as pd

ATTACK_TYPES = ("benign", "dos", "brute_force", "port_scan", "data_exfiltration")
FEATURE_COLUMNS = (
    "duration_ms",
    "bytes_sent",
    "bytes_received",
    "packets",
    "dst_port",
    "protocol",
    "failed_logins",
    "connection_rate",
    "unique_dst_ports",
)
LABEL_COLUMNS = ("is_attack", "attack_type")


def generate_traffic(samples: int = 5000, seed: int = 42) -> pd.DataFrame:
    """Create synthetic benign and attack flows without generating real traffic."""
    if samples < 20:
        raise ValueError("samples must be at least 20 to include train/test examples.")

    rng = np.random.default_rng(seed)
    attack_types = rng.choice(
        ATTACK_TYPES,
        size=samples,
        p=(0.72, 0.10, 0.07, 0.06, 0.05),
    )

    duration = np.clip(rng.lognormal(5.0, 0.9, samples), 1, 120_000)
    bytes_sent = np.clip(rng.lognormal(7.0, 1.2, samples), 20, 2_000_000)
    bytes_received = np.clip(rng.lognormal(7.2, 1.2, samples), 20, 2_000_000)
    packets = np.clip(rng.poisson(18, samples) + 1, 1, 100_000)
    common_ports = np.array([22, 53, 80, 123, 443, 445, 8080])
    dst_port = rng.choice(common_ports, size=samples).astype(int)
    protocol = rng.choice([0, 1, 2], size=samples, p=(0.78, 0.20, 0.02))
    failed_logins = rng.poisson(0.15, samples)
    connection_rate = np.clip(rng.lognormal(1.0, 0.7, samples), 0, 100_000)
    unique_dst_ports = np.clip(rng.poisson(1.2, samples) + 1, 1, 65_535)

    masks = {
        "dos": attack_types == "dos",
        "brute_force": attack_types == "brute_force",
        "port_scan": attack_types == "port_scan",
        "data_exfiltration": attack_types == "data_exfiltration",
    }

    count = int(masks["dos"].sum())
    connection_rate[masks["dos"]] = rng.lognormal(7.0, 0.6, count)
    packets[masks["dos"]] = rng.poisson(1_200, count) + 100
    bytes_sent[masks["dos"]] = rng.lognormal(10.0, 0.8, count)

    count = int(masks["brute_force"].sum())
    failed_logins[masks["brute_force"]] = rng.integers(8, 80, count)
    dst_port[masks["brute_force"]] = 22
    connection_rate[masks["brute_force"]] = rng.lognormal(3.0, 0.5, count)

    count = int(masks["port_scan"].sum())
    unique_dst_ports[masks["port_scan"]] = rng.integers(20, 500, count)
    connection_rate[masks["port_scan"]] = rng.lognormal(4.5, 0.5, count)

    count = int(masks["data_exfiltration"].sum())
    bytes_sent[masks["data_exfiltration"]] = rng.lognormal(13.0, 0.7, count)
    bytes_received[masks["data_exfiltration"]] = rng.lognormal(5.0, 0.8, count)
    duration[masks["data_exfiltration"]] = rng.lognormal(8.0, 0.6, count)

    return pd.DataFrame(
        {
            "duration_ms": duration.round(2),
            "bytes_sent": bytes_sent.round().astype(int),
            "bytes_received": bytes_received.round().astype(int),
            "packets": packets.astype(int),
            "dst_port": dst_port.astype(int),
            "protocol": protocol.astype(int),
            "failed_logins": failed_logins.astype(int),
            "connection_rate": connection_rate.round(2),
            "unique_dst_ports": unique_dst_ports.astype(int),
            "is_attack": (attack_types != "benign").astype(int),
            "attack_type": attack_types,
        }
    )
