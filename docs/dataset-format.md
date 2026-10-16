# Dataset format

The pipeline accepts CSV data with these exact required columns:

| Column | Meaning | Example |
|---|---|---:|
| `duration_ms` | Flow duration in milliseconds | `3200` |
| `bytes_sent` | Bytes sent by the source in the flow | `1400` |
| `bytes_received` | Bytes received by the source in the flow | `5000` |
| `packets` | Packet count | `24` |
| `dst_port` | Destination port number | `443` |
| `protocol` | Numeric protocol encoding (`0` TCP, `1` UDP, `2` ICMP in simulator) | `0` |
| `failed_logins` | Failed authentication count, if available | `0` |
| `connection_rate` | Connections per chosen observation interval | `3.5` |
| `unique_dst_ports` | Distinct destination ports contacted by source | `1` |
| `is_attack` | Ground truth: `0` benign or `1` attack | `0` |
| `attack_type` | Ground-truth category such as `benign`, `dos`, or `port_scan` | `benign` |

All nine features must be numeric and non-negative. Both labels are required for
training; inference-only CSVs may omit both label columns. If one label column is
present, the other must also be present. If the public dataset uses different names or
units, perform and document an explicit mapping before training. Different feature
definitions, capture periods, label imbalance, and preprocessing can all change model
results.

Possible public datasets to explore include UNSW-NB15 and CICIDS. Review their terms of
use, data dictionary, and label definitions before adapting them. The project does not
download any dataset automatically.
