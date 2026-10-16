# Data directory

- `raw/` is reserved for a downloaded public dataset that you have reviewed and are licensed to use.
- `processed/` receives the deterministic synthetic traffic CSV created by the CLI.
- Generated data is ignored by Git. Do not commit sensitive, personal, or unlicensed data.

Run `python main.py generate` to create the example dataset. For a CSV schema and adaptation notes, see [docs/dataset-format.md](../docs/dataset-format.md).
