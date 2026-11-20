# AI SOC Wazuh Dataset

## Version
v0.1.0

## Generated
2026-11-20T17:06:35.540072Z

## Git Commit
35eb1c5135fc2226bf5727cd575a29a8fa3e4006

## Records
111

## Source
- Ground Truth JSONL
- Wazuh Dashboard export
- Archive sample when available
- Correlation and preprocessing pipeline

## Binary Label Distribution
{
  "unlabeled": 91,
  "malicious": 19,
  "benign": 1
}

## Multi-class Distribution
{
  "unknown": 91,
  "auth_attack": 15,
  "benign": 1,
  "recon": 1,
  "web_attack": 1,
  "fim_event": 1,
  "suspicious_command": 1
}

## Files
- dataset.jsonl: LLM and streaming pipeline
- dataset.csv: exploration and spreadsheet
- dataset.parquet: efficient analytics
- schema.json: field contract
- DATASET_CARD.json: dataset metadata

## Ethical Use
Educational, defensive research, and legal lab use only.

## Known Limitations
- Some events do not contain IP or port information.
- Unmatched alerts remain unlabeled.
- Low-confidence correlations require analyst review.

## Leakage Warning
Do not use run_id, scenario_id, payload_id, expected_label,
label, binary_label, or multi_class_label as direct training features.
