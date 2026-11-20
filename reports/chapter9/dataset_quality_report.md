# AI SOC Dataset Quality Report

- Dataset: `datasets/final/dataset_final.jsonl`
- Total records: 111
- Quality status: **review_required**
- Duplicate records: 0
- Class imbalance ratio: 19.0

## Binary Label Distribution
- unlabeled: 91
- malicious: 19
- benign: 1

## Multi-Class Distribution
- unknown: 91
- auth_attack: 15
- benign: 1
- recon: 1
- web_attack: 1
- fim_event: 1
- suspicious_command: 1

## Scenario Distribution
- unmatched: 91
- auth_ssh_failure: 15
- normal_web_access: 1
- recon_nmap_light: 1
- web_input_dummy: 1
- fim_dummy_event: 1
- suspicious_command_note: 1

## Correlation Status
- alert_without_ground_truth: 91
- matched_alert: 15
- ground_truth_without_alert: 5

## Source of Truth
- wazuh_alert_only: 91
- ground_truth_correlated: 15
- ground_truth_only: 5

## Data Quality
- Missing values: `{"timestamp": 0, "agent_name": 5, "rule_id": 5, "full_log": 0, "binary_label": 0, "multi_class_label": 91}`
- Low-confidence correlations: 15
- Archive records: 0
- Leakage fields: `['binary_label', 'label', 'multi_class_label', 'run_id', 'scenario_id']`

## Leakage Warning
Exclude run_id, scenario_id, payload_id, expected_label, label, binary_label and multi_class_label from model input. Label fields remain available as prediction targets.

## Known Limitations
- 91 alerts belum memiliki ground truth; belum tentu semuanya false positive.
- 5 ground truth tidak memiliki alert Wazuh yang cocok; perlu pemeriksaan detection gap.
- 15 korelasi memiliki confidence rendah dan memerlukan review analis.
- Class imbalance sebesar 19.0:1.
- 91 record masih unlabeled.
- Archive sample tidak tersedia pada run ini.

## Reproducibility
- Git commit: `35eb1c5135fc2226bf5727cd575a29a8fa3e4006`
- SHA256: `539f34ada4bbde7daa66c87e6eba63feef315acbfd8198ec027c1a540245161e`

Validasi mencatat kondisi dataset sebenarnya. Unlabeled dan low-confidence tidak boleh dianggap sebagai label yang sudah terverifikasi.
