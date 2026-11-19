# Dataset Quality Report

- Dataset: `datasets/final/dataset_final.jsonl`
- Total records: 112
- Unique IDs: 112
- Duplicate count: 0

## Label Distribution
- benign: 1
- malicious: 5
- unlabeled: 106

## Multi-Class Distribution
- benign: 1
- recon: 1
- auth_attack: 1
- web_attack: 1
- fim_event: 1
- suspicious_command: 1
- unknown: 106

## Correlation Status
- ground_truth_without_alert: 6
- alert_without_ground_truth: 106

## Source of Truth
- ground_truth_only: 6
- wazuh_alert_only: 106

## Scenario Distribution
- normal_web_access: 1
- recon_nmap_light: 1
- auth_ssh_failure: 1
- web_input_dummy: 1
- fim_dummy_event: 1
- suspicious_command_note: 1
- unmatched: 106

## Missing Values
- timestamp: 0
- agent_name: 6
- rule_id: 6
- full_log: 0
- binary_label: 0
- multi_class_label: 106
- confidence: 0

## Leakage Warning
- expected_label must not be used as a direct model input
- label must not be used as a direct model input
- binary_label must not be used as a direct model input
- multi_class_label must not be used as a direct model input
- scenario_id must not be used as a direct model input
- run_id must not be used as a direct model input
- payload_id must not be used as a direct model input

## Known Limitations
- Only six records have Ground Truth labels.
- No successful Ground Truth-to-Wazuh correlation.
- Class imbalance is significant.
- Unlabeled alerts require analyst review.
- Dataset requires additional controlled experiments.
