# AI SOC Wazuh Dataset

## Version
v0.1.0

## Generated
2026-11-19T12:17:51.089766Z

## Git Commit
b9a1933a2b01282934d7ad7c883fd1f334a9f87b

## Source
Dataset dibuat dari evidence pack lab Wazuh:
- Ground truth JSONL
- Wazuh alerts
- Archive sample
- Script execution log
- Correlation pipeline

## Files
- `dataset.jsonl` untuk LLM dan pipeline streaming
- `dataset.csv` untuk eksplorasi cepat
- `dataset.parquet` untuk efisiensi analitik
- `schema.json` untuk struktur field
- `DATASET_CARD.json` untuk metadata dataset

## Label Distribution
{
  "unlabeled": 106,
  "malicious": 5,
  "benign": 1
}

## Multi-Class Distribution
{
  "unknown": 106,
  "benign": 1,
  "recon": 1,
  "auth_attack": 1,
  "web_attack": 1,
  "fim_event": 1,
  "suspicious_command": 1
}

## Ethical Use
Dataset ini hanya untuk edukasi, riset defensif,
AI SOC, dan lab legal. Tidak untuk menyerang sistem publik.

## Known Limitations
- Dataset berasal dari lab tertutup.
- Hanya enam record memiliki Ground Truth.
- Belum ada korelasi Ground Truth dan Wazuh yang berhasil.
- Distribusi kelas belum mewakili lingkungan produksi.
- Data perlu review sebelum publikasi eksternal.

## Leakage Warning
Jangan gunakan `run_id`, `scenario_id`, `payload_id`,
`expected_label`, `label`, `binary_label`, atau
`multi_class_label` sebagai fitur input training langsung.
