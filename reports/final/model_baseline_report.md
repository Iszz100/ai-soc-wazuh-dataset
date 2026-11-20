# Model Baseline Report

- Dataset: `datasets/final/dataset.parquet`
- Dataset records: 111
- Labeled records: 20

## Label Distribution
- malicious: 19
- benign: 1

## Supervised Models
- Status: skipped
- Reason: Minimal dua sampel per kelas diperlukan untuk supervised train/test split.

## Isolation Forest
- Status: trained
- Records: 111
- Anomalies: 24
- Normal: 87
- Score minimum: -0.3213
- Score maximum: 0.1646
- Note: Isolation Forest merupakan anomaly baseline, bukan classifier final.

## Rule-Based Baseline
- Status: evaluated
- Rule: rule_level >= 7 -> malicious else benign
- Confusion Matrix: `[[1, 0], [18, 1]]`
- False Positive Rate: 0.0000
- False Negative Rate: 0.9474

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| benign | 0.0526 | 1.0000 | 0.1000 | 1.0 |
| malicious | 1.0000 | 0.0526 | 0.1000 | 19.0 |

## Evaluation Notes
- Dataset kecil dan distribusi kelas belum seimbang.
- Supervised model belum dapat dievaluasi karena jumlah benign tidak mencukupi.
- Isolation Forest merupakan anomaly detection baseline, bukan classifier final.
- Rule-based baseline hanya pembanding sederhana.
- Hasil belum dapat digunakan sebagai bukti kesiapan produksi.

## Conclusion
Eksperimen baseline berhasil dijalankan. Pengembangan selanjutnya membutuhkan lebih banyak data benign, label terverifikasi, dan evaluasi ulang.
