# Laporan Akhir AI SOC

## 1. Executive Summary

Dataset AI SOC Wazuh berisi 112 records yang berasal dari
eksperimen lab dan Ground Truth.

Sebanyak 6 records memiliki label Ground Truth, terdiri
dari 1 benign dan 5 malicious. Sementara itu, 106 records
berstatus unlabeled.

Eksperimen baseline menunjukkan keterbatasan data untuk
supervised learning. Isolation Forest berhasil dijalankan
secara eksploratif, tetapi hasilnya belum dapat dijadikan
klaim performa produksi.

## 2. Dataset Overview

- Dataset: ai-soc-wazuh-dataset
- Version: v0.1.0
- Total records: 112
- Ground Truth records: 6
- Wazuh alert tanpa Ground Truth: 106
- Format: JSONL, CSV, Parquet

Pipeline mencakup korelasi, cleaning, feature engineering,
final labeling, validasi, dan ekspor dataset.

## 3. Label Distribution

| Label | Records |
|---|---:|
| Benign | 1 |
| Malicious | 5 |
| Unlabeled | 106 |
| Total | 112 |

Distribusi multi-class:
- benign: 1
- recon: 1
- auth_attack: 1
- web_attack: 1
- fim_event: 1
- suspicious_command: 1
- unknown: 106

## 4. Model Baseline Result

### Supervised Learning

Logistic Regression, Random Forest, dan
Hist Gradient Boosting dilewati karena jumlah
data per kelas tidak mencukupi untuk split stratified.

### Isolation Forest

- Records: 6
- Anomaly: 2
- Normal: 4
- Status: exploratory baseline

Hasil ini bukan ukuran akurasi klasifikasi.

### Rule-Based Baseline

Tidak dapat dievaluasi karena seluruh record Ground Truth
tidak memiliki informasi Wazuh rule_level.

## 5. Temuan Kritis

1. Belum ada korelasi Ground Truth dan Wazuh alert yang berhasil.
2. Enam record Ground Truth belum memiliki alert yang cocok.
3. Terdapat 106 alert tanpa Ground Truth.
4. Distribusi label sangat tidak seimbang.
5. Supervised model belum dapat dievaluasi secara valid.

## 6. Limitations

- Dataset masih berukuran kecil.
- Hanya enam record memiliki Ground Truth.
- Korelasi Ground Truth dan Wazuh belum berhasil.
- Evaluasi supervised learning belum tersedia.
- Isolation Forest masih bersifat eksploratif.
- Dataset belum layak untuk klaim performa produksi.

## 7. Rekomendasi Perbaikan

1. Perbaiki mekanisme korelasi Ground Truth dan Wazuh.
2. Perbanyak benign traffic.
3. Tambahkan variasi skenario dan host.
4. Review false positive dan false negative.
5. Tambahkan data berlabel yang tervalidasi.
6. Ulangi evaluasi setelah dataset mencukupi.

## 8. Next Step

1. Audit korelasi dan timestamp.
2. Jalankan eksperimen lab tambahan.
3. Perbanyak Ground Truth dan benign traffic.
4. Evaluasi ulang model baseline.
5. Lakukan review analis sebelum publikasi.

Laporan ini harus tetap ditinjau manusia sebelum
digunakan sebagai dokumentasi final.
