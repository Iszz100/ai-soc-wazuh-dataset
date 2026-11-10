# BAB 3 - Desain Ground Truth dan Schema Dataset Training AI

## 1. Tujuan

Bab ini membahas pembangunan fondasi dataset untuk penelitian
AI SOC berbasis Wazuh.

Fokus utama:
- Ground Truth sebagai sumber label aktivitas.
- Standardisasi label dataset.
- Mapping MITRE ATT&CK.
- Normalisasi Wazuh alerts.
- Dataset schema dan versioning.
- Validasi kualitas dataset.

## 2. Environment Laboratorium

| Komponen | Environment |
|---|---|
| Target | Ubuntu 18.04.6 LTS |
| Attacker / Analyst | Ubuntu 26.04.1 LTS |
| SIEM | Wazuh 4.14.6 |
| Wazuh Agent | 022 |
| Dataset format | JSONL |
| Repository | ai-soc-wazuh-dataset |

## 3. Implementasi Ground Truth

File:
- schemas/ground_truth.schema.json
- ground-truth/ground_truth.jsonl
- scripts/write_ground_truth.py

Ground Truth digunakan untuk mencatat aktivitas
yang dilakukan selama eksperimen.

Satu skenario awal berhasil dicatat:

Scenario ID:
baseline_ssh_typo_success

Aktivitas:
Satu kali kesalahan memasukkan password SSH,
kemudian berhasil melakukan autentikasi.

Aktivitas ini telah dikonfirmasi oleh pengguna
sebagai aktivitas benign.

## 4. Label Taxonomy dan MITRE Mapping

File:
- configs/label_taxonomy.json
- configs/mitre_mapping.json

Taxonomy menyediakan kategori label dan kebijakan
confidence untuk anotasi dataset.

MITRE mapping digunakan untuk menghubungkan
skenario eksperimen dengan taktik dan teknik MITRE ATT&CK.

## 5. Normalisasi Wazuh Alerts

File:
- scripts/normalize_wazuh_alert.py

Data diambil dari Wazuh Manager melalui
Wazuh Agent 022.

Total data awal: 9 events.

Seluruh 9 events berhasil dinormalisasi ke JSONL.

Field yang diekstrak meliputi:
- event_id
- timestamp
- agent_id
- agent_name
- source_ip
- source_port
- destination_ip
- destination_port
- destination_user
- rule_id
- rule_level
- rule_description
- rule_groups
- raw_event

## 6. Ground Truth Correlation

File:
- configs/correlation_rules.json
- scripts/correlate_ground_truth.py

Korelasi dilakukan berdasarkan:
- Timestamp.
- Agent ID.
- Source IP.
- Destination user.
- Rule ID.

Hasil korelasi awal:

| Status | Jumlah |
|---|---:|
| Matched | 5 |
| Unmatched | 4 |
| Total | 9 |

Lima alert yang cocok dengan aktivitas SSH
diberi label benign.

Empat alert lainnya tetap unlabeled karena
belum mempunyai Ground Truth yang sesuai.

Tidak ada alert yang diberi label malicious
pada tahap eksperimen awal ini.

## 7. Dataset Schema dan Quality Validation

File:
- schemas/final_dataset.schema.json
- scripts/validate_dataset.py

Pemeriksaan kualitas dataset awal menghasilkan:

| Pemeriksaan | Hasil |
|---|---:|
| Total records | 9 |
| Unique event IDs | 9 |
| Validation errors | 0 |
| Validation status | PASSED |

## 8. Dataset Versioning

File:
- scripts/create_dataset_card.py
- datasets/DATASET_CARD.json

Dataset Card awal dibuat dengan versi v0.1.0.

Dataset Card ini mendeskripsikan hasil normalisasi
sebelum proses korelasi Ground Truth.

Distribusi:
- Unlabeled: 9
- Unknown attack type: 9
- Unmatched scenario: 9

Dataset ini merupakan snapshot awal,
bukan dataset training final.

## 9. Struktur Artefak

Artefak utama Bab 3:

- configs/
- schemas/
- scripts/
- ground-truth/
- datasets/
- docs/bab-3/

Data mentah dan konfigurasi lokal yang mengandung
informasi environment tidak disertakan dalam
publikasi repository.

## 10. Keterbatasan

- Dataset awal masih memiliki jumlah event terbatas.
- Belum terdapat sampel malicious terverifikasi.
- Ground Truth baru mencakup satu skenario SSH.
- Sebagian alert tidak menyediakan source IP
  atau destination IP.
- Dataset belum cukup untuk pelatihan model AI SOC
  yang representatif.

## 11. Kesimpulan

Fondasi dataset AI SOC berbasis Wazuh telah dibangun.

Proses Ground Truth, normalisasi, korelasi,
schema, validasi, dan versioning telah
diimplementasikan.

Tahap berikutnya adalah menambah skenario eksperimen
terkontrol untuk menghasilkan dataset benign
dan malicious yang lebih beragam.

## 10. Quality Assurance (Bab 3.8)

Validasi dilakukan terhadap dataset hasil korelasi
Ground Truth menggunakan JSON Schema.

Hasil validasi:

| Pemeriksaan | Hasil |
|---|---:|
| Total records | 9 |
| Schema errors | 0 |
| Duplicate event IDs | 0 |
| Status | PASSED |

Seluruh record berhasil melewati validasi struktur
JSON Schema dan tidak ditemukan event_id duplikat.

Dataset masih memiliki 5 event benign terkonfirmasi
dan 4 event unlabeled.

Belum terdapat sampel malicious terverifikasi
pada versi dataset v0.1.0.

File validasi:
- schemas/final_dataset.schema.json
- scripts/validate_dataset.py

