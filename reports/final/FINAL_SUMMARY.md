# Final Summary

Mini project ini membangun pipeline AI SOC Wazuh end-to-end:

script pentest → ground truth → Wazuh alert/archive →
correlation → dataset final →
quality report → model baseline → AI-assisted SOC report →
publikasi aman.

## Output

- Dataset final: `datasets/final/`
- Model baseline: `models/`
- Evidence pack: `runs/`
- Quality report: `reports/final/`
- Decoder/rule Wazuh: `decoders/` dan `rules/`
- Public safety check:
  `reports/final/public_release_check.json`

## Kondisi Eksperimen

- Total dataset: 112 records.
- Ground Truth: 6 records.
- Benign: 1.
- Malicious: 5.
- Unlabeled: 106.
- Belum ada korelasi Ground Truth dan Wazuh yang berhasil.
- Isolation Forest dijalankan secara eksploratif.
- Supervised models dilewati karena data belum mencukupi.

## Pesan Utama

Dataset AI SOC bukan hasil samping pentest.

Dataset AI SOC adalah produk rekayasa data keamanan
yang legal, terukur, terdokumentasi, dan dapat diaudit.

Pentest menghasilkan bukti. Wazuh menangkap sinyal.
Ground Truth memberi kebenaran. Python membangun dataset.
AI membantu membaca pola. Analis tetap memegang keputusan.
