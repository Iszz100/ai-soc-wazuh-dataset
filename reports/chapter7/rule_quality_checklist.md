# Rule Quality Checklist - Chapter 7

## Scope
- [x] Rule hanya untuk event lab
- [x] Rule memakai group ai_soc_dataset
- [x] Rule tidak menangkap log umum yang diuji
- [x] Rule tidak terlalu sempit hingga sample sah gagal match

## Decoder
- [x] program_name terbaca
- [x] decoder parent match
- [x] JSON field diekstrak
- [x] scenario_id terbaca
- [x] run_id terbaca
- [x] attack_type terbaca
- [x] payload_id terbaca
- [x] expected_label terbaca

## Rule
- [x] Custom rule ID memakai rentang 100000-120000
- [x] Description jelas
- [x] Group konsisten
- [ ] MITRE ID tidak dipaksakan (perlu review mapping)
- [ ] Severity proporsional (perlu review)
- [x] Benign event tidak dibuat high severity

## Testing
- [x] Sample recon diuji
- [x] Sample auth_attack diuji
- [x] Sample web_attack diuji
- [x] Sample fim_event diuji
- [x] Sample suspicious_command diuji
- [x] Sample benign diuji
- [x] Positive testing berhasil
- [x] Negative scope testing berhasil
- [x] Output logtest disimpan
- [x] Hasil validasi scope didokumentasikan

## Dataset
- [x] Alert custom masuk alerts.json
- [ ] Event mentah tersedia di archives.json jika logall_json aktif
- [x] Field penting bisa dipakai korelasi
- [ ] False positive dievaluasi lebih lanjut
- [ ] False negative dievaluasi lebih lanjut
- [x] Rule dan decoder disimpan di Git
