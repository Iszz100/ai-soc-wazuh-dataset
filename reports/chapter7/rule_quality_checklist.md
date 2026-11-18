# Rule Quality Checklist - Chapter 7

## Scope
- [ ] Rule hanya untuk event lab
- [ ] Rule memakai group ai_soc_dataset
- [ ] Rule tidak menangkap log umum yang tidak relevan
- [ ] Rule tidak terlalu sempit hingga sample sah gagal match

## Decoder
- [ ] program_name terbaca
- [ ] decoder parent match
- [ ] JSON field diekstrak
- [ ] scenario_id terbaca
- [ ] run_id terbaca
- [ ] attack_type terbaca
- [ ] payload_id terbaca
- [ ] expected_label terbaca

## Rule
- [ ] Custom rule ID memakai rentang 100000-120000
- [ ] Description jelas
- [ ] Group konsisten
- [ ] MITRE ID tidak dipaksakan
- [ ] Severity proporsional
- [ ] Benign event tidak dibuat high severity

## Testing
- [ ] Sample recon diuji
- [ ] Sample auth_attack diuji
- [ ] Sample web_attack diuji
- [ ] Sample fim_event diuji
- [ ] Sample suspicious_command diuji
- [ ] Sample benign diuji
- [ ] Output logtest disimpan

## Dataset
- [ ] Alert masuk alerts.json
- [ ] Event mentah tersedia di archives.json jika logall_json aktif
- [ ] Field penting bisa dipakai korelasi
- [ ] False positive dicatat
- [ ] False negative dicatat
- [ ] Rule dan decoder disimpan di Git
