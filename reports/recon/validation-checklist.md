# Validation Checklist - Recon Dataset

## Scope
- [ ] Semua target adalah IP lab
- [ ] Tidak ada domain publik
- [ ] Tidak ada IP publik
- [ ] Semua command tersimpan
- [ ] Semua run punya run_id

## Ground Truth
- [ ] ground-truth/recon.jsonl tersedia
- [ ] start_time tersedia
- [ ] end_time tersedia
- [ ] scenario_id tersedia
- [ ] expected_label tersedia
- [ ] intensity tersedia

## Wazuh
- [ ] alerts.json diekspor
- [ ] archives.json dicek bila aktif
- [ ] rule_id dicatat
- [ ] rule_level dicatat
- [ ] rule_description dicatat

## Correlation
- [ ] jumlah ground truth dihitung
- [ ] jumlah alert dihitung
- [ ] run tanpa alert dicatat
- [ ] duplicate alert dicatat
- [ ] window waktu dijelaskan

## Dataset Quality
- [ ] benign dan recon tidak tercampur tanpa label
- [ ] output tool tersimpan
- [ ] error command tersimpan
- [ ] limitation ditulis
