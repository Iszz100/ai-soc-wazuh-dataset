# Cron Schedule - AI SOC Dataset Lab

## Tujuan
Menjalankan dataset generation secara periodik di lab tertutup.

## Jadwal
- Baseline ringan: per jam
- Mixed scenario: manual atau harian terbatas
- Attack simulation: hanya saat diawasi

## Safety
- Target hanya IP lab
- Config memakai LAB_CIDR
- Log cron disimpan
- Evidence tidak dihapus otomatis
- Baseline menggunakan konfigurasi khusus
- Attack simulation tidak dijadwalkan otomatis

## Cron Command
Baseline ringan dijalankan setiap jam menggunakan:
configs/orchestrator_baseline.json
