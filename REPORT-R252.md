# Laporan Revisi R2.5.2 — Manas Aegis v2.5.2-alpha

**Tanggal:** 2026-11-09 ~07:10 WIB
**Pemicu:** laporan MyLord (06:33 WIB) — "coba geh fitur bahasanya udah bagus tapi gak merata di seluruh menu dan tab masih ada bahasa yang gak sesei, contoh pakai english, di tab findings masih pakai bahasa indonesia, begitupun sebaliknya sama aja".
**Lingkup:** satu proyek, satu putaran revisi (aturan single-revisi 9 Nov 04:04) — Ciel verdict sendiri; Alicia dikabari (koordinasi), verdict tidak diminta.

## Diagnosis (terverifikasi dari kode, bukan tebakan)

Empat sumber ketidakmerataan, semuanya nyata:

1. **Judul + detail temuan pindai hardcode Indonesia** di `core_engine.py` (`run_scan` ~10 judul + ~10 detail, `_scan_filesystem` 4+4, mis. "Berkas konfigurasi berubah: {fname}") dan tersimpan begitu di `scan_state.json` — tampil Indonesia di SEMUA mode bahasa.
2. **Header "File" hardcode Inggris** di template (`__init__.py`, kolom terakhir tabel Findings).
3. **Nama pemeriksaan = ID Inggris mentah** (`config_integrity`, `honeypot_decoys`, …) — tampil apa adanya.
4. **Label level intel = data Inggris** (CISA "Actively exploited", NVD "9.8 CRITICAL") — tampil apa adanya di semua mode.

Yang TIDAK termasuk masalah (sudah benar): `_plain_reason`, `RULE_EXPLAIN`, `_custom_explain` hanya en+id dengan fallback en yang terdokumentasi; string UI lain sudah berkunci.

## Perbaikan

- **Temuan berbasis kunci.** `run_scan`/`_scan_filesystem` kini menyimpan `title_key`/`detail_key`/`params` + teks Inggris sebagai fallback di JSON mentah. HUD me-render via `t(lang, …)` (`_finding_text`). Kolom Detail kini menampilkan judul (tebal) + detail (redup) — sebelumnya hanya detail.
- **41 kunci baru × 15 bahasa** (judul/detail 15 temuan + `findings_file` + 9 nama `check_*` + `intel_level_exploited`) **+ 3 kunci kata severity NVD** (`intel_sev_high/medium/low`; CRITICAL memakai `sev_critical` yang sudah ada). Total kunci: 115 → **159** per bahasa, 0 selisih.
- **Label level intel** (`_intel_level_label`): "Actively exploited" → label terjemahan; "9.8 CRITICAL" → skor dipertahankan + kata severity diterjemahkan ("9.8 Kritis" / "7.5 Tinggi" / "5.0 Sedang" / "2.1 Rendah").
- **Migrasi temuan lama** (`_migrate_old_finding`, 15 pola judul Indonesia → kunci + ekstraksi param dari judul/detail): 37 temuan tersimpan sebelum v2.5.2 ikut tampil dalam bahasa HUD — bukan tetap Indonesia. Temuan yang tidak cocok pola tetap menampilkan teks tersimpannya (fallback, bukan kunci mentah).

## Verifikasi

- **Unit test: 38/38 lulus** (33 lama + 5 baru R2.5.2, termasuk render temuan penuh en+id tanpa bocor silang, migrasi temuan lama, label level intel).
- **E2E: 32/32 lulus** (HTTP nyata: render temuan en+id, header Berkas/File, nama pemeriksaan, migrasi, level intel — plus semua alur R2.5.1 tetap hijau).
- **Live di PC:** diverifikasi sesudah install (lihat laporan kirim ke MyLord).

## Self-verdict: PASS WITH NOTES

- Bahasa di seluruh menu + tab Findings kini merata (en + id terverifikasi render penuh; 13 bahasa lain kunci lengkap, terjemahan oleh Ciel — bukan penutur asli).
- Temuan lama 37 baris ikut bermigrasi (bukan tetap Indonesia).
- Notes: (1) terjemahan 13 bahasa non-en/id ditulis Ciel, bukan penutur asli; (2) bypass Fase R2 (SSRF fail-closed dkk.) tetap antre.
