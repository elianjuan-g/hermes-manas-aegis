# Laporan Revisi Fase R2 — Manas Aegis v2.4.0-alpha

**Tanggal:** 2026-11-09 (05:12–~06:30 WIB)
**Perintah:** MyLord, satu per satu dari chat (6 butir + 1 tambahan soal
batas riwayat). Mode kerja: "aku revisi 1 per 1 ya dari chat, kamu fokus
kelarin semuanya dari chat aku ini".
**Aturan verdict:** single project single revisi (MyLord, 9 Nov 04:04 WIB)
— Ciel verdict sendiri, verdict Alicia tidak diminta. Alicia tetap
diberi kabar (koordinasi).
**Paket:** `~/workspace/manas-aegis-rev1/` (19 file + `tests/`).

## Ringkasan

Enam butir revisi MyLord + satu butir tambahan (batas riwayat 120)
semuanya diimplementasikan, dites, dan diverifikasi:

1. **i18n** — HUD 15 bahasa, Inggris default (sebelumnya Indonesia).
2. **Simulasi terlihat persisten** — ringkasan simulasi terakhir tidak
   lagi hilang saat reload; kartu KPI menampilkan sub-jumlah simulasi.
   Kartu besar tetap menghitung **hanya aktivitas nyata**.
3. **README "Yang dipantau" + aturan khusus** — pengguna bisa menambah
   dan mengedit aturan; aturan yang ditambah benar-benar dijalankan
   engine dan divalidasi.
4. **Pindai: quick / full / network** — terintegrasi, dengan tab Temuan
   sebagai "notifikasi" (tidak ada saluran push).
5. **Empty state kaya informasi** — versi, status, aturan, simulasi
   terakhir, pindai terakhir, cara memunculkan aktivitas.
6. **Intelijen ancaman real-time** — CISA KEV + NVD, refresh otomatis,
   tabel dengan kolom penjelasan awam + profesional.
7. **Riwayat tanpa batas** (tambahan dari MyLord, 05:32) — cap 120
   dihapus; arsip append-only + pencarian riwayat.

## Jawaban untuk pertanyaan MyLord: "Simulasi count gak bertambah — sengaja kah?"

**Ya, sengaja — dan itu keputusan R1, bukan bug.** Tiga kartu KPI besar
menghitung **hanya aktivitas nyata**; simulasi tidak pernah
menggelembungkannya (penggelembungan itu ketidakjujuran v2.2.0 yang
diperbaiki R1). Bukti live (dicek 05:17 WIB): telemetri
`manas_telemetry.json` MyLord (ditulis 05:14) berisi **6 event,
semuanya simulasi, 0 nyata** — simulasi MyLord **berhasil jalan**.
Screenshot MyLord yang menunjukkan "0 event dicatat" diambil sebelum
tab dimuat ulang. **Yang diperbaiki di R2:** hasil simulasi kini
terlihat persisten (baris ringkasan + sub-jumlah per kartu), jadi
tidak ada lagi yang bertanya-tanya apakah simulasi jalan atau tidak.

## Yang berubah (per file)

| File | Perubahan |
|---|---|
| `hermes_manas_aegis/i18n.py` (BARU, 1810 baris) | 15 bahasa, 111 kunci, `RULE_EXPLAIN` (10 aturan × en+id), `t()` + `explain()` dengan fallback ke Inggris. Ditulis subagen, **diverifikasi Ciel sendiri** (import + kelengkapan semua bahasa + spot-check id). 3 kunci tambahan (`kpi_rules_sub`, `scan_last`, `scan_never`) ditambah Ciel ke semua 15 bahasa. |
| `hermes_manas_aegis/core_engine.py` | Custom rules (`_load_custom_rules`, validasi penuh, override 4 aturan), baseline CCE persisten + dibandingkan ulang quick scan, `get_last_simulation()`, scan engine (`run_scan` quick/full/network), `get_history_stats()` + arsip telemetri (live 500 + JSONL tak terbatas) + `search_events()` + `clear_all_history()`, `refresh_threat_intel()`, posture: `total_stored` = total incl. arsip, `history_real`/`history_sim`, codename v2.4.0-alpha. |
| `hermes_manas_aegis/threat_intel.py` (BARU) | CISA KEV + NVD CVE API 2.0 (gratis, tanpa kunci, resmi), parser, cache `threat_intel.json` (maks. 40 item), refresh yang tidak pernah throw; bila kedua sumber gagal, cache lama dipertahankan + ditandai stale. |
| `hermes_manas_aegis/__init__.py` | `build_analytical_hud_html(core, lang, query)` — semua string via `t()`; pemilih bahasa; ringkasan simulasi persisten + sub-jumlah per kartu; empty state info panel; aturan khusus di katalog + panel scope; tombol pindai + baris status + tab Temuan; tabel intel global + kolom Penjelasan; kotak pencarian + `/api/search`; label riwayat tanpa batas; endpoint `POST /api/scan`, `POST /api/intel-refresh`; `clear-history` via `clear_all_history()`; daemon refresh intel (10 menit, bila cache >6 jam). |
| `README.md` | Banner v2.4.0-alpha; seksi "Yang dipantau" (+ aturan khusus, format + validasi + reload); baris MANAS-CONFIG-FIM diperbarui (hash kini dibandingkan ulang); seksi "Pindai" (cek per scope + yang TIDAK dilakukan); seksi "Intelijen ancaman global" (sumber + refresh + bukan pemindaian perangkat); seksi "Bahasa"; tabel "Data yang disimpan" (arsip, scan, intel, baseline, aturan khusus); jumlah tes 23/23. |
| `CHANGELOG.md` | Entri v2.4.0-alpha (ditambah/diubah). |
| `plugin.yaml` / `pyproject.toml` | Versi 2.3.0 → 2.4.0. |
| `tests/test_manas_aegis.py` | Kelas baru `TestManasAegisR2` (11 tes). Dua tes R1 diperbarui: HUD kini dipanggil dengan `lang="id"` eksplisit (default berubah ke Inggris). |
| `SECURITY.md`, `core_engine.py` docstring | Versi 2.3.0 → 2.4.0 (referensi historis "sejak v2.3.0" dipertahankan). |

## Verifikasi

- **Unit test: 23/23 lulus** (`python3 -m unittest discover`).
  6 V22 + 6 R1 + 11 R2 baru. R2 mencakup: kelengkapan i18n +
  default Inggris + fallback; aturan khusus menyala pada pola
  non-URL + penolakan 6 entri tidak valid + override SQLI;
  ringkasan simulasi terakhir; quick scan mendeteksi perubahan
  config.yaml (dengan urutan setup yang benar: tulis config
  SEBELUM core pertama); full scan menemukan file injeksi prompt
  + token bomb, dan secret di `auth.json` TIDAK ditandai;
  network scan `hud_ok=False` = kritis; parser + refresh intel
  dengan opener mock (kedua sumber gagal → cache lama dipertahankan
  + stale); HUD berisi kolom Penjelasan + tab Temuan + tombol
  pindai + baris intel; arsip telemetri + pencarian + hapus riwayat.
- **E2E: 27/27 lulus** (`/tmp/e2e-r2.py`, HTTP nyata ke server HUD
  port 18778): default Inggris, `?lang=id`, fallback bahasa tak
  dikenal, barrage → ringkasan persisten + sub-jumlah per kartu +
  tetap ada setelah reload, pencarian (`?q=` + `/api/search`),
  pindai quick, refresh intel, baris intel dari cache, hapus riwayat.
- **Smoke test telemetri** (ephemeral, `/tmp/smoke-telemetry.py`):
  live 3 + arsip 2 = total 5 setelah 5 event (dengan
  `TELEMETRY_LIVE_MAX=3`); reload mempertahankan total; pencarian
  menemukan event arsip (n0) dan live (n4); hapus menghapus
  keduanya. Dua bug ditemukan dan diperbaiki selama smoke test:
  (1) `self.events` tidak di-trim di memori → total dihitung ganda;
  (2) pengindeksan arsip bergeser setelah trim → event hilang.
  Keduanya diperbaiki dengan mengarsipkan kelebihan dari jendela
  saat ini (bukan dari indeks absolut).
- **Smoke test R2** (`/tmp/smoke-r2.py`): aturan khusus, pindai,
  parser intel — semua lolos. Dua artefak dicatat (bukan bug):
  (a) langkah "tamper" melaporkan "Berkas konfigurasi baru" karena
  baseline dibuat sebelum config.yaml ada — tes unit memakai
  urutan setup yang benar; (b) pemblokiran custom rule oleh SSRF
  bawaan di VM (DNS via proxy mengembalikan 198.18.x.x) — tes unit
  memakai pola non-URL sehingga verifikasi custom rule bersih.

## Batas yang jujur (masih berlaku / baru)

- **Keputusan guard tidak berubah.** Yang berubah adalah bahasa,
  visibilitas, dan alat bantu — bukan logika pemblokiran. Bypass
  yang diketahui (git chaining, `python -c`, SSRF fail-open) tetap
  ada — itu Fase R2 (antre setelah revisi ini).
- **Pindai bukan pemindai perangkat.** Quick/full/network tidak
  memindai seluruh komputer, tidak ada port scan, tidak ada
  pemindaian LAN/internet, dan tidak memperbaiki apa pun otomatis.
- **Intel global bukan pemindaian perangkat.** Advisori CISA KEV +
  NVD adalah kewaspadaan; plugin tidak memeriksa apakah perangkat
  ini terdampak.
- **Notifikasi = di HUD.** Tidak ada saluran push (sistem/email/
  chat). Temuan pindai tampil di tab Temuan; pemblokiran real-time
  tampil di tabel Aktivitas.
- **Penjelasan hanya en + id.** Bahasa lain menampilkan penjelasan
  Inggris (fallback).
- **Pencarian arsip membaca maks. 20 MB terakhir** agar HUD tidak
  melambat pada arsip yang sangat besar.
- **Visual di HP/Desktop MyLord** hanya bisa diverifikasi dari
  perangkat MyLord (TERBUKA, seperti biasa).

## Verdict Ciel (self-verdict, aturan single revisi)

**PASS WITH NOTES.**

- Semua 6 butir revisi + 1 tambahan diimplementasikan dan
  terverifikasi (unit 23/23, e2e 27/27).
- Notes: (1) visual HP/Desktop MyLord masih TERBUKA (hanya bisa
  diverifikasi dari perangkatnya); (2) penjelasan hanya en+id;
  (3) bypass Fase R2 (SSRF fail-closed dkk.) tetap antre dan
  tidak disentuh revisi ini; (4) terjemahan 3 kunci tambahan
  (`kpi_rules_sub`, `scan_last`, `scan_never`) ditulis Ciel
  sendiri untuk 13 bahasa non-en/id — singkat dan sederhana,
  tapi bukan terjemahan penutur asli.
