# Changelog — Manas Aegis

Semua perubahan penting pada plugin ini dicatat di sini. Format
mengikuti [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
secara longgar. Versi memakai `MAJOR.MINOR.PATCH` + label
`-alpha` selama masih prototipe.

## [2.6.2-alpha] — 2026-11-09

Revisi atas audit Argon terhadap v2.6.1 (diteliti dan dikoreksi Ciel;
nomor baris Argon tidak dipakai — semua temuan dilacak ulang dengan
grep). Sembilan perbaikan: tiga P1 (shell parser, inspeksi argumen
rekursif, SSRF), tiga P2 (packaging, HUD threading/lock/atomic,
clear-history + skema config), tiga P3 (tombol suara mati, indikator
loading intel, bersih-bersih dokumen).

### Keamanan — diperbaiki

- **Parser shell: subshell/backtick/baris baru tidak lagi memecah
  pemeriksaan.** `$(...)` dan `` `...` `` kini dilacak (pemisah di
  dalamnya tidak memecah segmen), dan `\n` menjadi pemisah — jadi
  `$(curl ... | sh)` dan `echo ok\nrm -rf /tmp/x` tidak lolos lagi
  lewat fragmentasi. `python -c` berbahaya kini terdeteksi juga
  lewat `python3.11`, path absolut, dan flag gabungan
  (`python3 -u -c`, `python3 -X utf8 -c`); `from os import system`
  ikut diblokir.
- **Pola RCE kini cocok untuk `rm -rf` ke path absolut apa pun**
  (`rm -rf /tmp/x`, `rm -rf /`, `rm -fr`, `rm -r -f`, `--recursive
  --force`, plus bentuk `$(rm -rf /)` dan backtick). Sebelumnya
  pola menuntut `/` diikuti spasi/akhir/`*`, jadi `/tmp/x` lolos.
  Bentuk baru `sh $(curl ...)` / `` sh `curl ...` `` (dan `eval`)
  juga diblokir.
- **Inspeksi argumen kini rekursif.** Path kredensial di dalam
  dict/list bersarang ikut diperiksa (dulu hanya top-level), dan
  `~` di-expand sebelum canonicalization — `~/.../.hermes/auth.json`
  tidak lolos lagi.
- **SSRF: multicast + unspecified diblokir** (IPv4/IPv6, literal
  maupun hasil DNS); URL diekstrak dengan tanda baca JSON di akhir
  dibersihkan supaya host publik tidak terblokir gara-gara `},`;
  `scp`/`rsync`/`ssh`/`nc`/`dig`/`nslookup` (dan `sftp`/`ftp`)
  kini dihitung sebagai egress untuk taint gating.

### Diperbaiki

- **Packaging: `MANIFEST.in` + `data-files`.** sdist dan wheel kini
  membawa `plugin.yaml` + aset desktop (`desktop/plugin.js`) +
  honeypot decoy — diverifikasi dari isi arsip hasil build.
- **HUD: `ThreadingHTTPServer`** (dulu single-threaded);
  `reload_state()`/`_save_events()`/`_save_scan_state()`/
  `clear_all_history()` kini memakai lock yang sudah ada; tulis
  state atomik (temp + rename).
- **"Hapus riwayat" kini juga menghapus temuan pindai**
  (`scan_findings` + `scan_state.json`), sesuai yang sudah dijanjikan
  README. Strategi `MANAS-CALLID-RACE` di katalog diubah dari
  `SYNTHESIZE_PATCH` menjadi `HARD_BLOCK` (sesuai perilaku nyata).
  Lima kunci config R3 ditambahkan ke `plugin.yaml`
  (`taint_ttl_minutes`, `ssrf_allowlist`, `callid_race_window_s`,
  `callid_race_enabled`, `hud_auth_token`).
- **Tombol Suara dihapus.** Tombol itu mati (hanya membalik
  `localStorage`; tidak ada audio apa pun di HUD) — dihapus beserta
  kunci i18n-nya daripada dipertahankan sebagai pajangan.
- **Tombol Perbarui intel kini menunjukkan status loading**
  (nonaktif + label "Memperbarui intel…" selama fetch berjalan).
- **Dokumen dibersihkan:** klaim "8 eksperimental + 2 planned"
  dihapus (10/10 enforced sejak v2.6.0); kontradiksi CSRF/rate-limit
  diluruskan (CSRF + rate limit + token auth opt-in memang aktif);
  teks SSRF fail-open yang basi dihapus dari README, komentar kode,
  dan penjelasan aturan; `CONTRIBUTING.md` kini menyebut jumlah tes
  yang sebenarnya.

## [2.6.1-alpha] — 2026-11-09

Revisi kecil atas keluhan MyLord (screenshot HUD): kartu Skor Postur
muncul di SEMUA tab dan terlalu makan ruang.

### Diperbaiki

- **Kartu Skor Postur kini hanya di tab Activity.** Akar masalah: kartu
  dirender di alur `<main>` bersama sebelum panel-panel tab, jadi
  pengalih tab (yang hanya menyembunyikan `.panel`) tidak pernah
  menyembunyikannya. Kartu dipindah ke dalam panel `tab-act`.
- **Kartu diubah jadi box minimalis (`.posture-mini`).** Skor 44px +
  lima baris penuh diganti satu baris ringkas: skor 26px + grade di
  kiri, lima komponen sebagai chip kecil (label + bar 70px + nilai)
  di kanan. Padding 12px, tinggi total jauh lebih kecil.
- **Semua konten Activity kini di dalam tab-nya sendiri.** KPI, garis
  history, kartu "Yang dipantau", dan kartu "Pindai" juga dipindah ke
  dalam panel Activity (sebelumnya di alur bersama, jadi ganti tab
  tidak mengubah apa-apa di layar). Tiap tab kini menampilkan konten
  yang sepenuhnya berbeda.
- **Transisi fade 180ms** saat panel aktif berganti (naik 4px + fade),
  supaya perpindahan tab tidak terasa kaku.

### Catatan

- Tes: unit + kontrak 61/61, e2e R3 26/26, e2e posture-mini 17/17.

## [2.6.0-alpha] — 2026-11-09

Revisi R3 (atas perintah MyLord: "Gimana skor nya dibuat 10 semuanya"
+ "aku butuh guard terbaik diantara mereka semua"). Sepuluh fitur
untuk menutup celah enforcement yang dibuktikan oleh verdict REVISI.txt
dan riset kompetitor (llm-antidote ~82, blackbox ~78). Dimensi maturity
tetap jujur di 7–8: PR katalog #151504 harus di-merge Nous + pengguna
nyata dulu — itu di luar kendali kode.

### Ditambahkan

- **Taint tracking (per sesi).** Akses berkas kredensial (deceived ke
  honeypot atau diblokir) menandai sesi sebagai tainted (TTL 60 menit,
  hanya di memori); egress berikutnya dari sesi yang sama di-hard-block
  (MANAS-CRED-HONEYPOT). Simulasi tidak menandai taint.
- **Parser shell nyata** menggantikan regex untuk perintah berantai:
  pemisah `;` `&&` `||` `|` `&` (hormat quote + escape); tiap segmen
  diperiksa sendiri — `python -c` berbahaya diblokir per segmen,
  subcommand git ditulis ulang per segmen.
- **SSRF fail-closed + allowlist.** DNS yang gagal kini memblokir
  (dulu: dianggap SAFE). `ssrf_allowlist` di konfigurasi mengecualikan
  host bernama.
- **MANAS-SYMLINK-GUARD enforced.** Argumen dikanonikalisasi
  (`Path.resolve`); baca yang mengarah ke berkas terlindungi
  dialihkan ke decoy honeypot. Status planned → experimental.
- **MANAS-CALLID-RACE enforced.** Pemanggilan runtime identik
  (sesi + tool + hash argumen sama) dalam 10 detik di-hard-block.
  Status planned → experimental. Jendela bisa dikonfigurasi
  (`callid_race_window_s`). Simulasi dikecualikan.
- **Posture Score (0–100 + grade A–F)** di HUD: aturan 25 +
  enforcement 25 + hygiene 20 + intelijen 15 + aktivitas 15.
- **Guard Arena.** 10 skenario serangan (teks saja, tidak dieksekusi)
  dijalankan pada core sekali pakai lewat jalur enforcement runtime;
  hasil tersimpan (`arena_last.json`) dan tampil di tab Arena.
- **Audit time-travel.** Pemeriksaan ulang event runtime tersimpan:
  event yang baru akan tertangkap oleh mekanisme R3 ditandai
  "newly caught". Audit berbasis pola atas evidence tersimpan
  (bukan replay penuh — telemetri tidak menyimpan event "allow").
- **Pengamanan HUD.** CSRF token di semua POST (header
  `X-CSRF-Token`); rate limit 20 POST/IP/60 detik (HTTP 429);
  token auth opt-in (`hud_auth_token`) + halaman login + cookie
  sesi HttpOnly 24 jam (default mati — HUD loopback-only di iframe
  Desktop).
- **CI + contract test + coverage gate.** `.github/workflows/ci.yml`
  (Python 3.11/3.12): unit + contract test, coverage gate 70%
  (terukur 79% di v2.6.0). `tests/test_contract.py`: versi
  plugin.yaml == pyproject == codename, field katalog wajib,
  `register()` mendaftarkan semua hook + tool yang dideklarasikan,
  HUD render, konstanta hardening, nol dependensi non-stdlib.

### Diubah

- **Ke-10 aturan kini experimental** (tidak ada lagi planned).
  `rules_enforced` di posture: 8 → 10.
- **i18n: 159 → 180 kunci** per bahasa (21 kunci baru: posture 6 +
  arena 11 + time-travel 4), 15 bahasa lengkap, 0 mismatch.
- **Penjelasan aturan (RULE_EXPLAIN)** untuk SYMLINK-GUARD,
  CALLID-RACE, dan SHELL-RCE diperbarui ke status enforcement R3.
- **README:** tabel bypass diperbarui (git chaining, `python -c`,
  SSRF fail-open, symlink — semua sudah diperbaiki); seksi baru
  Skor postur / Arena / time-travel / pengamanan HUD.

### Diperbaiki

- **Sub-jumlah simulasi** kini memakai pencocokan substring yang
  sama dengan ringkasan (sudah benar sejak R2.5.1; tes R3 mengunci
  nilai (4, 2, 1) = 7 event dari 6 input barrage).
- **`get_last_simulation()`** tidak lagi memotong run di 6 event —
  satu input bisa menghasilkan beberapa event (vektor git kini
  menghasilkan 2 modify).

### Tes

- **Unit + contract: 61/61 lulus** — 38 lama + 16 baru R3 (taint,
  parser shell, SSRF fail-closed + allowlist, symlink, call-ID race,
  posture score, arena 10/10, time-travel, CSRF/posture/arena di
  HUD, key count 180) + 7 tes kontrak.
- **E2E HTTP nyata: 26/26 lulus** (`/tmp/e2e-r3.py`): CSRF 403/200,
  arena 10/10, time-travel, barrage 6 hasil, rate limit 429 di POST
  ke-21, token auth (login 401/302 + cookie sesi + HUD 200).
- **Cakupan: 79%** (core 80%, i18n 100%, threat_intel 86%).

### Catatan jujur

- **Maturity tetap 7–8, bukan 10.** PR katalog harus di-merge dan
  pengguna nyata harus memakai plugin ini dulu.
- **Packaging (wheel/sdist membawa plugin.yaml + aset desktop)**
  masih terbuka dari Fase R2 — belum masuk 10 fitur R3.
- **Arena skenario `arena-ssrf-dns-fail` dihapus** dari 10 skenario
  (tidak deterministik: DNS di VM selalu ter-resolve lewat proxy
  egress ke 198.18.x.x); fail-closed diuji oleh unit test dengan
  `socket.getaddrinfo` yang di-mock.
- **Terjemahan 21 kunci baru × 13 bahasa non-en/id** ditulis Ciel
  (bukan penutur asli) — pola yang sama seperti R2.5.2.

## [2.5.2-alpha] — 2026-11-09

Revisi R2.5.2 (atas laporan MyLord: fitur bahasa bagus tapi tidak
merata — mode English, tab Findings masih berbahasa Indonesia, dan
sebaliknya). Empat sumber ketidakmerataan, semua diperbaiki.

### Diperbaiki

- **Judul + detail temuan pindai masih hardcode Indonesia.** 15
  judul + 15 detail temuan (di `run_scan` dan `_scan_filesystem`)
  kini disimpan berbasis kunci (`title_key`/`detail_key`/`params`)
  dan dirender per bahasa di HUD. Teks Inggris disimpan sebagai
  fallback yang terbaca di JSON mentah. Total kunci i18n: 115 →
  **159** (41 kunci temuan/pemeriksaan/berkas/level + 3 kata
  severity NVD).
- **Header "File" hardcode Inggris.** Kini kunci `findings_file`
  ("File" / "Berkas" / dst. di 15 bahasa).
- **Nama pemeriksaan = ID Inggris mentah.** Kini label terjemahan
  (`check_config_integrity` → "Config integrity" / "Integritas
  konfigurasi", dst. untuk 9 pemeriksaan).
- **Label level intel = data Inggris mentah.** Level CISA
  "Actively exploited" dan level NVD "9.8 CRITICAL" kini
  diterjemahkan (skor angka dipertahankan, kata severity
  diterjemahkan: "9.8 Kritis" / "7.5 Tinggi" / "5.0 Sedang" /
  "2.1 Rendah").
- **Temuan lama (37 baris) ikut bermigrasi.** Temuan tersimpan
  sebelum v2.5.2 (judul Indonesia, tanpa kunci) dipetakan saat
  dimuat (`_migrate_old_finding`, 15 pola judul) sehingga ikut
  tampil dalam bahasa HUD — bukan tetap Indonesia.
- **Sel temuan menampilkan judul + detail.** Kolom Detail kini
  menampilkan judul temuan (tebal) + detail (redup) — sebelumnya
  hanya detail, jadi judul tidak pernah terlihat.

### Catatan

- Terjemahan untuk 13 bahasa selain en/id ditulis Ciel (bukan
  penutur asli) — sama seperti kunci i18n sebelumnya.
- **Unit test: 38/38 lulus** — 33 lama + 5 baru R2.5.2 (kelengkapan
  159 kunci, render temuan penuh en+id tanpa bocor silang, migrasi
  temuan lama, label level intel, kunci+fallback Inggris).
  **E2E: 32/32 lulus** (HTTP nyata: render temuan en+id, header
  Berkas/File, nama pemeriksaan, migrasi, level intel).

## [2.5.1-alpha] — 2026-11-09

Revisi R2.5.1 (atas laporan MyLord + screenshot: simulasi sudah
dijalankan tapi kartu KPI tetap 0; pindai Quick Scan "tidak masuk
ke browse/library"). Dua bug + satu integrasi yang belum terbukti.

### Diperbaiki

- **Sub-jumlah simulasi 0/0/0 (BUG).** Kartu KPI menghitung sub-jumlah
  simulasi dengan pencocokan persis (`verdict == "BLOCK"`), padahal
  string verdict sebenarnya adalah `"HARD_BLOCK"`,
  `"SYNTHESIZED_PATCH (Modify Args)"`, dan
  `"HONEYPOT_DECEIVED (Modify Args)"`. Hasilnya: 12 event simulasi
  MyLord (8 blocked, 2 modified, 2 deceived) terbaca 0/0/0.
  Sekarang memakai pencocokan substring yang sama seperti
  `get_last_simulation()` dan counter posture (`"BLOCK" in verdict`).
  Ringkasan "Last simulation" sudah benar dari dulu (pakai substring)
  — hanya sub-jumlah per kartu yang salah.
- **Pindai tidak membawa ke hasil (UX).** Sesudah Quick/Full/Network
  Scan, halaman hanya me-reload di tab Activity, jadi temuan
  tersembunyi di tab Findings dan MyLord mengira pindai tidak jalan.
  Sekarang sesudah pindai sukses, halaman pindah ke tab Findings
  (`?tab=find`, dipertahankan di URL; server me-render tab yang
  diminta, fallback ke Activity bila param tidak dikenal).
  Pencarian tetap di tab Activity (hidden input `tab=act`).

### Ditambah

- **Jalur data real terbukti.** `intercept_tool_call` punya
  `event_source="runtime"` (default) — jalur yang sama dipakai
  Hermes saat agen benar-benar memanggil tool. Diuji langsung di
  PC (bukan simulasi): 1 panggilan shell destruktif diblokir
  (HARD_BLOCK), 1 argumen dimodifikasi, 1 kredensial dialihkan ke
  honeypot. Ketiganya tercatat sebagai event REAL (source=runtime)
  dan menaikkan kartu KPI. Data real selanjutnya muncul otomatis
  setiap agen Hermes memanggil tool — plugin tidak bisa
  "mendeteksi" tool yang tidak pernah dipanggil.
- **Integrasi antar-proses (reload_state).** Server HUD adalah
  proses berumur panjang, tapi event juga ditulis proses lain
  (agen Hermes yang mencegat tool real, pindai dari sesi lain).
  Sebelumnya HUD hanya memuat state saat startup — event real
  dari proses lain tidak muncul sampai server di-restart (terbukti
  saat uji intercept real: 3 event real tertulis ke file, HUD
  tetap menampilkan 12). Kini `core.reload_state()` dipanggil di
  setiap GET, jadi halaman selalu mencerminkan isi disk.
- **Unit test: 33/28 lulus** — 28 lama + 5 baru R2.5.1 (sub-jumlah
  sim dengan string verdict asli incl. reproduksi telemetri MyLord
  12 event → 8/2/2, param tab, redirect pindai, reload_state
  antar-proses). **E2E: 21/21 lulus** (HTTP nyata: sub-jumlah sim
  non-nol + jumlah 6, tab=find, pindai → Findings, intercept real
  → counter real > 0, proses kedua menulis event → HUD menampilkannya
  tanpa restart).

## [2.5.0-alpha] — 2026-11-09

Revisi R2.5 (atas perintah MyLord: "UI-UX nya jangan AI SLOP lah,
cari design nya di figma atau apa gitu, pake yang profesional" +
"tambahin tema gelap sama terang"): HUD didesain ulang dari sistem
desain dashboard CISO C3iHub (IIT Kanpur, 2024 — platform keamanan
enterprise yang benar-benar dikirim ke klien, bukan konsep Dribbble),
plus tema gelap + terang. **Fungsi tidak berubah** — yang berubah
hanya lapisan visual (warna, tipografi, layout, ikon).

### Ditambah

- **Tema gelap + terang.** Tombol tema di kanan atas (ikon matahari/
  bulan, Lucide SVG). Pilihan tersimpan di browser
  (`localStorage 'manas-aegis-theme'`) dan diterapkan sebelum
  halaman pertama kali digambar (tanpa kedip). Default: gelap.
  Tema terang memakai token yang sama (hue severity sama, digelapkan
  agar kontras di latar putih; biru aksi tetap #0168FF).
- **Ikon SVG profesional (Lucide, ISC).** Semua ikon emoji di HUD
  (🔊 ▶ 🔍 ◆) diganti SVG inline (shield, activity, search, play,
  volume, refresh, scan, trash, sun, moon — grid 24px, stroke 2,
  currentColor), sesuai standing order ikon MyLord.

### Diubah

- **Sistem desain baru (referensi: CISO dashboard C3iHub).**
  Halaman slate gelap #2A2C38, kartu #1E1F27, sidebar #1F1F3B,
  biru aksi #0168FF, nav terpilih #2F2263. Satu skala severity di
  semua tempat: Critical #F53821, High #FF9B10, Medium #FFCE20,
  Low #00D796, Informative #80CAFF — dipakai di kartu KPI (garis
  aksen kiri), badge sumber, badge severity temuan, dan badge level
  intel. Warna kuat hanya untuk hal yang bermakna; biru hanya
  untuk aksi.
- **Tipografi profesional.** UI memakai sans-serif sistem (Inter/
  Segoe UI); monospace hanya untuk nilai data (timestamp, ID,
  evidence). Neon cyan (#00f5d4) dan latar hitam pekat (#040811)
  dihapus — keduanya ciri khas "dashboard AI generik".
- **Layout sidebar.** Navigasi (Activity / Threat intel / Findings)
  pindah ke sidebar kiri tetap (seperti dashboard SOC sungguhan);
  konten utama max-width 1120px. Di layar sempit (<760px) sidebar
  runtuh jadi bar atas. Tabel dibungkus kartu (radius + border),
  header huruf kapital kecil, baris hover, badge severity dengan
  titik + label (bukan warna saja — aksesibel untuk buta warna).
- **Unit test: 28/28 lulus** (6 V22 + 6 R1 + 11 R2 + 5 R2.5 baru).
  **E2E: 36/36 lulus** (HTTP nyata: tema + desain + semua alur R2).

## [2.4.0-alpha] — 2026-11-09

Revisi Fase R2 (atas permintaan MyLord, satu per satu dari chat):
i18n HUD (Inggris default, 15 bahasa), simulasi yang terlihat
persisten, aturan khusus yang bisa ditambah/diedit pengguna, pindai
(quick/full/network) + tab Temuan, riwayat tanpa batas + pencarian,
empty state yang kaya informasi, dan intelijen ancaman global
real-time + kolom penjelasan awam/profesional. **Keputusan guard
(blokir/ubah) tidak berubah** — yang berubah adalah bahasa,
visibilitas, dan alat bantu di sekitarnya, bukan logika pemblokiran.

### Ditambah

- **i18n HUD (15 bahasa, Inggris default).** `hermes_manas_aegis/i18n.py`:
  Inggris, Indonesia, Spanyol, Prancis, Jerman, Portugis, Italia,
  Rusia, Turki, Arab, Hindi, Tionghoa, Jepang, Korea, Vietnam.
  Menu bahasa di kanan atas HUD; pilihan tersimpan di browser;
  `?lang=` di URL juga didukung; bahasa tak dikenal jatuh ke Inggris.
  Nama aturan, ID advisori, dan CWE tidak diterjemahkan.
  Penjelasan awam/profesional tersedia dalam Inggris + Indonesia,
  bahasa lain menampilkan penjelasan Inggris.
- **Simulasi terlihat persisten.** Ringkasan simulasi terakhir
  (waktu, berapa dari 6 contoh yang cocok, berapa diblokir/diubah/
  dialihkan) kini tersimpan dan tampil di HUD — tidak lagi hilang
  saat halaman dimuat ulang. Setiap kartu KPI juga menampilkan
  sub-jumlah simulasinya (`simulation: N`). Kartu besar tetap
  menghitung **hanya aktivitas nyata** — simulasi tidak pernah
  menggelembungkan angka nyata (itu ketidakjujuran v2.2.0 yang
  diperbaiki R1 dan dipertahankan di sini).
- **Aturan khusus (custom rules).** File
  `~/.hermes/manas-aegis-custom-rules.json` (di home, bukan di
  direktori plugin, supaya tidak ikut terhapus saat install ulang):
  `rules[]` (aturan baru, `rule_id` harus diawali `CUSTOM-`) dan
  `overrides{}` (mengganti pola utama MANAS-SQLI-AST,
  MANAS-SHELL-RCE, MANAS-CONFIG-FIM, MANAS-MEM-FIREWALL).
  Validasi penuh saat dimuat (regex harus bisa dikompilasi,
  `test_positive`/`test_negative` harus lolos, override aturan
  yang tidak dikenal ditolak); entri tidak valid ditolak dan
  dicatat sebagai error — plugin tidak pernah mati karena file
  aturan yang rusak. Aturan khusus yang valid benar-benar
  dijalankan engine dan muncul di katalog HUD dengan badge "custom".
- **Pindai (quick / full / network) + tab Temuan.**
  Quick: integritas konfigurasi vs baseline persisten
  (`cce_baseline.json`), decoy honeypot, validasi aturan khusus,
  backstop telemetri, self-test aturan. Full: quick + pemindaian
  isi file di `~/.hermes` (pola injeksi prompt, karakter zero-width,
  secret di luar file kredensial yang dikenal, heuristik token bomb;
  maks. 300 file / 1 MB per file; direktori plugin dilewati).
  Network: **hanya** postur jaringan plugin sendiri (HUD loopback,
  izin file state, postur SSRF) — **bukan** port scan dan **bukan**
  pemindaian LAN/internet. Temuan tersimpan (`scan_state.json`,
  maks. 50, duplikat digabung) dan tampil di tab Temuan — itulah
  "notifikasi" plugin ini; tidak ada saluran push.
- **Riwayat tanpa batas + pencarian.** Cap 120 event **dihapus**.
  File live menyimpan 500 event terbaru (agar HUD cepat dimuat);
  event yang lebih lama pindah ke arsip append-only
  (`manas_telemetry_archive.jsonl`) yang tidak pernah dihapus
  plugin — kecuali lewat "Hapus riwayat" (yang juga menghapus
  arsip). Kotak pencarian di tab Aktivitas + endpoint
  `/api/search?q=...` mencari riwayat live dan arsip.
- **Empty state kaya informasi.** Saat belum ada aktivitas nyata,
  panel kosong kini menampilkan versi, status koneksi, jumlah
  aturan (eksperimental + khusus + terencana), aturan khusus,
  simulasi terakhir, pindai terakhir, dan cara memunculkan
  aktivitas — bukan sekadar satu kalimat.
- **Intelijen ancaman global real-time.** Diambil otomatis dari
  **CISA KEV** dan **NVD CVE API 2.0** (keduanya gratis, tanpa
  kunci, resmi), cache lokal `threat_intel.json` (maks. 40 item),
  refresh otomatis tiap 10 menit bila cache lebih tua dari 6 jam +
  tombol "Perbarui intelijen". Tanpa internet, cache lama tetap
  ditampilkan dan HUD menulis dengan jelas bahwa data mungkin
  kedaluwarsa. Ditampilkan sebagai **kewaspadaan global** — plugin
  TIDAK memeriksa apakah perangkat ini terdampak.
- **Kolom Penjelasan di katalog aturan.** Setiap aturan punya
  penjelasan dua tingkat: "Untuk semua orang" (bahasa awam) dan
  "Untuk profesional keamanan" (pola/trigger dan batasnya).

### Diubah

- **Bahasa default HUD: Inggris** (sebelumnya Indonesia).
  Tes R1 yang mengasumsikan Indonesia kini memanggil HUD dengan
  `lang="id"` secara eksplisit.
- **Baseline konfigurasi kini persisten** (`cce_baseline.json`) dan
  **dibandingkan ulang** oleh quick scan — baris MANAS-CONFIG-FIM
  di README diperbarui (tetap bukan FIM sungguhan: tidak ada
  pemantauan real-time).
- **"Hapus riwayat" kini juga menghapus arsip** (live + archive +
  feed STIX), bukan hanya file live.
- **Unit test: 23/23 lulus** (6 V22 + 6 R1 + 11 R2 baru).
  **E2E: 27/27 lulus** (HTTP nyata: default Inggris, `?lang=id`,
  fallback bahasa tak dikenal, barrage → ringkasan persisten,
  pencarian, pindai, refresh intel, hapus riwayat).

## [2.3.0-alpha] — 2026-11-09

Revisi Fase R1: klaim diluruskan, label alpha, dokumentasi
operasional, UI HUD jujur, redaksi telemetri, pemisahan event
simulasi. **Keputusan guard (blokir/ubah) tidak berubah** —
yang berubah adalah kejujuran label/angka dan cara data dicatat
dan ditampilkan, bukan logika pemblokiran.

### Diubah

- **Label alpha.** Plugin kini jelas berlabel ALPHA/prototipe di
  README.md (baris pertama), `plugin.yaml`, dan `pyproject.toml`
  (versi 2.3.0). Peringatan opt-in + lingkungan uji non-sensitif
  ditulis di depan.
- **Klaim diluruskan.**
  - Dihapus: "Absolute Defense", "Autonomous Threat-Synthesis
    Core" sebagai klaim keamanan, "10 runtime rules" tanpa
    pembedaan, "standards enforced" (nilai statis di kode,
    bukan hasil pemeriksaan — README lama sendiri hanya menyebut
    ~12 kerangka), "TAXII LIVE" (tidak ada transport TAXII —
    hanya bundel STIX 2.1 lokal), dan "Virtual Patching Engine"
    sebagai patch sistem (yang dilakukan hanya mengubah argumen
    yang dikembalikan ke Hermes).
  - Dihapus: klaim "Dual-Layout Compatibility (Hermes 0.21.x &
    0.23.x)" dan "validate/doctor pass cleanly" — tidak ada bukti
    integrasi di repo yang mendukungnya. Diganti dengan yang
    benar-benar dites: Hermes 0.21.5 di PC; 0.23.x BELUM dites.
  - Tag `stix-taxii` di `plugin.yaml` diganti `stix-local`.
  - Deskripsi `tactical_doctrine` diperbaiki: `ssvc_enforce`
    dan `stealth_audit` tidak punya perilaku apa pun di kode
    (hanya nilai enum; tidak ada gate SSVC di mana pun) —
    satu-satunya cabang doktrin adalah `counter_deceive`,
    doktrin lain membuat CRED-HONEYPOT jatuh ke HARD_BLOCK.
- **README ditulis ulang total** (README.md): bahasa sederhana,
  bagian "mencegah APA / TIDAK mencegah APA", tabel 10 guard
  (ancaman, trigger, tindakan, status, batas bypass, data yang
  dicatat), cara install, enable/disable, konfigurasi, verifikasi
  berhasil, troubleshooting, uninstall/rollback, data yang
  disimpan, versi Hermes yang dites, dan glosarium istilah.
- **Status guard dinyatakan jujur:** 0 implemented, 8
  experimental, 2 planned (MANAS-SYMLINK-GUARD dan
  MANAS-CALLID-RACE hanya terdefinisi di katalog, tanpa
  enforcement).
- **Dokumen baru:** SECURITY.md (cara melaporkan celah, tanpa
  bounty), CHANGELOG.md (berkas ini), CONTRIBUTING.md (aturan
  klaim + cara menjalankan tes).

### Diimplementasikan di kode (bukan hanya di dokumen)

- **UI HUD direvisi** (lihat
  `Manas-Aegis-Usulan-Revisi-UI.md`): layar pertama tenang tanpa
  alarm CVE palsu (empty state "Belum ada aktivitas yang cocok
  dengan aturan perlindungan." + panel "Yang dipantau / Yang
  tidak dipindai"); ID `HERMES-SEC-...` tampil sebagai ID
  advisori internal, bukan CVE; "Virtual Patches" → "Aktivitas
  yang diubah agar lebih aman"; "Hard Blocks" → "Aktivitas
  diblokir oleh aturan"; "N Rules Active" → "N aturan
  terdefinisi"; skor katalog pindah ke Detail teknis berlabel
  "nilai referensi aturan"; status "Aktif" hanya bila hook
  terverifikasi terdaftar, bila belum tampil "Status koneksi
  belum dapat diverifikasi"; chime mati default (opt-in lewat
  toggle Suara); tombol "Hapus riwayat" + endpoint
  `/api/clear-history`.
- **Redaksi telemetri sebelum disimpan:** `_redact_evidence`
  (rekursif: pola secret + kredensial di URL + potong 160
  karakter) diterapkan pada evidence sebelum event ditulis ke
  `manas_telemetry.json` — bukan hanya pada output stream.
- **Event simulasi dipisah dari event nyata:** `intercept_tool_call`
  menerima `event_source="simulation"`; `execute_barrage_simulation`
  memakai itu; counter `total_intercepted`/`hard_blocked` hanya
  menghitung event nyata; event simulasi dihitung terpisah
  (`simulation_events`) dan berlabel SIMULASI di HUD.
- **Status guard di kode:** `ThreatVectorSpec.status` —
  8 `experimental`, 2 `planned` (SYMLINK-GUARD, CALLID-RACE);
  `get_system_posture` mengembalikan `rules_defined` (10) dan
  `rules_enforced` (8, aturan eksperimental) + `alpha: True`,
  menggantikan `verifiable_rules_active` dan `standards_enforced`
  (21, nilai statis).
- **Tes:** 12 unit test (6 lama + 6 baru R1: redaksi rekursif,
  redaksi di telemetri tersimpan, pemisahan counter simulasi,
  status aturan planned, empty state HUD, badge SIMULASI) —
  **12/12 lulus** (`python3 -m unittest discover -v`,
  diverifikasi 2026-11-09). Discovery dari root kini menemukan
  semua tes (dulu 0 — diperbaiki dengan `tests/__init__.py`).

### Diketahui, masuk R2

- **SSRF fail-open:** DNS yang gagal saat ini dianggap SAFE
  (core_engine.py: `except socket.gaierror: pass`). Akan dibuat
  fail-closed; hasil cek DNS juga belum mengikat koneksi
  berikutnya, redirect belum diperiksa.
- **Bypass perintah git berantai (terkonfirmasi):** `git status;
  touch /tmp/pwned` — perintah kedua tetap utuh. Rewrite hanya
  mengganti kemunculan `git` pertama.
- **Bypass `python -c` (terkonfirmasi):** `python -c` tanpa
  `socket` + `subprocess` dalam string yang sama lolos dari pola
  SHELL-RCE.
- **Path canonicalization:** pemeriksaan path berbasis substring,
  tanpa canonicalization dan tanpa symlink check.
- **HUD tanpa auth/CSRF/rate limit:** endpoint HUD (termasuk
  `/api/barrage` via POST) tidak memakai autentikasi aplikasi,
  pemeriksaan Origin/CSRF, atau rate limit; HUD loopback saja.
- **Tes:** 12 unit test (6 lama + 6 baru R1), cakupan tetap
  sempit — bypass yang diketahui (git chaining, `python -c`,
  SSRF fail-open) belum diperbaiki, itu Fase R2. Belum ada
  contract test Hermes, CI, atau tes instalasi bersih.
- **Packaging:** wheel Python tidak membawa `plugin.yaml` /
  aset Desktop dan belum punya entry point plugin Hermes yang
  dinyatakan; instalasi bersih Hermes perlu jadi release gate.
- **Dua guard planned:** MANAS-SYMLINK-GUARD dan
  MANAS-CALLID-RACE belum punya enforcement sama sekali.

## [2.2.0] — 2026-11-08

Versi yang disubmit ke hackathon Hermes (PR katalog #151320).
Klaim-klaim pada versi ini yang kemudian diluruskan di atas
tercantum di `REVISI.txt` (verdict revisi).
