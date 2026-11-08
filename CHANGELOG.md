# Changelog — Manas Aegis

Semua perubahan penting pada plugin ini dicatat di sini. Format
mengikuti [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
secara longgar. Versi memakai `MAJOR.MINOR.PATCH` + label
`-alpha` selama masih prototipe.

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
