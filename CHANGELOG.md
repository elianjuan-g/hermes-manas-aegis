# Changelog — Manas Aegis

Semua perubahan penting pada plugin ini dicatat di sini. Format
mengikuti [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
secara longgar. Versi memakai `MAJOR.MINOR.PATCH` + label
`-alpha` selama masih prototipe.

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
