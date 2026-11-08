# Manas Aegis — Plugin Guardrail untuk Hermes Agent

> **⚠️ ALPHA / PROTOTIPE — v2.3.0-alpha**
>
> Plugin ini masih **prototipe eksperimental**. Pasang hanya kalau Anda
> memilih ikut mencoba (**opt-in**), dan hanya di **lingkungan uji
> non-sensitif** — bukan di komputer produksi, bukan untuk melindungi
> data rahasia, dan bukan sebagai satu-satunya pengaman Anda.
>
> Jangan pasang plugin ini lalu merasa komputer Anda sudah aman.
> Plugin ini hanya memeriksa sebagian aktivitas tool Hermes Agent,
> sebelum tool itu dijalankan. Ia **bukan** pemindai seluruh komputer,
> **bukan** pemindai CVE untuk semua software yang terpasang, dan
> **bukan** jaminan bahwa tidak ada serangan yang lolos.

## Apa itu Manas Aegis?

Manas Aegis adalah plugin **guardrail** (pagar pembatas) untuk Hermes
Agent. Cara kerjanya sederhana:

1. Sebelum Hermes menjalankan sebuah tool, plugin memeriksa argumen
   (isi perintah) tool tersebut.
2. Bila argumen cocok dengan salah satu pola aturan, plugin bisa
   **memblokir** (tool tidak dijalankan), **mengubah** argumen
   (misalnya menambahkan flag aman pada perintah git, atau
   mengganti pola berbahaya dengan teks pengganti), atau
   **menyamarkan** isi sensitif pada hasil tool.
3. Setiap tindakan plugin dicatat sebagai event di file lokal di
   komputer Anda, dan bisa dilihat di dasbor web lokal (HUD).

Semua pemeriksaan dilakukan dengan **pencocokan pola teks (regex)**,
bukan dengan parser bahasa, bukan dengan sandbox, dan bukan dengan
firewall jaringan. Itu sebabnya ada celah yang diketahui — lihat
tabel aturan di bawah.

## Ini mencegah APA — dan TIDAK mencegah APA

### Yang bisa dicegah (sebatas pola yang dikenal)

- Perintah git tertentu yang ditulis ulang dengan flag aman.
- Pembacaan file kredensial yang polanya dikenali — dialihkan ke
  file umpan (decoy) atau diblokir, tergantung pengaturan.
- URL yang jelas-jelas mengarah ke alamat privat/loopback/metadata
  cloud — diblokir sebelum tool dijalankan.
- Pola injeksi SQL dan perintah shell destruktif yang polanya
  dikenali — diblokir.
- Pola injeksi pada konfigurasi hook dan pada tool memory.

### Yang TIDAK dicegah — baca ini sebelum memakai

- **Bukan sandbox.** Plugin tidak membatasi apa yang bisa dilakukan
  sistem operasi, jaringan, atau tool yang tidak melewati hook
  Hermes. Perintah yang tidak cocok dengan pola akan lolos.
- **Bukan firewall jaringan.** Plugin hanya memeriksa URL di argumen
  tool. Ia tidak mengikat koneksi berikutnya ke IP yang diperiksa,
  tidak memeriksa redirect, dan tidak menegakkan kebijakan egress.
- **Bukan satu-satunya kontrol keamanan.** Jangan jadikan plugin ini
  satu-satunya pelindung akses file, jaringan, atau secret Anda.
- **Bukan pemindai CVE.** Angka dan ID yang tampil di HUD adalah
  **ID advisori internal** (`HERMES-SEC-...`) dan nilai referensi
  dari katalog aturan — bukan CVE publik dan bukan hasil pemindaian
  perangkat Anda.
- **Bukan patch sistem.** Yang disebut "mengubah argumen" di sini
  hanya mengubah argumen yang dikembalikan ke Hermes. Plugin tidak
  menambal software apa pun.
- **Tidak semua aturan aktif.** Dari 10 aturan di katalog, **8
  eksperimental** dan **2 hanya terdefinisi** (planned) — lihat tabel.
- **Bila hook gagal atau plugin mati**, tidak ada perlindungan dari
  plugin. Hermes tetap berjalan seperti biasa tanpa pemeriksaan ini.

## Tabel 10 guard

Status:

- **experimental** — ada kode pemeriksaannya, tapi berbasis pola dan
  punya celah yang diketahui. Jangan diandalkan sebagai pengaman
  tunggal.
- **planned** — hanya ada namanya di katalog aturan. **Tidak ada**
  pemeriksaan yang berjalan di v2.3.0-alpha.

| Aturan | Ancaman | Trigger | Tindakan | Status | Batas / bypass yang diketahui | Data yang dicatat |
|---|---|---|---|---|---|---|
| MANAS-GIT-FS-RCE | Perintah git yang memanfaatkan konfigurasi repo berbahaya (CWE-78) | Perintah git `status`, `diff`, `log`, `checkout`, `pull`, `fetch`, atau `clone` pada argumen `command`/`cmd`/`script` | modify | experimental | Hanya subcommand di atas yang ditulis ulang, dan hanya kemunculan pertama. **Perintah berantai lolos**, contoh: `git status; touch /tmp/pwned` — bagian kedua tetap berjalan. Bukan parser shell. | Perintah git yang sudah diubah (maks. 110 karakter pertama) |
| MANAS-CRED-HONEYPOT | Pembacaan file kredensial (CWE-522 / CWE-73) | Argumen berisi path kredensial yang dikenali (mis. `.hermes/auth.json`, `.env`, kunci SSH, `.aws/credentials`) pada operasi baca | modify / block | experimental | Pencocokan substring pada teks argumen saja. **Tanpa canonicalization dan tanpa pemeriksaan symlink** — variasi path/encoding bisa lolos (perbaikan direncanakan di R2). | Path yang cocok dan path decoy tujuan (bila dialihkan) |
| MANAS-SSRF-SINKHOLE | Permintaan ke alamat internal / metadata cloud (CWE-918) | URL `http(s)://...` di argumen tool yang mengarah ke IP privat, loopback, link-local, reserved, `localhost`, atau host metadata | block | experimental | **DNS yang gagal saat ini dianggap SAFE** — ini keterbatasan yang diketahui dan akan dibuat fail-closed di R2. Hasil cek DNS juga tidak mengikat koneksi berikutnya, dan redirect tidak diperiksa. | URL dan alasan pemblokiran |
| MANAS-WEBHOOK-AUTH | Session ID webhook berbentuk aneh (CWE-863) | `session_id` diawali `webhook:` dan berisi lebih dari 2 tanda colon (`:`) | block | experimental | Hanya memeriksa **bentuk** session ID, **bukan autentikasi webhook**. Session ID yang bentuknya normal tapi palsu tidak terdeteksi. | Session ID yang diblokir |
| MANAS-CONFIG-FIM | Injeksi hook pada konfigurasi (CWE-94) | Pola teks injeksi hook konfigurasi di argumen tool | block | experimental | Hanya memblokir pola teks. Hash konfigurasi hanya di-snapshot sekali saat init dan **tidak pernah dibandingkan ulang** — ini **bukan** file-integrity monitoring (FIM) sungguhan. | Potongan argumen (maks. 160 karakter) |
| MANAS-MEM-FIREWALL | Injeksi directive ke memory (CWE-74) | Pola directive-injection di argumen tool yang namanya mengandung `memory` | modify | experimental | Hanya berlaku untuk tool yang namanya mengandung "memory". Pola di luar itu tidak disentuh. | Catatan bahwa pola dibersihkan dari argumen |
| MANAS-SYMLINK-GUARD | Serangan symlink / TOCTOU (CWE-59) | — (tidak ada trigger) | — | **planned** | Hanya terdefinisi di katalog aturan. **Tidak ada enforcement di v2.3.0-alpha.** | — |
| MANAS-SQLI-AST | Injeksi SQL (CWE-89) | Pola regex injeksi SQL pada argumen tool (teks argumen digabung jadi satu string) | block | experimental | **Bukan parser AST SQL** — hanya pencocokan pola. Pola baru yang belum dikenal bisa lolos; teks normal yang kebetulan mirip pola bisa terblokir. | Potongan argumen (maks. 160 karakter) |
| MANAS-SHELL-RCE | Perintah shell destruktif (CWE-78) | Pola regex perintah shell destruktif pada argumen tool | block | experimental | Hanya pola yang dikenal. **`python -c` tanpa `socket` + `subprocess` dalam string yang sama lolos dari pola**; perintah berantai juga bisa lolos. Bukan sandbox shell. | Potongan argumen (maks. 160 karakter) |
| MANAS-CALLID-RACE | Race condition call-ID antar sesi (CWE-362) | — (tidak ada trigger) | — | **planned** | Hanya terdefinisi di katalog aturan. **Tidak ada enforcement di v2.3.0-alpha.** | — |

Catatan tentang angka di tabel dan di HUD: nilai seperti CVSS,
CWSS, EPSS, dan SSVC adalah **nilai referensi yang ditulis di
katalog aturan**, bukan hasil pengukuran atas perangkat Anda.
Jangan membacanya sebagai "skor risiko komputer saya". Angka "standards enforced" yang ada di README lama adalah **nilai
statis yang ditulis langsung di kode** (core_engine.py:297) —
bukan hasil pemeriksaan atas sekian standar; README lama sendiri
hanya menyebut sekitar 12 kerangka bernama. Angka itu tidak dipakai
lagi di dokumen ini.

## Cara install

Jalur yang terverifikasi:

1. Salin direktori plugin ini ke
   `~/.hermes/plugins/hermes-manas-aegis`.
2. Aktifkan plugin di Hermes.
3. Verifikasi dengan perintah:

   ```sh
   hermes plugins validate ~/.hermes/plugins/hermes-manas-aegis
   ```

> [BELUM TERVERIFIKASI] Langkah detail mengaktifkan plugin lewat
> antarmuka Hermes, serta perintah `hermes plugins validate <dir>
> --install-deps`, belum terverifikasi dari instalasi bersih di
> mesin ini. Bila perintah di atas gagal, lihat bagian
> Troubleshooting di bawah dan laporkan hasilnya (lihat
> CONTRIBUTING.md).

Yang **belum** terverifikasi dan karena itu **tidak** kami janjikan:

- Instalasi lewat paket Python (wheel) — paket Python saat ini
  tidak membawa `plugin.yaml` dan aset Desktop, jadi build Python
  saja belum membuktikan plugin bisa dipasang lewat jalur resmi
  Hermes. Perbaikan packaging masuk R2.
- Kompatibilitas dengan Hermes selain versi yang dites (lihat
  "Versi Hermes yang dites" di bawah).

## Enable / disable

- **Memakai plugin:** aktifkan di Hermes, lalu mulai sesi Hermes
  seperti biasa. Bila plugin jalan, HUD tersedia (lihat
  "Verifikasi berhasil").
- **Mematikan plugin:** nonaktifkan plugin di Hermes, atau hapus
  direktori plugin (lihat "Uninstall / rollback"). Setelah itu
  Hermes berjalan tanpa pemeriksaan Manas Aegis.
- **Mematikan HUD saja:** atur `auto_launch_hud_server` ke `false`
  di konfigurasi plugin (lihat "Konfigurasi"). HUD tidak lagi
  otomatis menyala saat sesi dimulai.

> [BELUM TERVERIFIKASI] Nama menu dan langkah klik untuk
> enable/disable di Hermes Desktop belum terverifikasi dari
> instalasi bersih. Bila menu di perangkat Anda berbeda, hapus
> direktori plugin adalah cara mematikan yang paling pasti.

## Konfigurasi

Opsi-opsi ini ada di `plugin.yaml` (`config_schema`):

| Opsi | Default | Yang sebenarnya dilakukan |
|---|---|---|
| `tactical_doctrine` | `counter_deceive` | Mengubah perilaku **baca kredensial saja**. `counter_deceive`: operasi baca file kredensial dialihkan ke file umpan (decoy). **`ssvc_enforce` dan `stealth_audit` tidak punya perilaku apa pun di kode** — keduanya hanya nilai enum di `plugin.yaml`; tidak ada gate SSVC di mana pun. Satu-satunya cabang doktrin di kode adalah `if doctrine == "counter_deceive"` (core_engine.py:428): doktrin lain membuat CRED-HONEYPOT jatuh ke jalur HARD_BLOCK (blokir). Doctrine **tidak** menambah enforcement lain, dan tidak membuat SSVC memblokir semua keputusan ACT/ATTEND. |
| `auto_launch_hud_server` | `true` | Bila `true`, HUD otomatis dinyalakan saat plugin terdaftar. Bila `false`, HUD tidak otomatis menyala. |
| `hud_port` | `18777` | Port lokal HUD. HUD hanya mendengarkan di loopback (`127.0.0.1`). |
| `git_rce_synthesis` | `true` | Bila `true`, perintah git yang dikenali ditulis ulang dengan flag aman (lihat MANAS-GIT-FS-RCE). Bila `false`, penulisan ulang git dimatikan. |
| `ssrf_dns_firewall` | `true` | Bila `true`, URL di argumen tool diperiksa DNS-nya dan URL ke alamat internal diblokir (lihat MANAS-SSRF-SINKHOLE). Bila `false`, pemeriksaan SSRF dimatikan. Ingat: DNS yang gagal saat ini dianggap SAFE. |

Catatan: konfigurasi dibaca saat plugin pertama kali dibuat.
Mengubah konfigurasi setelahnya tidak otomatis diterapkan sampai
plugin dimuat ulang.

## Verifikasi berhasil

Bila plugin berjalan, Anda akan melihat:

1. **HUD di `http://127.0.0.1:18777`** — dasbor lokal yang
   menampilkan status plugin dan riwayat event. Bila halaman
   tidak bisa dibuka, HUD belum jalan (lihat Troubleshooting).
2. **Event tercatat** — saat sebuah aturan menangani aktivitas,
   satu event muncul di riwayat HUD dan tersimpan di file
   `manas_telemetry.json` (lihat "Data yang disimpan").

Cara membaca HUD dengan benar:

- **Layar pertama yang tenang adalah normal.** Pada instalasi
  baru tanpa riwayat, yang benar tampil adalah: *"Belum ada
  aktivitas yang cocok dengan aturan perlindungan."* Itu artinya
  belum ada aktivitas yang ditangani — **bukan** berarti komputer
  Anda bebas kerentanan.
- **Angka di HUD = event lokal yang tersimpan** (maksimal 120
  event terbaru), bukan jumlah serangan di internet dan bukan
  hasil pemindaian perangkat.
- **ID `HERMES-SEC-...` adalah ID advisori internal**, bukan CVE
  publik. Jangan membacanya sebagai "CVE yang ditemukan di
  perangkat saya".
- **Simulasi berlabel SIMULASI.** Tombol simulasi menjalankan 6
  contoh input lokal terhadap aturan — itu latihan, bukan serangan
  nyata, dan hasilnya tidak dihitung sebagai aktivitas nyata.
- **Status "Aktif" hanya berarti plugin terdaftar di hook.**
  Bila status koneksi belum bisa diverifikasi, jangan anggap
  perlindungan sedang berjalan.

## Troubleshooting singkat

| Gejala | Kemungkinan penyebab | Yang bisa dilakukan |
|---|---|---|
| HUD tidak bisa dibuka di `127.0.0.1:18777` | HUD gagal start, atau port sudah dipakai proses lain | Periksa apakah plugin aktif; coba port lain lewat `hud_port`; periksa apakah ada proses lain memakai port 18777. Bila HUD tetap tidak jalan, plugin tetap bisa memeriksa tool — HUD hanya tampilannya. |
| Plugin tidak tampak menangani apa pun | Hook belum terdaftar (registrasi hook bersifat kondisional, tergantung method runtime Hermes), atau belum ada aktivitas yang cocok dengan pola | Jalankan `hermes plugins validate` pada direktori plugin; periksa versi Hermes Anda (lihat bawah). |
| Tool yang normal ikut terblokir | Teks argumen kebetulan cocok dengan pola (false positive — pola regex memang bisa salah) | Matikan sementara aturan terkait (`git_rce_synthesis` / `ssrf_dns_firewall` ke `false`) atau nonaktifkan plugin, lalu laporkan contohnya (lihat SECURITY.md / CONTRIBUTING.md). |
| Perintah berbahaya lolos | Pola belum mengenalinya (lihat kolom "Batas" di tabel guard) | Itu keterbatasan yang diketahui. Jangan andalkan plugin untuk perintah itu; laporkan sebagai temuan (lihat SECURITY.md). |
| `hermes plugins doctor` gagal | Diketahui: doctor gagal pada kwarg `parameters` di Hermes 0.21.5, sementara inti hook tetap jalan | Ini keterbatasan yang diketahui. Validasi utama adalah `hermes plugins validate` dan HUD/event yang tercatat. |

## Uninstall / rollback

Untuk menghapus plugin sepenuhnya:

1. Nonaktifkan plugin di Hermes (bila memungkinkan).
2. Hapus direktori plugin:

   ```sh
   rm -rf ~/.hermes/plugins/hermes-manas-aegis
   ```

3. Hapus file state (bila ada) — telemetri lokal
   `manas_telemetry.json` dan feed lokal
   `stix21_taxii_feed.json` di direktori state plugin.
4. Mulai ulang Hermes.

Tidak ada perubahan sistem lain yang dibuat plugin ini, jadi
menghapus direktori + file state di atas sudah mengembalikan
keadaan seperti sebelum plugin dipasang.

## Data yang disimpan

Semua data disimpan **lokal di komputer Anda**. Tidak ada data
yang dikirim ke server luar oleh plugin ini.

| Data | Isi | Batas |
|---|---|---|
| `manas_telemetry.json` | Event aktivitas yang ditangani aturan: waktu, nama tool, ID aturan, tindakan (diblokir/diubah), dan potongan argumen/bukti | Maksimal **120 event terbaru**; event lama terhapus otomatis |
| `stix21_taxii_feed.json` | Bundel STIX 2.1 lokal dari event yang sama (30 bundel terakhir) — ini file lokal, **bukan** feed TAXII live dan tidak ada transport TAXII | 30 bundel terakhir |

Yang perlu Anda tahu soal privasi:

- **Evidence diredaksi sebelum disimpan (sejak v2.3.0-alpha).**
  Sebelum event ditulis ke `manas_telemetry.json`, bukti (evidence)
  diredaksi secara rekursif: pola secret yang dikenal (mis. token
  `ghp_`/`sk-`, kunci AWS, JWT) diganti penanda, kredensial di URL
  (`user:pass@host`) disamarkan jadi `user:***@host`, dan bukti
  dipotong maksimal 160 karakter. Redaksi ini berbasis pola — bukan
  jaminan sempurna. **Jangan memasukkan data rahasia ke argumen tool
  saat plugin ini aktif**, dan jangan membagikan file telemetri Anda
  ke orang lain tanpa memeriksa isinya. `session_id` dan nama tool
  tetap tersimpan apa adanya.
- HUD berjalan di loopback (`127.0.0.1`) sehingga tidak bisa
  diakses dari jaringan luar, tetapi endpoint HUD **tidak memakai
  autentikasi, pemeriksaan Origin/CSRF, atau rate limit**.
  Siapa pun yang bisa mengakses komputer Anda bisa membuka HUD
  dan memanggil endpoint-nya.
- File decoy (`honeypot_sandbox/decoy.env`,
  `honeypot_sandbox/decoy_auth.json`) berisi **data umpan palsu**
  yang sengaja mudah dikenali — bukan kredensial asli.

## Versi Hermes yang benar-benar dites

- **Hermes 0.21.5 — dites di PC.** `hermes plugins validate`
  lolos sebagian; `hermes plugins doctor` gagal pada kwarg
  `parameters` (inti hook tetap jalan). Unit test di salinan kerja
  rev1 ini: **12/12 lulus** (`python3 -m unittest discover -v`,
  diverifikasi 2026-11-09) — 6 tes lama + 6 tes baru R1 (redaksi,
  pemisahan counter simulasi, status aturan, empty state HUD).
  Discovery dari root kini menemukan semua tes (dulu 0 — diperbaiki
  dengan `tests/__init__.py`). Cakupan tetap sempit: bypass yang
  diketahui (git chaining, `python -c`, SSRF fail-open) belum
  diperbaiki — itu Fase R2.
- **Hermes 0.23.x — BELUM dites.** Jangan menganggap plugin ini
  sudah terbukti jalan di 0.23.x.

Registrasi hook bersifat kondisional — tergantung method apa yang
disediakan runtime Hermes. `pre_llm_call` hanya menaikkan pengali
risiko sesi menjadi 1,95 bila pola racun memory cocok pada 3 pesan
terakhir, dan **selalu return None** — ia tidak memblokir atau
menyaring pesan LLM apa pun.

## Cara melaporkan celah keamanan

Lihat [SECURITY.md](SECURITY.md). Singkatnya: laporkan lewat
GitHub Issues repo ini dengan label `security`, jangan menguji
celah di sistem orang lain, dan jangan mempublikasikan detail
celah sebelum ada perbaikan.

## Istilah yang dipakai di dokumen ini

- **Guardrail** — pagar pembatas: memeriksa dan membatasi sebagian
  aktivitas, bukan benteng keamanan menyeluruh.
- **Hook** — titik di alur Hermes tempat plugin bisa memeriksa
  aktivitas sebelum/sesudah tool dijalankan.
- **Modify / block / observe** — modify: argumen diubah lalu
  tool tetap jalan; block: tool tidak dijalankan; observe:
  hanya dicatat.
- **Regex / pola** — pencocokan teks berdasarkan pola karakter.
  Cepat tapi mudah diakali dengan variasi teks.
- **Decoy / honeypot** — file umpan berisi data palsu, untuk
  menyesatkan pembaca yang tidak berhak.
- **STIX** — format standar untuk mencatat informasi ancaman.
  Di plugin ini STIX hanya berupa file lokal, bukan feed live.
- **Fail-open / fail-closed** — fail-open: bila pemeriksaan gagal
  (mis. DNS error), aktivitas dianggap aman dan dibiarkan lewat;
  fail-closed: bila pemeriksaan gagal, aktivitas diblokir.
  SSRF di plugin ini masih fail-open (akan diperbaiki di R2).
