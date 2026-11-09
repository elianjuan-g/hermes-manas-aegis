# Manas Aegis — Plugin Guardrail untuk Hermes Agent

> **⚠️ ALPHA / PROTOTIPE — v2.6.2-alpha**
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
- **Semua aturan aktif.** Ke-10 aturan di katalog **enforced**
  (status experimental — berbasis pola, bukan planned). Sejak
  v2.6.0-alpha tidak ada lagi aturan berstatus planned — lihat tabel.
- **Bila hook gagal atau plugin mati**, tidak ada perlindungan dari
  plugin. Hermes tetap berjalan seperti biasa tanpa pemeriksaan ini.

## Yang dipantau

Panel "Yang dipantau" di HUD merangkum cakupan plugin ini:

- **Yang dipantau:** sebagian aktivitas tool Hermes Agent yang cocok
  dengan 10 aturan eksperimental (lihat tabel guard di bawah — sejak
  v2.6.0-alpha tidak ada lagi aturan berstatus planned). Aktivitas
  yang tidak cocok dengan pola apa pun tidak dicatat.
- **Yang tidak dipindai:** plugin ini TIDAK memindai seluruh komputer,
  semua aplikasi, atau seluruh kerentanan pada perangkat. Bukan
  pemindai CVE dan bukan pemindai antivirus.
- **Aturan khusus (custom rules):** Anda bisa menambahkan aturan
  sendiri dan mengedit aturan bawaan tertentu — lihat di bawah.
  Aturan yang Anda tambah benar-benar dijalankan oleh engine
  (bukan sekadar pajangan), dan divalidasi sebelum dipakai.

### Aturan khusus (custom rules)

File: `~/.hermes/manas-aegis-custom-rules.json` (di direktori home
Anda, BUKAN di dalam direktori plugin — supaya aturan Anda tidak
ikut terhapus saat plugin di-install ulang).

Format:

```json
{
  "rules": [
    {
      "rule_id": "CUSTOM-BLOCK-BAD-WORD",
      "codename": "CUSTOM-BLOCK-BAD-WORD",
      "pattern": "rahasia-perusahaan",
      "tools": ["sqlite_query"],
      "test_positive": "baca rahasia-perusahaan dari db",
      "test_negative": "baca laporan bulanan dari db"
    }
  ],
  "overrides": {
    "MANAS-SQLI-AST": "SELECT\\s+.*\\bOR\\b\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1['\"]?"
  }
}
```

- `rules`: daftar aturan baru. Setiap aturan wajib punya `rule_id`
  (harus diawali `CUSTOM-`, unik), `codename`, dan `pattern` (regex).
  `tools` (opsional) membatasi aturan ke nama tool tertentu; bila
  kosong, aturan berlaku untuk semua tool. `test_positive` /
  `test_negative` (opsional tapi dianjurkan) membuktikan pola Anda
  benar: `test_positive` harus cocok dengan pola, `test_negative`
  harus tidak cocok.
- `overrides`: mengganti pola utama sebuah aturan bawaan. Hanya
  aturan yang punya satu pola utama yang bisa di-override:
  `MANAS-SQLI-AST`, `MANAS-SHELL-RCE`, `MANAS-CONFIG-FIM`,
  `MANAS-MEM-FIREWALL`. Override aturan lain ditolak dan dicatat
  sebagai error.
- **Validasi:** file dibaca saat plugin dimuat. Entri yang tidak
  valid (regex tidak bisa dikompilasi, `rule_id` salah, tes
  positif/negatif gagal, override aturan yang tidak dikenal)
  **ditolak dan dicatat sebagai error** — plugin tidak pernah mati
  karena file aturan yang rusak. Error terlihat di HUD (panel
  "Yang dipantau") dan di `get_system_posture()`.
- **Reload:** aturan dibaca saat plugin dimuat. Setelah mengedit
  file, muat ulang plugin (atau mulai ulang sesi Hermes) agar
  aturan baru berlaku.
- Aturan khusus yang valid muncul di tabel katalog HUD dengan
  badge "custom", lengkap dengan penjelasan yang dibuat dari
  deskripsi dan pola aturan tersebut.

## Tabel 10 guard

Status:

- **experimental** — ada kode pemeriksaannya, tapi berbasis pola dan
  punya celah yang diketahui. Jangan diandalkan sebagai pengaman
  tunggal.
- **planned** — hanya ada namanya di katalog aturan. **Tidak ada**
  pemeriksaan yang berjalan. (Di v2.6.0-alpha: tidak ada lagi aturan
  berstatus planned — ke-10 aturan enforced.)

| Aturan | Ancaman | Trigger | Tindakan | Status | Batas / bypass yang diketahui | Data yang dicatat |
|---|---|---|---|---|---|---|
| MANAS-GIT-FS-RCE | Perintah git yang memanfaatkan konfigurasi repo berbahaya (CWE-78) | Perintah git `status`, `diff`, `log`, `checkout`, `pull`, `fetch`, atau `clone` pada argumen `command`/`cmd`/`script` | modify | experimental | Hanya subcommand di atas yang ditulis ulang. Sejak v2.6.0-alpha perintah berantai dipecah per segmen oleh parser shell nyata — tiap segmen diperiksa dan ditulis ulang sendiri. Bukan sandbox shell. | Perintah git yang sudah diubah (maks. 110 karakter pertama) |
| MANAS-CRED-HONEYPOT | Pembacaan file kredensial (CWE-522 / CWE-73) | Argumen berisi path kredensial yang dikenali (mis. `.hermes/auth.json`, `.env`, kunci SSH, `.aws/credentials`) pada operasi baca — termasuk di dalam dict/list bersarang dan ditulis sebagai `~/...` | modify / block | experimental | Pencocokan substring pada teks argumen (rekursif ke dalam dict/list bersarang), ditambah canonicalization sejak v2.6.0-alpha: symlink di-resolve, `~` di-expand, dan baca yang mengarah ke berkas terlindungi dialihkan ke decoy (MANAS-SYMLINK-GUARD). Variasi path/encoding lain masih bisa lolos. | Path yang cocok dan path decoy tujuan (bila dialihkan) |
| MANAS-SSRF-SINKHOLE | Permintaan ke alamat internal / metadata cloud (CWE-918) | URL `http(s)://...` di argumen tool yang mengarah ke IP privat, loopback, link-local, reserved, multicast, unspecified, `localhost`, atau host metadata | block | experimental | **Sejak v2.6.0-alpha DNS yang gagal dianggap TIDAK AMAN (fail-closed)** — permintaan diblokir. Host di `ssrf_allowlist` dikecualikan. Hasil cek DNS juga tidak mengikat koneksi berikutnya, dan redirect tidak diperiksa. | URL dan alasan pemblokiran |
| MANAS-WEBHOOK-AUTH | Session ID webhook berbentuk aneh (CWE-863) | `session_id` diawali `webhook:` dan berisi lebih dari 2 tanda colon (`:`) | block | experimental | Hanya memeriksa **bentuk** session ID, **bukan autentikasi webhook**. Session ID yang bentuknya normal tapi palsu tidak terdeteksi. | Session ID yang diblokir |
| MANAS-CONFIG-FIM | Injeksi hook pada konfigurasi (CWE-94) | Pola teks injeksi hook konfigurasi di argumen tool | block | experimental | Hanya memblokir pola teks. Hash konfigurasi kini **dibandingkan ulang** oleh quick scan terhadap baseline persisten (`cce_baseline.json`) — perubahan dilaporkan sebagai temuan. Ini tetap **bukan** FIM sungguhan (tidak ada pemantauan file real-time, dan menghapus `cce_baseline.json` akan membuat baseline baru dari kondisi saat ini). | Potongan argumen (maks. 160 karakter) |
| MANAS-MEM-FIREWALL | Injeksi directive ke memory (CWE-74) | Pola directive-injection di argumen tool yang namanya mengandung `memory` | modify | experimental | Hanya berlaku untuk tool yang namanya mengandung "memory". Pola di luar itu tidak disentuh. | Catatan bahwa pola dibersihkan dari argumen |
| MANAS-SYMLINK-GUARD | Serangan symlink / TOCTOU (CWE-59) | Argumen berisi path yang setelah di-resolve (symlink, atau `~` yang di-expand) mengarah ke berkas kredensial yang dikenali | modify | experimental | Hanya berlaku untuk operasi baca. TOCTOU (symlink diganti setelah cek) tidak dicegah — ini bukan pengunci filesystem. | Path yang cocok dan path decoy tujuan (bila dialihkan) |
| MANAS-SQLI-AST | Injeksi SQL (CWE-89) | Pola regex injeksi SQL pada argumen tool (teks argumen digabung jadi satu string) | block | experimental | **Bukan parser AST SQL** — hanya pencocokan pola. Pola baru yang belum dikenal bisa lolos; teks normal yang kebetulan mirip pola bisa terblokir. | Potongan argumen (maks. 160 karakter) |
| MANAS-SHELL-RCE | Perintah shell destruktif (CWE-78) | Pola regex perintah shell destruktif pada argumen tool | block | experimental | Hanya pola yang dikenal. Sejak v2.6.0-alpha perintah berantai dipecah per segmen dan bentuk `python -c` berbahaya diblokir oleh parser shell per segmen; sejak v2.6.2-alpha pemecahan juga menghormati `$(...)`/backtick dan baris baru, dan `rm -rf` ke path absolut apa pun diblokir. Bukan sandbox shell. | Potongan argumen (maks. 160 karakter) |
| MANAS-CALLID-RACE | Race condition call-ID antar sesi (CWE-362) | Pemanggilan tool yang sama (sesi + tool + hash argumen sama) dalam 10 detik | block | experimental | Hanya berlaku untuk pemanggilan runtime; simulasi dikecualikan. Jendela 10 detik bisa dikonfigurasi (`callid_race_window_s`). | Nama tool dan hash argumen |

Catatan tentang angka di tabel dan di HUD: nilai seperti CVSS,
CWSS, EPSS, dan SSVC adalah **nilai referensi yang ditulis di
katalog aturan**, bukan hasil pengukuran atas perangkat Anda.
Jangan membacanya sebagai "skor risiko komputer saya". Angka "standards enforced" yang ada di README lama adalah **nilai
statis yang ditulis langsung di kode** (core_engine.py:297) —
bukan hasil pemeriksaan atas sekian standar; README lama sendiri
hanya menyebut sekitar 12 kerangka bernama. Angka itu tidak dipakai
lagi di dokumen ini.

## Skor postur, Guard Arena, dan audit time-travel (baru di v2.6.0)

### Skor postur (Posture Score)
Kartu skor di HUD memberi satu angka 0–100 + grade (A–F) untuk kondisi
perlindungan saat ini, dari lima komponen:
- **Aturan (25):** jumlah aturan enforced / aturan terdefinisi.
- **Enforcement (25):** dikurangi 5 per temuan scan kritis, dan 10 bila
  SSRF firewall dimatikan.
- **Hygiene (20):** dikurangi 10 bila ada error aturan khusus, dan 10
  bila ada temuan kritis integritas konfigurasi.
- **Intelijen (15):** 15 bila cache intelijen segar, 7 bila basi, 0 bila
  belum pernah diambil.
- **Aktivitas (15):** 15 bila ada event/pindai dalam 24 jam terakhir,
  7 bila pernah ada aktivitas, 0 bila belum ada sama sekali.

Skor ini adalah **ringkasan kondisi lokal**, bukan sertifikat keamanan.
Skor 100 tidak berarti komputer Anda aman — hanya berarti kondisi yang
plugin ini ukur sedang baik.

### Guard Arena
Tab **Arena** di HUD menjalankan 10 skenario serangan (hanya teks,
tidak pernah dieksekusi) melawan jalur enforcement yang sama dengan
runtime — pada core sekali pakai, jadi tidak mengotori telemetri Anda.
Hasilnya tersimpan (`arena_last.json`) dan tampil sebagai tabel
skenario / yang diharapkan / hasil / PASS–FAIL. Tombol **Run Arena**
menjalankan ulang kesepuluh skenario. Arena membuktikan aturan
benar-benar bekerja, bukan sekadar terdaftar di katalog.

### Audit time-travel (Time-travel audit)
Tombol **Run Time-travel audit** memeriksa ulang event runtime yang
sudah tersimpan, dan menandai event yang **baru akan tertangkap**
oleh mekanisme R3 (parser `python -c`, symlink guard, SSRF
fail-closed) padahal aturan lamanya tidak menangkapnya. Ini audit
**berbasis pola atas evidence yang tersimpan** — bukan replay penuh
(telemetri tidak menyimpan event "allow" dan evidence terpotong /
direduksi), jadi hasilnya adalah perkiraan jujur, bukan bukti mutlak.
Call-ID race tidak dinilai oleh audit ini (tidak bisa dinilai dari
satu event saja).

### Pengamanan HUD (baru di v2.6.0)
- **CSRF token** aktif di semua POST (token per-proses, dikirim lewat
  header `X-CSRF-Token`).
- **Rate limit:** maks. 20 POST per IP per 60 detik (HTTP 429 bila
  lewat).
- **Token auth (opt-in):** set `hud_auth_token` di konfigurasi plugin
  untuk meminta token sebelum HUD bisa dibuka (halaman login +
  cookie sesi HttpOnly 24 jam). **Default: mati** — karena HUD
  loopback-only dan tampil di dalam aplikasi Desktop sebagai iframe,
  auth bawaan akan memaksa halaman login di dalam aplikasi. Nyalakan
  bila Anda butuh lapisan tambahan.

## Pindai: quick scan, full scan, network scan

Tiga tombol pindai di HUD menjalankan pemeriksaan **on-demand**
(sekali jalan, bukan pemantauan terus-menerus). Hasilnya tersimpan
dan tampil di tab **Temuan** di HUD — itulah "notifikasi" plugin ini.
Plugin **tidak punya** saluran push (tidak ada notifikasi sistem,
email, atau pesan chat). Pemblokiran real-time tetap muncul di tabel
Aktivitas begitu terjadi.

### Quick scan

Pemeriksaan cepat tanpa membaca isi file Anda:

- **Integritas konfigurasi** — hash file konfigurasi yang dipantau
  dibandingkan dengan baseline persisten (`cce_baseline.json`).
  File yang berubah = temuan kritis; file baru/hilang = peringatan.
  Baseline dibuat otomatis saat pertama kali plugin berjalan.
- **Decoy honeypot** — file umpan (`decoy_auth.json`, `decoy.env`)
  masih ada atau tidak. Decoy yang hilang = temuan kritis.
- **Aturan khusus** — apakah ada aturan khusus yang tidak valid
  (lihat "Aturan khusus" di atas). Error validasi dilaporkan.
- **Backstop telemetri** — apakah ada secret atau pola injeksi
  yang lolos ke dalam evidence yang tersimpan (pertanda redaksi
  tidak sempurna). Secret di evidence tersimpan = temuan kritis.
- **Self-test aturan** — simulasi terakhir: berapa dari 6 contoh
  yang cocok dengan aturan. Bila belum pernah simulasi, dicatat
  sebagai info; bila ada contoh yang tidak cocok, dicatat sebagai
  peringatan.

### Full scan

Semua pemeriksaan quick scan, ditambah pemindaian isi file:

- **Isi file di `~/.hermes`** — file teks (maksimal 300 file,
  maksimal 1 MB per file) dipindai untuk pola injeksi prompt,
  karakter zero-width (penanda injeksi tersembunyi), secret di luar
  file kredensial yang dikenal, dan heuristik token bomb (pengulangan
  token ekstrem atau baris raksasa tanpa spasi yang bisa membanjiri
  konteks model).
- Direktori plugin ini sendiri **tidak** dipindai (isinya pola
  deteksi dan contoh simulasi — memindainya hanya menghasilkan
  false positive), symlink tidak diikuti, dan direktori
  `.git` / `node_modules` / `__pycache__` / `honeypot_sandbox`
  dilewati.

### Network scan

**Bukan** pemindaian port dan **bukan** pemindaian LAN/internet.
Network scan hanya memeriksa **postur jaringan plugin ini sendiri**:

- **HUD loopback** — apakah server HUD masih terikat di
  `127.0.0.1` (bukan di alamat jaringan luar).
- **Izin file state** — apakah file state plugin bisa ditulis
  siapa saja (world-writable). File yang hanya bisa dibaca
  orang lain tidak dianggap masalah (itu default umask normal).
- **Postur SSRF** — apakah evaluator SSRF aktif, berapa upaya
  SSRF yang sudah diblokir, dan catatan keterbatasan yang
  diketahui (DNS yang gagal dianggap TIDAK AMAN — fail-closed
  sejak v2.6.0-alpha).

### Yang TIDAK dilakukan pindai

- Tidak memindai seluruh komputer, semua aplikasi, atau semua
  kerentanan perangkat.
- Tidak memindai jaringan (tidak ada port scan, tidak ada
  pemindaian host lain).
- Tidak memperbaiki apa pun secara otomatis — pindai hanya
  **melaporkan** temuan. Tindakan atas temuan tetap keputusan
  Anda.

Temuan disimpan di `scan_state.json` (maksimal 50 temuan,
duplikat digabung dan diperbarui waktunya) dan tampil di tab
Temuan. Menghapus riwayat dari HUD juga menghapus temuan pindai.

## Intelijen ancaman global

Tab **Intelijen ancaman** di HUD punya dua bagian:

1. **Katalog aturan** — 10 aturan bawaan (plus aturan khusus
   Anda). Setiap baris kini punya kolom **Penjelasan** dengan dua
   tingkat: **"Untuk semua orang"** (bahasa awam: apa yang
   dilakukan aturan ini, dengan kata-kata biasa) dan **"Untuk
   profesional keamanan"** (pola/trigger dan batasnya). Penjelasan
   tersedia dalam bahasa Inggris dan Indonesia; bahasa lain
   menampilkan penjelasan Inggris.
2. **Intelijen global terbaru** — advisori dari sumber resmi yang
   diambil otomatis saat Hermes menyala dan ada internet.

### Sumber dan pembaruan

- **CISA Known Exploited Vulnerabilities (KEV)** —
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (daftar kerentanan yang diketahui sedang dieksploitasi aktif).
- **NVD CVE API 2.0** —
  `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&sortBy=published&sortOrder=desc`
  (CVE terbaru yang dipublikasikan).
- Keduanya gratis, tanpa kunci API, dan resmi. Data diambil
  maksimal 40 item terbaru dan disimpan di cache lokal
  (`threat_intel.json`).
- **Pembaruan otomatis:** server HUD memeriksa cache setiap
  10 menit dan mengambil ulang bila cache kosong atau lebih tua
  dari 6 jam. Ada juga tombol **"Perbarui intelijen"** di HUD
  untuk mengambil ulang secara manual.
- **Tanpa internet:** cache lama tetap ditampilkan dan HUD
  menulis dengan jelas bahwa data mungkin kedaluwarsa atau sumber
  tidak dapat dijangkau. Bila kedua sumber gagal, cache lama
  dipertahankan (tidak dihapus).

### Yang BUKAN intelijen ancaman di sini

- Ini **bukan** pemindaian perangkat Anda. Advisori global
  ditampilkan sebagai **kewaspadaan** — plugin TIDAK memeriksa
  apakah perangkat ini terdampak oleh advisori tersebut.
- Jangan membaca baris intelijen global sebagai "kerentanan yang
  ditemukan di perangkat saya". Bila Anda ingin tahu apakah suatu
  CVE memengaruhi software Anda, periksa versi software yang
  terpasang dan bandingkan dengan advisori tersebut.

## Bahasa

HUD tersedia dalam **15 bahasa**: Inggris, Indonesia, Spanyol,
Prancis, Jerman, Portugis, Italia, Rusia, Turki, Arab, Hindi,
Tionghoa, Jepang, Korea, dan Vietnam.

- **Bahasa default adalah Inggris.**
- Pilih bahasa dari menu di kanan atas HUD. Pilihan tersimpan di
  browser (localStorage) dan dipakai lagi saat Anda membuka HUD
  berikutnya. Anda juga bisa memilih bahasa lewat URL:
  `http://127.0.0.1:18777/?lang=id`.
- Nama aturan, ID advisori, dan CWE tidak diterjemahkan (itu
  identifier, bukan kalimat).
- Penjelasan "untuk semua orang" dan "untuk profesional
  keamanan" tersedia dalam bahasa Inggris dan Indonesia; bahasa
  lain menampilkan penjelasan Inggris.
- Menambah bahasa baru: tambah satu dict bahasa di
  `hermes_manas_aegis/i18n.py` dengan semua kunci yang sama seperti
  dict Inggris (ada pemeriksaan otomatis yang menolak kunci yang
  hilang), lalu tambah pasangan `(kode, nama)` ke
  `SUPPORTED_LANGS` di file yang sama.

## Desain HUD

HUD didesain ulang di v2.5.0-alpha dari sistem desain **dashboard
CISO C3iHub (IIT Kanpur, 2024)** — platform keamanan enterprise
yang benar-benar dikirim ke klien (perusahaan asuransi
internasional), bukan konsep Dribbble. Referensi:
<https://fulloflyf.com/work/ciso-dashboard/> dan panduan
<https://www.aufaitux.com/blog/cybersecurity-dashboard-ui-ux-design/>.

- **Token warna (gelap):** halaman slate `#2A2C38`, kartu `#1E1F27`,
  sidebar `#1F1F3B`, biru aksi `#0168FF`, nav terpilih `#2F2263`.
- **Satu skala severity di semua tempat:** Critical `#F53821`,
  High `#FF9B10`, Medium `#FFCE20`, Low `#00D796`,
  Informative `#80CAFF` — dipakai di kartu KPI, badge sumber,
  badge severity temuan, dan badge level intel. Warna kuat hanya
  untuk hal yang bermakna; biru hanya untuk aksi. Badge selalu
  punya titik + label (bukan warna saja).
- **Tema gelap + terang.** Tombol tema di kanan atas HUD.
  Tema terang: halaman `#F2F3F5`, kartu putih `#FFFFFF`,
  sidebar putih; hue severity sama tapi digelapkan agar kontras
  di latar putih. Pilihan tersimpan di browser (localStorage
  `manas-aegis-theme`); default gelap.
- **Tipografi:** UI sans-serif sistem (Inter/Segoe UI); monospace
  hanya untuk nilai data (timestamp, ID, evidence).
- **Ikon:** SVG inline gaya Lucide (grid 24px, stroke 2,
  currentColor). Tidak ada emoji sebagai ikon.
- **Layout:** sidebar kiri tetap (Activity / Threat intel /
  Findings), konten max-width 1120px; di layar sempit (<760px)
  sidebar runtuh jadi bar atas.

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
- **Angka di HUD = event lokal yang tersimpan** (riwayat tanpa batas:
  file live 500 event terbaru + arsip semua event lama — lihat "Data
  yang disimpan"), bukan jumlah serangan di internet dan bukan
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
| `manas_telemetry.json` | Event aktivitas yang ditangani aturan: waktu, nama tool, ID aturan, tindakan (diblokir/diubah), dan potongan argumen/bukti | **Tanpa batas.** File live menyimpan 500 event terbaru (agar HUD cepat dimuat); event yang lebih lama pindah ke arsip dan tidak pernah dihapus oleh plugin — kecuali Anda menekan "Hapus riwayat" |
| `manas_telemetry_archive.jsonl` | Arsip semua event lama (satu event per baris, format JSON Lines). Bisa dicari lewat kotak pencarian di HUD (tab Aktivitas) atau endpoint `/api/search?q=...` | **Tanpa batas.** File ini hanya tumbuh saat event baru keluar dari jendela live. Pencarian arsip membaca paling banyak 20 MB terakhir agar HUD tidak melambat |
| `stix21_taxii_feed.json` | Bundel STIX 2.1 lokal dari event yang sama (30 bundel terakhir) — ini file lokal, **bukan** feed TAXII live dan tidak ada transport TAXII | 30 bundel terakhir |
| `scan_state.json` | Hasil pindai terakhir + daftar temuan (maksimal 50 temuan, duplikat digabung) | 50 temuan |
| `threat_intel.json` | Cache intelijen ancaman global (CISA KEV + NVD, maksimal 40 item) + status per sumber | 40 item, diperbarui bila lebih tua dari 6 jam |
| `cce_baseline.json` | Baseline hash file konfigurasi yang dipantau (untuk quick scan) | Dibuat otomatis saat pertama jalan; hapus file ini untuk membuat baseline baru |
| `~/.hermes/manas-aegis-custom-rules.json` | Aturan khusus Anda (di home, bukan di direktori plugin) | Tidak ada batas jumlah aturan; entri tidak valid ditolak |

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
  diakses dari jaringan luar. Endpoint HUD **memakai token CSRF
  per-proses di semua POST, rate limit 20 POST per IP per 60 detik
  (HTTP 429), dan token auth opt-in** (`hud_auth_token`); tetapi
  **tidak ada pemeriksaan Origin header**. Siapa pun yang bisa
  mengakses komputer Anda bisa membuka HUD dan memanggil
  endpoint-nya.
- File decoy (`honeypot_sandbox/decoy.env`,
  `honeypot_sandbox/decoy_auth.json`) berisi **data umpan palsu**
  yang sengaja mudah dikenali — bukan kredensial asli.

## Versi Hermes yang benar-benar dites

- **Hermes 0.21.5 — dites di PC.** `hermes plugins validate`
  lolos sebagian; `hermes plugins doctor` gagal pada kwarg
  `parameters` (inti hook tetap jalan). Unit + contract test di
  salinan kerja rev1 ini: **61/61 lulus** (`python3 -m unittest
  discover`, diverifikasi 2026-11-09) — 6 tes lama + 6 tes R1 +
  11 tes R2 + 5 tes R2.5 + 5 tes R2.5.1 + 5 tes R2.5.2 + 16 tes
  R3 + 7 tes kontrak. E2E HTTP nyata: **26/26 lulus**
  (`/tmp/e2e-r3.py` — CSRF 403/200, arena 10/10, rate limit 429,
  token auth 401/302). Cakupan: **79%** (`coverage run`,
  gate CI 70%). Bypass yang diketahui di v2.5.2 (git chaining,
  `python -c`, SSRF fail-open) **sudah diperbaiki di v2.6.0**
  (parser shell, SSRF fail-closed); packaging (wheel/sdist
  membawa plugin.yaml + aset desktop) sudah diperbaiki di v2.6.2
  (MANIFEST.in + data-files; diverifikasi dari isi arsip).
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
  SSRF di plugin ini fail-closed sejak v2.6.0-alpha: DNS yang
  gagal diblokir, bukan dianggap aman.
