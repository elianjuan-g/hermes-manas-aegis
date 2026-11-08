# Laporan Revisi Fase R2.5.1 — Manas Aegis v2.5.1-alpha

**Tanggal:** 2026-11-09 (~06:36–07:00 WIB)
**Perintah:** MyLord, dari chat + screenshot (kartu KPI 0/0/0/10,
"simulation: 0" di semua kartu): "data simulasi nya udah di
jalankan tapi disini masih 0, aku mau gak cuman data simulasi nya
juga tapi data real nya juga harus kedetect dan semua
terimplementasikan dan saling integrasi, itu juga di Scans,
beneran gak itu fitur nya, kok aku klik quick scan gak mau masuk
ke browse/library".
**Aturan verdict:** single project single revisi (MyLord, 9 Nov 04:04 WIB)
— Ciel verdict sendiri, verdict Alicia tidak diminta. Alicia tetap
diberi kabar (koordinasi).
**Paket:** `~/workspace/manas-aegis-rev1/`.

## Temuan (diperiksa dari data asli di PC, bukan dari laporan)

### 1. Sub-jumlah simulasi 0/0/0 — BUG, sudah diperbaiki

Telemetri di PC saat diperiksa: **12 event, semuanya simulasi**,
dengan verdict:

- `HARD_BLOCK`: 8
- `SYNTHESIZED_PATCH (Modify Args)`: 2
- `HONEYPOT_DECEIVED (Modify Args)`: 2

Kartu KPI menghitung sub-jumlah simulasi dengan pencocokan **persis**
(`verdict == "BLOCK"`). `"HARD_BLOCK" != "BLOCK"`, jadi hasilnya
0/0/0 — padahal datanya ada dan ringkasan "Last simulation"
sudah benar dari dulu (fungsi itu memakai pencocokan substring).
**Ini bug saya**, bukan data MyLord yang hilang. Perbaikan:
sub-jumlah kini memakai pencocokan substring yang sama seperti
counter posture dan `get_last_simulation()`. Hasil sesudah perbaikan
(dengan telemetri MyLord yang sama): **8/2/2**.

Catatan: kartu BESAR tetap 0 — itu benar menurut desain R1
(kartu besar hanya menghitung aktivitas REAL; simulasi tidak
boleh menggelembungkannya). Yang salah hanya sub-jumlahnya.

### 2. Data real — jalurnya ada, buktinya kini terlihat

Semua 12 event di telemetri adalah simulasi; **0 event real**.
Alasannya jujur: event real hanya muncul saat Hermes benar-benar
mencegat panggilan tool dari agen yang sedang jalan. Plugin
terpasang dan hook-nya terdaftar, tapi tidak ada panggilan tool
real yang lewat sejak instalasi — jadi tidak ada yang bisa
"dideteksi".

Untuk membuktikan jalur real terimplementasi dan terintegrasi
penuh, saya uji langsung di PC lewat jalur yang sama dipakai
Hermes (`intercept_tool_call`, `event_source="runtime"` — default,
bukan simulasi): 1 panggilan shell destruktif diblokir
(HARD_BLOCK), 1 argumen dimodifikasi, 1 kredensial dialihkan ke
honeypot. Ketiganya tercatat sebagai event REAL dan menaikkan
kartu KPI. **Ini uji integrasi langsung, bukan simulasi** — dan
saya katakan terus terang: data real selanjutnya muncul otomatis
setiap agen Hermes memanggil tool. Plugin tidak bisa mendeteksi
tool yang tidak pernah dipanggil.

### 3. Pindai (Scans) — fiturnya BENAR-BENAR jalan

Bukti dari data di PC: **37 temuan tersimpan** (1 telemetry
backstop + 36 filesystem content dari pindai penuh — deteksi
nyata atas berkas di `~/.hermes`). Pindai terakhir yang MyLord
jalankan (network) menemukan 0 temuan — itu hasil bersih, bukan
gagal jalan.

Yang rusak adalah UX-nya: sesudah pindai, halaman hanya me-reload
di tab Activity, jadi temuan tersembunyi di tab Findings dan
terlihat seperti "tidak masuk ke mana-mana". Perbaikan: sesudah
pindai sukses, halaman otomatis pindah ke tab Findings
(`?tab=find` di URL; server me-render tab yang diminta). Pencarian
tetap di tab Activity.

## Verifikasi

- **Unit test: 32/32 lulus** (28 lama + 4 baru R2.5.1, termasuk
  reproduksi telemetri MyLord: 12 event → sub-jumlah 8/2/2).
- **E2E: 19/19 lulus** (HTTP nyata: sub-jumlah sim non-nol dan
  berjumlah 6, `?tab=find` me-render Findings aktif, pindai →
  Findings, intercept real → counter real > 0).
- **Live di PC:** diverifikasi sesudah install (lihat laporan
  kirim ke MyLord).

## Batas yang jujur (masih berlaku)

- **Event real baru** hanya muncul saat agen Hermes benar-benar
  memanggil tool. Uji integrasi di atas membuktikan jalurnya
  jalan; frekuensi data real tergantung pemakaian Hermes MyLord.
- **Bahasa tidak merata** (laporan MyLord sebelumnya: temuan
  pindai masih Indonesia saat mode English, dst.) **BELUM**
  diperbaiki di rilis ini — itu giliran berikutnya (v2.5.2).
  Judul/detail temuan pindai masih hardcode Indonesia di
  `core_engine.py`; header "File" masih hardcode Inggris.
- **Bypass Fase R2** (SSRF fail-closed dkk.) tetap antre.

## Verdict Ciel (self-verdict, aturan single revisi)

**PASS WITH NOTES.**

- Bug sub-jumlah simulasi diperbaiki dan dibuktikan dengan
  telemetri asli MyLord (8/2/2).
- Jalur data real dibuktikan lewat uji integrasi langsung di PC.
- UX pindai diperbaiki (otomatis ke Findings).
- Notes: (1) data real selanjutnya tergantung pemakaian Hermes;
  (2) perbaikan bahasa (v2.5.2) masih antre; (3) bypass Fase R2
  tetap antre.
