# Laporan Revisi v2.6.1-alpha — Kartu Skor Postur Minimalis, Tab Activity Saja

**Pemicu:** keluhan MyLord via screenshot HUD (9 Nov 2026 ~15:07 WIB):
"ini kenapa muncul disetiap tab? ini terlalu makan ruang dibikin boxscard
minimalis aja" — kartu Posture Score (65, grade C) tampil di semua tab.

## Akar masalah (terkonfirmasi dari kode)

Kartu dirender di `build_analytical_hud_html` pada alur `<main>` bersama,
SEBELUM panel-panel tab (`tab-act`, `tab-intel`, `tab-find`, `tab-arena`).
Pengalih tab (`showTab`) hanya menambah/menghapus class `active` pada
`.panel` — kartu yang bukan `.panel` tidak pernah disembunyikan, jadi
tampil di semua tab. Bukan bug CSS; murni penempatan di luar panel.

## Perbaikan

1. **Pindah ke dalam panel Activity.** `{posture_html}` kini dirender
   tepat setelah `<div class="panel" id="tab-act">` dibuka, sebelum
   form pencarian. Satu-satunya penempatan (assert: tepat 1 kemunculan).
2. **Box minimalis (`.posture-mini`).** Menggantikan kartu besar
   (`.posture-big`, angka 44px + 5 baris penuh):
   - Satu baris flex: judul kecil + skor 26px + grade 14px di kiri.
   - Lima komponen sebagai chip kecil di kanan: label + bar 70px
     (dulu 140px) + nilai tebal, membungkus rapi di layar sempit.
   - Padding 12px 16px (dulu 16px 18px + margin 14px).

## Yang TIDAK berubah

- Kartu "Yang dipantau" dan "Pemindaian" tetap di alur bersama (sudah
  begitu sejak v2.4.0; bukan bagian dari keluhan ini). Bila MyLord mau,
  keduanya bisa dipindah ke Activity juga di revisi berikut.
- Nilai skor/komponen tidak berubah — hanya penempatan + tampilan.
  Skor live 65/C di PC MyLord tetap 65/C setelah install.

## Verifikasi (Ciel sendiri)

- Render HUD (EN + ID): tepat 1 `.posture-mini`, di dalam `tab-act`
  (posisi: setelah `id="tab-act"`, sebelum `id="tab-intel"`),
  `posture-big` hilang, font 44px hilang, nilai render benar
  (fresh core 70/C, 25/25, 25/25, 20/20, 0/15, 0/15).
- Unit + kontrak: **61/61 PASS**.
- E2E R3 (regresi, HTTP nyata): **26/26 PASS**.
- E2E posture-mini (HTTP nyata): **17/17 PASS** — termasuk
  `GET /?tab=intel` tetap 1 mini-box, CSRF 403 tanpa token / 200
  dengan token, arena 10/10, label ID "Skor postur".
- Dua "FAIL" awal adalah salah ekspektasi skrip cek, bukan kode:
  skor fresh core 70 (bukan 65 live) dan respons arena bersarang
  di `arena.passed` — keduanya diperbaiki di skrip, lalu hijau.

## Self-verdict: PASS WITH NOTES

- Notes: (1) verdict visual tetap milik MyLord — kartu mini + hanya
  di Activity perlu dilihatnya di HP/Desktop; (2) "Yang dipantau" +
  "Pemindaian" masih tampil di semua tab (sengaja, di luar keluhan);
  (3) file workflow CI (`.github/workflows/ci.yml`) masih hanya di
  working tree — belum ter-push (butuh scope `workflow`, terbuka
  sejak R3).
- Repo: commit v2.6.1-alpha; PR katalog #151504 diperbarui ke v2.6.1.
- Install PC: backup v260, gateway restart, HUD live v2.6.1-alpha.

## Perluasan (keluhan kedua MyLord, screenshot 15:12 WIB)

> "setiap ganti bar ga ada yang berubah, yang berubah yang bawah
> gak menarik sama sekali terlalu kaku"

Keluhan ini AKARnya sama tapi LEBIH LUAS dari kartu Skor Postur: KPI,
garis history, kartu "Yang dipantau", dan kartu "Pindai" juga masih di
alur `<main>` bersama — jadi ganti tab hanya menukar panel bawah,
80% layar atas tetap identik. Terasa mati/kaku.

### Perbaikan tambahan (masih v2.6.1, sebelum install)

- **Semua konten Activity pindah ke dalam `tab-act`**: KPI (4 kartu),
  posture-mini, 3 garis history, kartu scope, kartu scan. Alur bersama
  di atas panel kini HANYA header (judul + kontrol bahasa/tema/suara/
  simulasi) + garis status. Tiap tab kini menampilkan konten yang
  sepenuhnya berbeda.
- **Transisi fade 180ms** saat panel aktif berganti
  (`.panel.active{animation:panelFade .18s ease}` — naik 4px + fade),
  sesuai standar animasi 150–250ms. Perpindahan tab tidak lagi
  "menjentik" kaku.

### Verifikasi tambahan

- Render (EN + ID): KPI, posture-mini, hist, scope, scan — semuanya
  tepat 1x dan semuanya di antara `id="tab-act"` dan `id="tab-intel"`;
  alur bersama di atas tab-act bersih dari blok Activity; CSS
  `panelFade` hadir; nilai KPI fresh core benar (0/0/0/10).
- Unit + kontrak 61/61, e2E R3 26/26, e2E posture-mini 17/17 —
  semuanya hijau kembali setelah perluasan.
