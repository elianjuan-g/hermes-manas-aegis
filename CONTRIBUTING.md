# Berkontribusi — Manas Aegis (CONTRIBUTING.md)

Terima kasih sudah mau membantu. Plugin ini masih ALPHA, jadi
aturan di bawah ini penting agar klaim kami tetap jujur.

## Cara kontribusi

1. Baca README.md dulu — terutama tabel guard dan bagian
   "TIDAK mencegah APA".
2. Buat perubahan kecil dan fokus pada satu hal.
3. Sertakan tes bila Anda mengubah perilaku kode.
4. Perbarui README.md / CHANGELOG.md bila perubahan Anda mengubah
   perilaku, batas, atau klaim apa pun.
5. Kirim perubahan sebagai pull request dengan penjelasan:
   apa yang diubah, mengapa, dan bukti apa (tes / hasil run).

## Aturan klaim (wajib)

- **Setiap klaim harus menunjuk kode + tes.** Jangan menulis
  klaim keamanan ("mencegah X", "memblokir Y", "N standar
  ditegakkan") tanpa menyebutkan file + baris kode yang
  melakukannya dan tes yang membuktikannya.
- **Dilarang mengarang angka atau versi yang belum dites.**
  Jangan menulis jumlah standar, jumlah aturan aktif, versi
  Hermes yang didukung, atau hasil tes tanpa bukti run yang
  bisa diulang.
- **Bedakan status dengan jujur:** `implemented` (enforcement
  nyata di jalur hook, terbukti tes), `experimental` (ada kode
  tapi berbasis pola/parsial, ada bypass yang diketahui),
  `planned` (hanya terdefinisi, tanpa enforcement),
  `not supported` (tidak ada sama sekali). Jangan menaikkan
  status tanpa bukti.
- **Jangan memakai bahasa yang melebih-lebihkan:** hindari
  "absolute defense", "proteksi menyeluruh", "patch sistem",
  "feed live", atau "CVE" untuk ID internal (`HERMES-SEC-...`
  bukan CVE publik).

## Cara menjalankan tes

Jalankan tes dari direktori root repo:

```sh
python3 -m unittest discover -v
```

Saat ini ada **83 unit test** (61 dasar + 22 baru v2.6.2: 21 unit +
1 kontrak) dan semuanya **lulus (83/83)**, diverifikasi 2026-11-09. Jangan menyembunyikan
kegagalan tes: bila run Anda tidak hijau, tulis hasil sebenarnya
di PR. Bila Anda menambah guard atau mengubah pola, tambahkan tes
untuk: input normal, bypass/edge case, dan kondisi gagal (mis.
DNS gagal, file state rusak).

## Yang tidak kami terima

- Perubahan yang memperkenalkan klaim tanpa bukti (lihat "Aturan
  klaim" di atas).
- Kode yang menguji celah di sistem orang lain.
- Dependensi berbayar atau layanan yang mengharuskan akun/kunci
  baru tanpa diskusi dulu.
- Perubahan besar tanpa issue/PR diskusi terlebih dahulu.

## Melaporkan celah keamanan

Jangan lewat pull request. Lihat SECURITY.md — laporkan via
GitHub Issues dengan label `security`.
