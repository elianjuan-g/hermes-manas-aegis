# Keamanan — Cara Melaporkan Celah (SECURITY.md)

Manas Aegis masih **ALPHA / prototipe** (v2.6.0-alpha). Laporan celah
sangat membantu — tapi mohon laporkan dengan cara yang aman.

## Cara melaporkan

Laporkan lewat **GitHub Issues repo ini dengan label `security`**.

Sertakan:

1. Apa yang terjadi (langkah untuk mengulang, sesingkat mungkin).
2. Versi plugin dan versi Hermes yang Anda pakai.
3. Apa yang Anda harapkan terjadi vs. apa yang benar-benar terjadi.
4. Bila ada, potongan argumen/log yang relevan — **setelah
   menghapus secret, token, atau data pribadi apa pun**.

## Yang TIDAK boleh dilakukan

- **Jangan menguji celah di sistem atau data orang lain.** Uji
  hanya di lingkungan Anda sendiri.
- **Jangan mempublikasikan detail celah** (di media sosial, blog,
  atau issue publik tanpa label security) sebelum ada perbaikan.
- **Jangan memasukkan secret/token asli** ke dalam laporan.
- **Jangan memakai celah yang Anda temukan** untuk mengakses,
  mengubah, atau merusak apa pun.

## Kebijakan

- **Tidak ada bounty.** Tidak ada hadiah uang untuk laporan celah.
- Laporan yang masuk akan dibaca maintainer; perbaikan dilakukan
  sesuai prioritas (celah yang paling berbahaya didahulukan).
- Celah yang sudah diketahui dan dicatat di CHANGELOG (bagian
  "Diketahui, masuk R2") tidak perlu dilaporkan ulang — kecuali
  Anda menemukan varian atau dampak baru.

## Catatan jujur soal status keamanan plugin ini

Plugin ini adalah guardrail berbasis pola, bukan pertahanan
keamanan mandiri. Celah yang sudah diketahui (lihat README.md
tabel guard dan CHANGELOG.md) antara lain: SSRF fail-open saat
DNS gagal, bypass perintah git berantai, `python -c` yang lolos
dari pola, tidak ada canonicalization path/symlink check, dan
HUD tanpa autentikasi/CSRF/rate limit. Jangan memakai plugin ini
untuk melindungi secret atau operasi produksi.
