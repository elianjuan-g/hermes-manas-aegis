# Blueprint R3 — Manas Aegis v2.6.0-alpha ("Guard Terbaik")

**Tanggal:** 2026-11-09
**Pemicu:** perintah MyLord — skor jadi 10 di semua dimensi, fitur + guard unik, valid, berguna; "guard terbaik diantara mereka semua".
**Metode:** Creation Synthesis — TRIZ + SCAMPER + Six Hats + first-principles + diverge→converge.
**Status:** RENCANA — menunggu GAS build MyLord.

## 1. Kontradiksi inti (TRIZ)

**"Jika ketegasan guard naik (% panggilan berbahaya diblokir), maka pekerjaan sah rusak (% panggilan sah yang lolos tanpa interupsi turun)."**
Solusi dari prinsip inventif:
- **Segmentasi** — enforcement berjenjang per aturan/per tool/per sesi (blokir / ubah / tanya / audit), bukan satu saklar global.
- **Asimetri** — perlakuan beda per segmen: terminal = parser shell asli; read_file = honeypot; panggilan model = taint tracking.
- **Blessing in disguise** — kejujuran soal batas (tabel bypass per aturan) justru jadi fitur kepercayaan.
- **Preliminary action** — hitung state SEBELUM panggilan (taint, baseline) agar keputusan saat panggilan instan.
- **The other way round** — balik dari blocklist ke allowlist untuk tool paling berbahaya: yang dikenal-aman lolos otomatis, yang tidak dikenal diperiksa.
- **Self-service** — aturan custom pengguna + auto-tune dari keputusan pengguna.

## 2. First-principles (yang PASTI benar)

- Guard hanya bisa menegakkan apa yang ia LIHAT (tool call lewat hook).
- Guard hanya bisa MEMBLOKIR apa yang ia PUTUSKAN sebelum eksekusi.
- Pencocokan pola itu dangkal; state (taint) itu dalam.
- Pengguna adalah otoritas akhir; tugas guard adalah membuat keputusan pengguna mudah, bukan menggantikannya.
- Guard yang sering salah alarm akan dimatikan; guard yang diam dipercaya sampai gagal.
- Maka bangun dari nol: (a) taint tracking stateful, (b) enforcement berjenjang, (c) bukti (simulasi) yang bisa dijalankan pengguna, (d) satu angka postur.

## 3. Diverge → converge (14 ide, skor F/I/C/R 1–5, total /20)

| # | Ide | F | I | C | R | Total | Keputusan |
|---|---|---|---|---|---|---|---|
| 1 | Taint tracking (baca sensitif → egress diblokir, per sesi) | 4 | 5 | 3 | 2 | 14 | BANGUN |
| 2 | Shell parser asli (ganti regex; pecah `;` `&&` `\|\|` `\|`) | 4 | 5 | 3 | 2 | 14 | BANGUN |
| 3 | SSRF fail-closed + allowlist DNS | 5 | 4 | 4 | 3 | 16 | BANGUN |
| 4 | Symlink guard (canonicalization realpath) — aturan planned jadi nyata | 5 | 3 | 4 | 4 | 16 | BANGUN |
| 5 | Call-ID race guard (deteksi duplikat/replay) — aturan planned jadi nyata | 4 | 3 | 4 | 3 | 14 | BANGUN |
| 6 | HUD auth + CSRF + rate-limit | 4 | 4 | 3 | 3 | 14 | BANGUN |
| 7 | CI + contract test + coverage gate | 5 | 3 | 5 | 4 | 17 | BANGUN |
| 8 | Guard Arena (skenario red-team bernama + laporan lulus/gagal) | 4 | 5 | 3 | 3 | 15 | BANGUN |
| 9 | Posture Score (satu angka 0–100 di HUD) | 5 | 4 | 5 | 4 | 18 | BANGUN |
| 10 | Time-travel audit (replay sesi lama lewat aturan SEKARANG) | 4 | 4 | 4 | 3 | 15 | BANGUN |
| 11 | Auto-tune (belajar dari allow/deny pengguna) | 2 | 4 | 2 | 2 | 10 | TUNDA — bisa diakali, butuh desain trust terpisah |
| 12 | Skill guard (verifikasi skill sebelum load) | 3 | 3 | 3 | 3 | 12 | TUNDA — antre R3.1 |
| 13 | Package guard (lookup OSV.dev) | 3 | 3 | 2 | 3 | 11 | TUNDA — butuh network, antre R3.1 |
| 14 | Guard Duel (model kedua menyerang guard sendiri) | 2 | 4 | 2 | 2 | 10 | TUNDA — butuh model kedua, biaya |

**Yang ditolak dan kenapa (satu kalimat):** Auto-tune ditolak karena keputusan pengguna bisa diakali penyerang lewat prompt injection; Skill/Package guard ditunda karena butuh desain trust + network terpisah; Guard Duel ditunda karena butuh model kedua dan biaya jalan terus.

## 4. Pemetaan ke skor 10/10

| Dimensi (skor lama) | Fitur yang menutup | Target |
|---|---|---|
| Enforcement 5 | Taint tracking, shell parser, SSRF fail-closed, symlink guard, callid-race guard | 10 |
| Cakupan 7 | 2 aturan planned jadi nyata (10/10 enforced); taint tracking | 10 |
| Observabilitas 9 | Posture Score, Guard Arena, Time-travel audit | 10 |
| Kejujuran 9 | Sudah 9; Guard Arena + Time-travel audit membuktikan klaim (bukan sekadar menulis) | 10 |
| Tes 7 | CI + contract test + coverage gate | 10 |
| Dokumen/UX 8 | Posture Score + Arena (UX baru); README diperbarui | 10 |
| Kematangan 4 | CI + PR merge (di luar kendali Ciel — jujur dicatat) + pengguna nyata (di luar kendali) | 7–8 (jujur: 10 butuh merge + pengguna) |
| Keamanan plugin 6 | HUD auth + CSRF + rate-limit | 10 |
| Ekstensibilitas 8 | Arena + Posture Score memakai mesin aturan yang sama | 10 |
| Keunikan 7 | Guard Arena, Posture Score, Time-travel audit — tidak ada di kompetitor | 10 |

**Catatan jujur:** dimensi Kematangan tidak bisa 10 dari kode saja — butuh PR #151504 di-merge Nous dan pengguna nyata pertama. Itu di luar kendali Ciel; yang bisa Ciel lakukan adalah membuat pluginnya layak merge (CI hijau, contract test, docs lengkap).

## 5. Yang membuat kita UNIK vs llm-antidote & blackbox (setelah R3)

| Fitur | Manas Aegis R3 | llm-antidote | blackbox |
|---|---|---|---|
| Taint tracking | ✅ (baru) | ✅ | ❌ |
| Shell parser (bukan regex) | ✅ (baru) | ✅ (capability class) | ❌ (pola) |
| SSRF fail-closed | ✅ (baru) | — | — |
| Symlink + callid-race enforcement nyata | ✅ (baru) | — | — |
| HUD + 15 bahasa + tema | ✅ | ❌ | ✅ (dashboard, 1 bahasa) |
| Intel global CISA/NVD | ✅ | ❌ | ✅ (DKG graph, berat) |
| Guard Arena (red-team bernama) | ✅ (baru) | ✅ (behavioral eval, tanpa UI) | ❌ |
| Posture Score 0–100 | ✅ (baru) | ❌ | ❌ |
| Time-travel audit | ✅ (baru) | ❌ | ❌ |
| Aturan custom pengguna + self-test | ✅ | ❌ (fleet policy, enterprise) | ❌ |
| Simulasi barrage | ✅ | ❌ | ❌ |
| CI + contract test | ✅ (baru) | ✅ | ✅ |

## 6. Rencana eksekusi (setelah GAS)

1. Core enforcement: taint tracking + shell parser + SSRF fail-closed + symlink + callid-race.
2. HUD: auth/CSRF/rate-limit + Posture Score + Guard Arena + Time-travel audit.
3. Kualitas: CI (GitHub Actions) + contract test + coverage gate + README/CHANGELOG.
4. Verifikasi: unit + e2e (nilai, bukan label) + live di PC.
5. Self-verdict → push repo → PR #151504 update → kabari Alicia → install PC → verifikasi live → laporan MyLord.
