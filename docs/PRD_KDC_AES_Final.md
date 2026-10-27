# PRD Final: KDC dan Komunikasi Dua Arah dengan AES Manual

**Status:** FINAL (disetujui, tidak diubah lagi kecuali ada arahan dosen). Ikuti dokumen ini apa adanya dan jangan menambah fitur di luar isinya.

**Tujuan dokumen:** spesifikasi ringkas untuk coding agent. Fokus utama adalah **belajar dan mengimplementasikan AES secara manual**. Bagian jaringan dan komunikasi dibuat sesederhana mungkin dan **tidak menangani semua kasus error**. Aturan penulisan kode ada di **Bagian 11** dan wajib dipatuhi.

**Tenggat pengumpulan:** Selasa, 27 Oktober 2026, 23.59 WIB (link repo GitHub lewat Google Form).

---

## 1. Aturan Wajib (dari soal)

1. Tiga entitas (KDC, Alice, Bob) berjalan di **tiga perangkat dengan IP berbeda**. IP dan port dibaca dari `config.json`.
2. Mengikuti diagram **Key Distribution Scenario** lima langkah. Setelah langkah 5, Alice dan Bob berkomunikasi dua arah memakai AES.
3. **AES dan KDC harus manual.** Dilarang memakai library kripto (`cryptography`, `pycryptodome`, `pyaes`, `Crypto`, `hashlib`, dan sejenisnya).
4. Key dan plaintext berformat **ASCII**; ciphertext ditampilkan dalam **Hex**.
5. Key **tidak boleh di-hardcode** dan bisa diubah tanpa menjalankan ulang program (lewat menu).
6. Program interaktif (menu) agar mudah diuji saat demo.
7. Transmisi harus bisa diamati di Wireshark.
8. **Comment minimal.** Jangan menulis comment yang menarasikan langkah atau menyerupai catatan. Pakai nama fungsi dan variabel yang jelas. Kode harus bisa dijelaskan lisan tanpa catatan. Detail di Bagian 11.
9. Hanya Python standar: `socket`, `threading`, `json`, `secrets`, `argparse`, `unittest`.

## 2. Lima Langkah Protokol

```text
1. Alice -> KDC   : ID_A || ID_B || N1
2. KDC   -> Alice : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
3. Alice -> Bob   : E(Kb, [Ks || ID_A])
4. Bob   -> Alice : E(Ks, N2)
5. Alice -> Bob   : E(Ks, f(N2))
```

- `Ka`: key Alice-KDC. `Kb`: key Bob-KDC. Keduanya tepat 16 karakter ASCII, diketik lewat prompt (bukan di kode).
- `Ks`: session key, dibuat KDC, 16 karakter alfanumerik acak (`secrets`).
- `N1`, `N2`: bilangan acak (integer 1 sampai 2^32).
- `f(N2) = N2 - 1`.
- `E(K, M)` = AES-128-CBC manual + padding PKCS#7, IV acak 16 byte; hasil disimpan sebagai **satu string Hex = IV + ciphertext**.
- Tiket Bob = `E(Kb, [Ks || ID_A])`. Alice meneruskannya tanpa membukanya.

**Format plaintext sebelum enkripsi** (teks ASCII dengan pemisah `|`; aman karena ID dan `Ks` hanya alfanumerik):

| Objek | Isi |
|---|---|
| Respons untuk Alice | `Ks|ID_A|ID_B|N1` |
| Tiket Bob | `Ks|ID_A` |
| Challenge | `N2` (sebagai teks angka) |
| Jawaban | `N2-1` (sebagai teks angka) |

ID adalah huruf/angka saja (default `alice`, `bob`).

## 3. Struktur Proyek

```text
kdc-aes/
├── aes.py        # AES-128, CBC, PKCS#7
├── common.py     # kirim/terima pesan, seal/unseal, validasi input, menu, chat
├── kdc.py
├── alice.py
├── bob.py
├── test_aes.py
├── .gitignore    # berisi __pycache__/
└── README.md
```

## 4. Bagian A: AES Manual (`aes.py`) — fokus utama

### 4.1 Representasi dan komponen
- Blok dan state = list 16 byte. Urutan sama dengan urutan input (column-major): byte ke-`i` berada di kolom `i // 4`, baris `i % 4`.
- AES-128: key 16 byte, 11 round key, 10 putaran.

| Fungsi | Tugas |
|---|---|
| `xtime(b)`, `gmul(a, b)` | Perkalian di GF(2^8) dengan polinomial 0x11B |
| pembuatan `SBOX` dan `INV_SBOX` | Untuk tiap byte `x`: cari invers perkalian di GF(2^8) (0 menjadi 0), lalu `s = inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63`. Inverse S-box dibuat dengan membalik tabel. (Menulis tabel S-box langsung juga boleh jika bisa dijelaskan.) |
| `expand_key(key)` | Hasilkan 11 round key. Tiap kata ke-`i` kelipatan 4: `w[i] = w[i-4] ^ SubWord(RotWord(w[i-1])) ^ Rcon`; selain itu `w[i] = w[i-4] ^ w[i-1]`. `Rcon` = `01 02 04 08 10 20 40 80 1b 36` |
| `sub_bytes`, `inv_sub_bytes` | Ganti tiap byte dengan nilai S-box / inverse S-box |
| `shift_rows`, `inv_shift_rows` | Baris `r` digeser ke kiri sebanyak `r` (invers: ke kanan). Dengan indeks column-major: `new[c*4 + r] = old[((c + r) % 4) * 4 + r]` |
| `mix_columns`, `inv_mix_columns` | Per kolom, kalikan dengan matriks `[2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]` (invers: `[14 11 13 9; 9 14 11 13; 13 9 14 11; 11 13 9 14]`) memakai `gmul` |
| `add_round_key` | XOR state dengan round key |
| `encrypt_block(key, block)` | AddRoundKey(0); putaran 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey; putaran 10: SubBytes, ShiftRows, AddRoundKey |
| `decrypt_block(key, block)` | AddRoundKey(10); putaran 9 sampai 1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns; akhir: InvShiftRows, InvSubBytes, AddRoundKey(0) |

### 4.2 Mode CBC dan padding
- `pad(data)`: PKCS#7 (selalu menambah 1-16 byte; panjang kelipatan 16 menambah satu blok penuh).
- `unpad(data)`: periksa byte terakhir (1-16) dan semua byte padding sama; jika tidak, raise `ValueError`.
- `encrypt_cbc(key, plaintext_bytes)`: buat IV 16 byte acak (`secrets.token_bytes(16)`), pad, XOR tiap blok dengan blok ciphertext sebelumnya (IV untuk blok pertama), enkripsi. Kembalikan `IV + ciphertext` (bytes).
- `decrypt_cbc(key, data_bytes)`: pisahkan 16 byte pertama sebagai IV, dekripsi per blok, XOR dengan blok sebelumnya, `unpad`. Panjang data harus kelipatan 16 dan minimal 32 byte, selain itu `ValueError`.

### 4.3 Test (`test_aes.py`, pakai `unittest`)

| Test | Isi | Hasil |
|---|---|---|
| Vektor FIPS-197 B | key `2b7e1516 28aed2a6 abf71588 09cf4f3c`, plaintext `3243f6a8 885a308d 313198a2 e0370734` | ciphertext `3925841d 02dc09fb dc118597 196a0b32`; dekripsi kembali ke plaintext |
| Vektor FIPS-197 C.1 | key `000102...0f`, plaintext `00112233 44556677 8899aabb ccddeeff` | ciphertext `69c4e0d8 6a7b0430 d8cdb780 70b4c55a`; dekripsi kembali |
| Key expansion | key vektor B | round key terakhir `d014f9a8 c9ee2589 e13f0cc8 b6630ca6` |
| S-box | `SBOX[0x00]=0x63`, `SBOX[0x53]=0xED`; `INV_SBOX[SBOX[x]] == x` untuk semua `x` | sesuai |
| Operasi balikan | `inv_shift_rows(shift_rows(s)) == s`, `inv_mix_columns(mix_columns(s)) == s`, `inv_sub_bytes(sub_bytes(s)) == s` | sesuai |
| CBC round-trip | plaintext panjang 0 sampai 40 byte, key acak | plaintext kembali |
| CBC acak | plaintext sama dienkripsi dua kali | hasil berbeda (IV baru) |
| Padding | plaintext kelipatan 16 menghasilkan satu blok padding penuh; data dengan padding rusak | `unpad` raise `ValueError` |
| Larangan library | pindai semua `.py` | tidak ada impor library kripto |

Selesaikan dan lulus semua test AES **sebelum** mengerjakan jaringan.

## 5. Bagian B: Jaringan (Sederhana)

### 5.1 Transport
- TCP. Satu pesan = satu baris JSON diakhiri `\n` (`common.send(sock, dict)` dan `common.recv(sock) -> dict`, memakai `sock.makefile` atau buffer sederhana dengan `readline`).
- Field biner adalah string Hex (huruf kecil).
- Port default: KDC 5000, Bob 5001. Server bind ke `0.0.0.0`.
- Tidak ada framing panjang, timeout, atau retry.

### 5.2 Pesan

| Langkah | Pesan |
|---|---|
| 1 | `{"type":"REQ","a":"alice","b":"bob","n1":123456}` |
| 2 | `{"type":"RESP","for_a":"<hex>","ticket":"<hex>"}` |
| 3 | `{"type":"TICKET","ticket":"<hex>"}` |
| 4 | `{"type":"CHALLENGE","data":"<hex>"}` |
| 5 | `{"type":"ANSWER","data":"<hex>"}` |
| hasil | `{"type":"AUTH","ok":true}` atau `{"type":"AUTH","ok":false}` (dikirim Bob ke Alice) |
| chat | `{"type":"MSG","data":"<hex>"}` |

### 5.3 `common.py`
- `send(sock, obj)`, `recv(sock)`.
- `seal(key, text) -> hex string` (ASCII text → `encrypt_cbc` → hex) dan `unseal(key, hex) -> text` (hex → `decrypt_cbc` → teks ASCII; error jadi `ValueError`).
- `ask_key(prompt) -> bytes/str`: ulangi sampai input tepat 16 karakter ASCII printable.
- `valid_text(s)`: tidak kosong dan semua karakter ASCII printable (32-126).
- `run_menu(title, options)`: tampilkan menu, baca pilihan, panggil fungsi yang sesuai, ulangi sampai pilihan keluar. Dipakai bersama oleh KDC, Alice, dan Bob agar tidak ada kode menu yang berulang.
- `chat_session(sock, ks)`: seluruh logika chat (5.7) ditulis sekali di sini dan dipakai Alice dan Bob.

### 5.4 `kdc.py`
- Membaca host bind dan port KDC dari section `kdc` di `config.json`.
- Saat mulai: minta key `alice` dan `bob` lewat prompt; simpan dalam dictionary di memori.
- Server berjalan di thread latar; thread utama menjalankan menu:
```text
1. Ubah key Alice
2. Ubah key Bob
0. Keluar
```
- Per koneksi (satu thread per koneksi, tutup setelah selesai): terima `REQ` → jika `a` atau `b` tidak ada di dictionary, cetak pesan dan tutup koneksi → buat `Ks` baru → `for_a = seal(Ka, "Ks|a|b|n1")`, `ticket = seal(Kb, "Ks|a")` → kirim `RESP`.
- Cetak log tiap langkah (siapa meminta, `for_a` dan `ticket` dalam Hex). **Jangan cetak `Ka`, `Kb`, `Ks`.**

### 5.5 `alice.py`
- Membaca alamat KDC dan Bob dari section `kdc` dan `bob` di `config.json`.
- Argumen opsional: `--id alice` dan `--peer bob`.
- Menu:
```text
1. Ubah key Ka
2. Jalankan protokol (langkah 1-5)
3. Chat dengan Bob (setelah autentikasi)
0. Keluar
```
- Opsi 2: buat `N1` → connect ke KDC → kirim `REQ` → terima `RESP` → `unseal(Ka, for_a)` dan periksa bagian `ID_A`, `ID_B`, `N1` sesuai → simpan `Ks` → connect ke Bob → kirim `TICKET` → terima `CHALLENGE` → `unseal(Ks, data)` jadi `N2` → kirim `ANSWER = seal(Ks, str(N2-1))` → terima `AUTH`. Jika `ok`, simpan koneksi ke Bob dan cetak "autentikasi berhasil". Jika ada kegagalan (dekripsi gagal, nilai tidak cocok, koneksi gagal), cetak pesan singkat dan kembali ke menu.
- Opsi 3 (chat): lihat 5.7.

### 5.6 `bob.py`
- Membaca host bind dan port Bob dari section `bob` di `config.json`.
- Argumen opsional: `--id bob` dan `--peer alice`.
- Menu:
```text
1. Ubah key Kb
2. Tunggu Alice (langkah 3-5) lalu chat
0. Keluar
```
- Opsi 2: listen dan `accept` satu koneksi (blocking) → terima `TICKET` → `unseal(Kb, ticket)` → periksa `ID_A` sama dengan peer → simpan `Ks` → buat `N2` → kirim `CHALLENGE = seal(Ks, str(N2))` → terima `ANSWER` → `unseal(Ks, ...)` sama dengan `str(N2-1)` → kirim `AUTH ok=true` dan masuk chat; selain itu kirim `AUTH ok=false`, tutup koneksi, kembali ke menu.
- Log tiap langkah (Hex). Jangan cetak key atau `Ks`.

### 5.7 Chat dua arah (Alice dan Bob, logika sama, ditulis sekali di `common.chat_session`)
- Satu **thread penerima**: baca pesan `MSG` dari socket; `unseal(Ks, data)`; cetak `[terima] <plaintext>` beserta Hex ciphertext. Jika dekripsi gagal, cetak "pesan tidak valid" dan lanjut.
- Thread utama: loop `input()`; teks yang valid (`valid_text`) dikirim sebagai `MSG` dengan `seal(Ks, text)` dan dicetak `[kirim] <plaintext>` beserta Hex ciphertext; ketik `/exit` untuk keluar chat (tutup koneksi dan kembali ke menu).
- Jika koneksi ditutup lawan, thread penerima mencetak "lawan memutus koneksi" dan chat berakhir saat input berikutnya. Tidak perlu penanganan lebih canggih.

### 5.8 Perubahan key
- Alice (`Ka`), Bob (`Kb`), dan KDC (`Ka`, `Kb`) bisa diubah lewat menu kapan saja saat tidak sedang chat; perubahan berlaku untuk protokol berikutnya. Setelah mengubah key, ulangi protokol dari awal.
- Key yang tidak cocok antara KDC dan peserta menghasilkan kegagalan dekripsi pada langkah 2 atau 3, dan itu perilaku yang diharapkan.

## 6. Yang Sengaja Tidak Dikerjakan

Agar tetap sederhana, **jangan** menambahkan: framing panjang atau batas ukuran pesan, timeout dan retry, state machine formal, banyak klien atau sesi paralel, pencegahan replay, validasi berlapis, kode error baku, penanganan semua kasus koneksi putus, file konfigurasi, logging berstruktur, fitur tambahan di luar dokumen ini.

## 7. Pengujian Manual (tiga perangkat)

| No | Skenario | Hasil yang diharapkan |
|---|---|---|
| 1 | Jalankan KDC, Bob (opsi 2), lalu Alice (opsi 2) dengan key yang cocok | Alice dan Bob menampilkan autentikasi berhasil |
| 2 | Alice kirim pesan ke Bob lalu Bob balas, beberapa kali | Kedua sisi menampilkan plaintext benar dan ciphertext Hex |
| 3 | Pesan yang sama dikirim dua kali | Ciphertext Hex berbeda |
| 4 | Ubah `Ka` di Alice saja lalu jalankan protokol | Gagal di langkah 2 dengan pesan jelas |
| 5 | Ubah `Kb` di Bob saja lalu jalankan protokol | Gagal di langkah 3 (`AUTH ok=false`) |
| 6 | Ubah key di KDC dan peserta secara konsisten lalu ulangi protokol | Berhasil tanpa restart program |
| 7 | Wireshark di perangkat Alice | Langkah 1 terbaca (`a`, `b`, `n1`); langkah 2-5 dan `MSG` hanya Hex; `Ks` dan key tidak terlihat |

**Wireshark:** pilih interface jaringan yang dipakai (bukan loopback). Capture filter `tcp port 5000 or tcp port 5001`; display filter `tcp.port == 5000 || tcp.port == 5001`; gunakan "Follow TCP Stream". Jika perangkat tidak saling terhubung, cek firewall dan isolasi Wi-Fi (hotspot pribadi sebagai cadangan).

## 8. Urutan Pengerjaan (disarankan hari ini, 27 Okt)

| Urutan | Pekerjaan | Perkiraan |
|---|---|---|
| 1 | `aes.py` lengkap + `test_aes.py` hijau | 2-3 jam |
| 2 | `common.py` + `kdc.py`, uji dengan Alice sampai langkah 2 | 1 jam |
| 3 | `bob.py` + sisi Alice langkah 3-5 + chat | 1,5 jam |
| 4 | Uji tiga perangkat + Wireshark + tangkapan layar | 1 jam |
| 5 | README + rapikan comment + cek tidak ada key di repo | 30 menit |
| 6 | Push ke GitHub dan kumpulkan lewat Google Form (target sebelum 22.00) | 15 menit |

## 9. Kriteria Selesai

- [ ] Semua test AES lulus (test vector FIPS-197).
- [ ] Lima langkah berjalan di tiga perangkat dengan IP berbeda.
- [ ] Alice dan Bob bertukar pesan dua arah; ciphertext tampil Hex.
- [ ] Key bisa diubah lewat menu tanpa restart dan tidak ada key di kode atau repo.
- [ ] Tidak ada library kripto yang dipakai.
- [ ] Wireshark menampilkan paket yang relevan.
- [ ] README berisi cara menjalankan (KDC, Bob, Alice), contoh argumen IP, filter Wireshark, dan keterbatasan.
- [ ] Kode mematuhi aturan Bagian 11 (checklist 11.9 terpenuhi).
- [ ] Setiap anggota paham cara kerja AES (SubBytes, ShiftRows, MixColumns, AddRoundKey, key expansion), mode CBC dan IV, padding, serta alur lima langkah KDC.
- [ ] Repo hanya memuat dua akun anggota dan commit mencerminkan kontribusi masing-masing.

## 10. Keterbatasan yang Dicatat di README

CBC tanpa MAC tidak memberi integritas ciphertext; tiket tanpa timestamp sehingga rentan replay; `N1` dikirim plaintext sesuai diagram; AES manual belum diaudit dan tidak constant-time; proyek ini untuk pembelajaran, bukan produksi.

## 11. Aturan Penulisan Kode (Clean Code)

Aturan ini wajib dipatuhi agent di semua file `.py`. Tujuannya: kode rapi, mudah dibaca, dan bisa dijelaskan lisan tanpa catatan.

### 11.1 Gaya dan format
- Ikuti PEP 8: indentasi 4 spasi, panjang baris maksimal 88 karakter, dua baris kosong antar fungsi tingkat atas.
- Encoding UTF-8, akhir baris LF, file diakhiri satu baris kosong, tanpa spasi di akhir baris.
- Import satu per baris, diurutkan: library standar saja, lalu modul proyek. Dilarang `from x import *`.
- Gunakan f-string, bukan penggabungan string dengan `+` atau `%`.
- Boleh memakai formatter (`black` atau `ruff`) secara lokal; tidak wajib dan tidak dihitung sebagai dependensi proyek.

### 11.2 Penamaan
- Fungsi dan variabel `snake_case`; konstanta `UPPER_SNAKE_CASE`; kelas (jika ada) `PascalCase`.
- Nama harus menjelaskan isi: `round_key`, `ticket_hex`, `session_key`, bukan `x`, `tmp`, `data2`.
- Fungsi diawali kata kerja (`expand_key`, `send_message`, `validate_key`); fungsi yang mengembalikan boolean diawali `is_` atau `has_`.
- Nama singkat hanya untuk indeks loop (`i`, `c`, `r`) dan istilah standar AES yang sudah umum (`sbox`, `rcon`, `state`).
- Simbol privat (helper internal) diawali satu garis bawah.

### 11.3 Fungsi dan struktur
- Satu fungsi satu tugas. Panjang fungsi maksimal sekitar 25 baris; fungsi AES (`sub_bytes`, `shift_rows`, dan seterusnya) idealnya di bawah 15 baris.
- Parameter maksimal 4. Kedalaman blok (`if`/`for` bersarang) maksimal 3; gunakan *early return* untuk mengurangi nesting.
- Tidak ada konstanta ajaib. Beri nama: `BLOCK_SIZE = 16`, `ROUNDS = 10`, `KEY_LENGTH = 16`, `DEFAULT_KDC_PORT = 5000`, `DEFAULT_BOB_PORT = 5001`.
- Tidak ada kode duplikat. Logika yang dipakai lebih dari satu tempat dipindah ke fungsi bersama di `common.py` (menu, chat, kirim/terima, seal/unseal).
- Hindari variabel global yang berubah. Satu-satunya pengecualian: dictionary key di `kdc.py` (dengan lock). State sesi (`ks`, koneksi) dioper sebagai parameter atau disimpan dalam satu objek kecil, bukan banyak global.
- Seluruh `aes.py` murni: input bytes, output bytes, tanpa `print`, tanpa socket, dan tanpa membaca input. Interaksi pengguna hanya di `kdc.py`, `alice.py`, dan `bob.py`.
- Setiap file yang bisa dijalankan memakai `main()` dan `if __name__ == "__main__": main()`.
- Konversi `str` dan `bytes` dilakukan hanya di batas modul (`seal`/`unseal`, kirim/terima). Di dalam `aes.py` semuanya `bytes`/`list[int]`.

### 11.4 Type hint dan docstring
- Beri type hint pada signature semua fungsi (`def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:`).
- Docstring hanya satu baris dan hanya untuk fungsi publik yang tujuannya tidak jelas dari nama. Tidak ada docstring panjang.

### 11.5 Comment (dinilai oleh dosen)
- Default: **tanpa comment**. Kode yang jelas tidak butuh comment.
- Dilarang: comment yang menarasikan langkah (`# langkah 1: kirim ke KDC`), menjelaskan hal yang sudah terbaca dari kode (`# tambah 1`), kode yang di-comment, `TODO`/`FIXME`, dan blok penjelasan panjang.
- Boleh (jarang): satu baris untuk alasan yang tidak jelas dari kode, misalnya sumber konstanta (`# FIPS-197, tabel Rcon`).
- Penjelasan teori dan alasan desain ditaruh di `README.md`, bukan di kode.

### 11.6 Penanganan error
- Tangkap exception yang spesifik (`ValueError`, `OSError`, `json.JSONDecodeError`). Dilarang `except:` kosong dan dilarang menelan error diam-diam (`pass`).
- Validasi input di batas program (input menu, key, plaintext, pesan jaringan), bukan di dalam fungsi kripto murni; fungsi kripto cukup `raise ValueError` dengan pesan jelas.
- Pesan error untuk pengguna singkat dan jelas, dalam bahasa Indonesia, tanpa traceback (traceback hanya muncul untuk bug di luar yang diantisipasi).
- Tutup socket dengan `with` atau `try/finally`.

### 11.7 Keamanan dan keluaran
- Tidak ada key, `Ks`, atau nonce yang ditulis di kode, di berkas, maupun dicetak ke layar. Hex ciphertext boleh dicetak.
- Gunakan `secrets` untuk semua nilai acak (IV, `Ks`, nonce). Dilarang `random`.
- Seluruh `print` melalui satu fungsi kecil `log(label, message)` di `common.py` sehingga format keluaran seragam (`[STEP 2] ...`, `[KIRIM] ...`).

### 11.8 Test
- Satu test satu perilaku; nama menjelaskan perilaku (`test_encrypt_fips197_vector`, `test_unpad_rejects_zero_padding`).
- Test tidak bergantung urutan dan tidak butuh jaringan.
- Jalankan dengan `python -m unittest` dan harus hijau sebelum commit.

### 11.9 Checklist sebelum commit dan sebelum kumpul
- [ ] `python -m unittest` hijau.
- [ ] Tidak ada import library kripto atau `random`.
- [ ] Tidak ada literal key atau `print` yang mencetak key/`Ks`.
- [ ] Pencarian `#` di semua file: tidak ada comment narasi, kode mati, atau TODO.
- [ ] Tidak ada fungsi lebih dari sekitar 25 baris, tidak ada nesting lebih dari 3 tingkat.
- [ ] Tidak ada konstanta ajaib dan tidak ada kode duplikat (menu dan chat hanya di `common.py`).
- [ ] Semua signature punya type hint; tidak ada `except:` kosong.
- [ ] Tidak ada `__pycache__/` atau berkas sementara di repo.
