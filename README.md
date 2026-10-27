# Manual AES KDC

Implementasi pembelajaran distribusi kunci KDC dan komunikasi dua arah
Alice-Bob menggunakan AES-128-CBC manual sesuai [PRD](docs/PRD_KDC_AES_Final.md).

## Struktur proyek

```text
.
├── aes.py
├── common.py
├── config.example.json
├── kdc.py
├── alice.py
├── bob.py
├── test_aes.py
├── test_protocol.py
├── docs/
│   └── PRD_KDC_AES_Final.md
└── .gitignore
```

Pembagian tanggung jawab:

- `aes.py`: AES-128 manual, CBC, dan PKCS#7.
- `common.py`: transport JSON berbasis TCP, validasi, menu, logging, dan chat.
- `config.example.json`: template konfigurasi jaringan.
- `kdc.py`: server KDC dan distribusi session key.
- `alice.py`: klien Alice dan penginisiasi protokol.
- `bob.py`: server Bob, autentikasi tiket, dan penerima protokol.
- `test_aes.py`: pengujian AES dengan `unittest`.

## Batasan

Proyek ini hanya memakai library standar Python dan ditujukan untuk pembelajaran.
CBC tanpa MAC tidak memberi integritas ciphertext, tiket tidak memiliki timestamp,
dan implementasi AES manual belum diaudit untuk penggunaan produksi.

Detail protokol, format pesan, urutan implementasi, dan prosedur pengujian ada di
`docs/PRD_KDC_AES_Final.md`.

## Konfigurasi jaringan

Salin template konfigurasi sebelum menjalankan program:

```bash
cp config.example.json config.json
```

Edit alamat `host` dan `port` di `config.json`. `host` adalah alamat yang
dipakai proses lain untuk terhubung, sedangkan `bind_host` adalah alamat
interface tempat KDC atau Bob listen. Jika `bind_host` tidak ditulis, nilainya
adalah `0.0.0.0`.

Jalankan dari direktori project:

```bash
python3 kdc.py
python3 bob.py
python3 alice.py
```

`config.json` tidak di-commit karena sudah tercantum di `.gitignore`.

## Pengujian

```bash
python3 -m unittest -v
```
