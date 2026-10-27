# Manual AES KDC

Implementasi pembelajaran distribusi kunci KDC dan komunikasi dua arah
Alice-Bob menggunakan AES-128-CBC manual sesuai [PRD](docs/PRD_KDC_AES_Final.md).

## Struktur proyek

```text
.
├── aes.py
├── common.py
├── kdc.py
├── alice.py
├── bob.py
├── test_aes.py
├── docs/
│   └── PRD_KDC_AES_Final.md
└── .gitignore
```

Pembagian tanggung jawab:

- `aes.py`: AES-128 manual, CBC, PKCS#7, dan demo interaktif lokal.
- `common.py`: transport JSON berbasis TCP, validasi, menu, logging, dan chat.
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
