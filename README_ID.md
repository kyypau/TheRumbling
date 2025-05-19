<p align="center">
  <img src="Banner.png" alt="Rumbling Banner" width="600"/>
</p>

# The Rumbling

**Lepaskan kekuatan Eldia dengan The Rumbling!**  
Sebuah tool analisis dan stress testing jaringan berbasis Python yang terinspirasi dari *Attack on Titan*. Dirancang untuk pengujian keamanan jaringan secara etis dan pemantauan performa. Tool ini memungkinkan kamu untuk mengintai, menguji, dan memantau target jaringan dengan kekuatan para Titan—tentunya dengan tanggung jawab! 🚨

---

## ⚠️ Hanya untuk Penggunaan Etis

The Rumbling hanya diperuntukkan bagi pengujian penetrasi yang **diizinkan secara hukum** dan untuk tujuan edukatif. Penggunaan tanpa izin adalah ilegal dan bertentangan dengan prinsip Eldia. **Selalu dapatkan izin tertulis sebelum melakukan pengujian.**

---

## Apa Itu The Rumbling?

**The Rumbling** adalah tool CLI serbaguna yang dirancang untuk pentester, admin jaringan, dan penggemar cybersecurity. Dengan tampilan bertema *Attack on Titan*, tool ini memberikan kekuatan dan gaya dalam satu paket. Apakah kamu ingin ping server, ambil informasi WHOIS, atau pantau bandwidth—semua bisa dilakukan!

---

## 🔥 Fitur Unggulan

- 🗡️ Lakukan stress test ke jaringan (Layer 4 & 7) menggunakan metode seperti `TITAN_STOMP`, `COLOSSAL_SURGE`, dan `RUMBLE_WRATH`. Dukungan proxy dan spoofing user-agent tersedia.

- 📡 Lacak latensi dan status jaringan target dengan ping ICMP. Tampilkan packet loss & RTT rata-rata.

- 🕵️‍♂️ Ambil data WHOIS detail dari ipwhois.app seperti negara, ISP, organisasi, dll.

- 🔍 Cek status HTTP situs target dan tampilkan kode status serta penjelasannya.

- 📊 Pantau bandwidth secara real-time (bytes/packets dikirim & diterima) dengan `psutil`.

- 🛑 Hentikan semua operasi dengan satu perintah.

- ✨ Menu penuh warna dengan banner ASCII khas Attack on Titan—epik setiap kali digunakan!

- 🐧📱 Berjalan lancar di Kali Linux, Termux, dan sistem berbasis Linux lainnya.

---

## 🛠️ Instalasi

### Prasyarat

- Python 3.6+
- git
- pip

### Kali Linux

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
git clone https://github.com/kyypau/TheRumbling.git
cd TheRumbling
pip3 install -r requirements.txt
python3 rumbling.py
````

### Termux

```bash
pkg update && pkg upgrade -y
pkg install python git build-essential -y
git clone https://github.com/kyypau/TheRumbling.git
cd TheRumbling
pip install -r requirements.txt
# Jika error saat kompilasi:
pkg install clang make pkg-config -y
termux-setup-storage
python rumbling.py
```

---

## 🧩 Troubleshooting

* **Gagal Instal Modul:**

  * Pastikan sudah install `build-essential` (Kali) atau `clang make pkg-config` (Termux)
  * Upgrade pip: `pip3 install --upgrade pip`

* **Ping Gagal:**

  * Periksa koneksi internet & firewall
  * Tes manual: `ping -c 5 google.com`

* **WHOIS Error:**

  * Pastikan API `ipwhois.app` aktif & koneksi internet stabil

* **Termux Error:**

  * Nonaktifkan optimasi baterai untuk Termux
  * Update ke versi terbaru Termux (`>=0.118.0`)

---

## 🤝 Kontribusi

Ingin memperkuat kekuatan The Rumbling? Fork repositori, kirim pull request, atau buat issue baru. Mari kita bangun bersama alat Titan terbaik—secara etis dan keren!

---

## ⚖️ Disclaimer

**The Rumbling hanya untuk edukasi dan pengujian yang sah.**
Segala penyalahgunaan termasuk serangan jaringan tanpa izin adalah tindakan ilegal.
Saya tidak bertanggung jawab atas dampak negatif yang disebabkan oleh tool ini.
Gunakan dengan tanggung jawab & hormati hukum yang berlaku.

---
