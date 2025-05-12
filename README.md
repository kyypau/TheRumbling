🌍 [English](README.md) | 🇮🇩 [Bahasa Indonesia](README_ID.md)

<p align="center">
  <img src="banner.jpg" alt="Rumbling Banner" width="600"/>
</p>

# The Rumbling

**Unleash the power of Eldia with The Rumbling!**  
A Python-based network analysis and stress testing tool inspired by *Attack on Titan*. Designed for ethical network security testing and performance monitoring. This tool allows you to scout, probe, and monitor network targets with the might of the Titans—responsibly, of course! 🚨

---

## ⚠️ For Ethical Use Only ⚠️

The Rumbling is strictly intended for **legally authorized** penetration testing and educational purposes. Unauthorized use is illegal and goes against the principles of Eldia. **Always obtain explicit permission before testing any system.**

---

## What is The Rumbling?

**The Rumbling** is a versatile CLI tool built for penetration testers, network admins, and cybersecurity enthusiasts. With its Attack on Titan-inspired interface, this tool combines power and style in one package. Whether you're pinging servers, gathering WHOIS data, or monitoring bandwidth—The Rumbling can do it all!

---

## 🔥 Key Features

- 🗡️ Perform network stress tests (Layer 4 & 7) using methods like `TITAN_STOMP`, `COLOSSAL_SURGE`, and `RUMBLE_WRATH`. Supports proxy usage and user-agent spoofing.

- 📡 Ping target servers via ICMP to check latency and availability. Displays packet loss and average RTT.

- 🕵️‍♂️ Fetch detailed WHOIS data from ipwhois.app including country, ISP, organization, and more.

- 🔍 Check HTTP status codes of target websites and display their descriptions.

- 📊 Monitor real-time bandwidth (bytes/packets sent & received) using `psutil`.

- 🛑 Gracefully shut down all operations with a single command.

- ✨ Colorful CLI menu with Attack on Titan ASCII banner—epic every time you run it!

- 🐧📱 Fully compatible with Kali Linux, Termux, and other Linux-based systems.

---

## 🛠️ Installation

### Requirements

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
# If you encounter compilation errors:
pkg install clang make pkg-config -y
termux-setup-storage
python rumbling.py
```

---

## 🧩 Troubleshooting

* **Module Installation Failure:**

  * Ensure you have `build-essential` (Kali) or `clang make pkg-config` (Termux) installed
  * Upgrade pip: `pip3 install --upgrade pip`

* **Ping Fails:**

  * Check your internet connection & firewall settings
  * Try manual ping: `ping -c 5 google.com`

* **WHOIS Lookup Issues:**

  * Make sure `ipwhois.app` API is up and your internet is stable

* **Termux-Specific Issues:**

  * Disable battery optimization for Termux
  * Update to the latest Termux version (`>=0.118.0`)

---

## 🤝 Contribution

Want to strengthen The Rumbling even more? Fork the repository, submit a pull request, or open an issue. Let’s build the greatest Titan tool—ethically and awesomely!

---

## ⚖️ Disclaimer

**The Rumbling is for educational and authorized testing purposes only.**
Any misuse—including unauthorized attacks—is illegal.
I am not responsible for any negative consequences caused by this tool.
Use responsibly and respect all applicable laws.

---
