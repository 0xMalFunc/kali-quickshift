
# Kali Quick Shift 🚀

**Turn a fresh Ubuntu 22.04 / 24.04 LTS into a complete Kali‑style pentesting & reverse‑engineering workstation — with one script.**  
Stay on stable Ubuntu while cherry‑picking the goodies you miss from Kali Linux.

---

## ✨ What’s inside

| Stack | Key tools (subset) |
|-------|--------------------|
| **Core / Dev** | `git`, `curl`, `docker.io`, `docker-compose`, `zsh` + Oh‑My‑Zsh, `tmux`, `tilix`, `eza`, `bat`, `fzf`, `ripgrep`, `gcc/g++`, `cmake`, `ninja`, `python3-venv` |
| **Power mgmt** | `tlp`, `thermald`, `powertop` |
| **Pentest** | `nmap`, `wireshark`, `sqlmap`, `hydra`, `bettercap`, `mitmproxy`, `john`, `hashcat`, `aircrack-ng`, `burpsuite`, `ZAP`, `metasploit-framework`, `crackmapexec`, `ffuf`, `nuclei`, `subfinder`, `amass`, `feroxbuster`, `theHarvester` |
| **Reverse‑Engineering** | `ghidra`, `radare2`, `cutter`, `gdb-multiarch`, `strace`, `binwalk`, `apktool`, `dex2jar`, `jd-gui`, `checksec`, `capstone`, `unicorn` |
| **Desktop goodies** | `VLC`, `FFmpeg`, `GIMP`, `Inkscape`, `OBS Studio`, `Syncthing`, `Timeshift` |

> 🛈 Full lists live in **`install.sh`**.

---

## 🔧 Smart installer highlights

* **Idempotent** — run it again any time; it only adds what’s missing.  
* **Fallback logic** — if a tool isn’t in Ubuntu repos, it auto‑installs via **Flatpak, Snap, pipx, or a vendor script**.  
* **Universe & multiverse** repos enabled automatically.  
* **Laptop‑friendly** — enables `tlp` & `thermald` out of the box.  
* **Python venv** at **`/opt/security-tools-venv`** for extra pentest libs (`pwntools`, `impacket`, …).  
* Installs **Go 1.21** when required (for `nuclei`, `ffuf`, etc.).

---

## ⚡ Quick start

```bash
# 1. Clone
git clone https://github.com/0xMalFunc/kali-quickshift.git
cd kali-quickshift

# 2. Run (~3–6 GB downloads; grab a ☕)
chmod +x install.sh
sudo ./install.sh
```

> 💡 Reboot afterwards for kernel modules & shell tweaks to load.

---

## 🛠 Post‑install checklist

1. **Docker rootless:**  
   ```bash
   sudo usermod -aG docker $USER && newgrp docker
   ```
2. **Wireshark capture as user:**  
   ```bash
   sudo dpkg-reconfigure wireshark-common  # choose *Yes*
   sudo usermod -aG wireshark $USER
   ```
3. **Oh‑My‑Zsh themes/plugins:** tweak `~/.zshrc`.
4. **Timeshift:** take a snapshot before hardcore experimentation.

---

## 🤔 Why not just install Kali?

| Need | Kali ISO | **Kali Quick Shift** |
|------|----------|----------------------|
| Stable **Ubuntu LTS** base | ❌ | ✅ |
| Best‑in‑class **hardware support** & PPAs | ❌ | ✅ |
| Lightweight (no extra desktop) | ❌ | ✅ |
| Keep existing **Snap/Flatpak/dev** workflow | ❌ | ✅ |

---

## 👐 Contributing

PRs & issue reports welcome!  
Please keep the script:

* **Idempotent** – no interactive prompts  
* **Lean** – aim for < 6 GB extra disk usage  
* **Ubuntu‑only** – separate PR for Debian support

---

## 📝 License

**MIT © 2025 “0xmalfunc”**

---

## ⚖️ Disclaimer

This toolkit installs **offensive‑security** software.  
Use **only on systems & networks** you **own or have explicit permission** to test.  
You are **fully responsible** for any misuse or damage.
