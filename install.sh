#!/usr/bin/env bash
# kali-quickshift — provision Ubuntu 22.04/24.04 with a Kali-style toolkit
# Author: "0xmalfunc" – 2024
#
# This version adds per-package fallbacks (snap or GitHub) so the script keeps
# running even when a tool is missing from the Ubuntu archives.

set -euo pipefail
IFS=$'\n\t'

msg() { printf "\e[1;32m[+] %s\e[0m\n" "$*"; }
err() { printf "\e[1;31m[!] %s\e[0m\n" "$*"; }
warn() { printf "\e[1;33m[*] %s\e[0m\n" "$*"; }

# Check if running as root
[[ $EUID -eq 0 ]] || { err "Run with sudo or as root."; exit 1; }

# Check Ubuntu version
if ! grep -q "Ubuntu" /etc/os-release; then
    err "This script is designed for Ubuntu systems only."
    exit 1
fi

UBUNTU_VERSION=$(lsb_release -rs)
if [[ "$UBUNTU_VERSION" != "22.04" && "$UBUNTU_VERSION" != "24.04" ]]; then
    warn "This script is tested on Ubuntu 22.04/24.04. You're running $UBUNTU_VERSION. Continue at your own risk."
    read -p "Continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

msg "Enabling universe & multiverse repositories"
add-apt-repository -y universe
add-apt-repository -y multiverse

msg "Updating system"
apt-get update || { err "Failed to update package lists"; exit 1; }
apt-get -y full-upgrade || warn "System upgrade had some issues, continuing anyway"

install_pkgs() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" || return 1
}

# ───────────────────────────────────[ Core / Dev ]───────────────────────────────────
CORE_PKGS=(
    git curl wget build-essential dkms linux-headers-$(uname -r) \
    software-properties-common zsh tmux tilix unzip flameshot htop glances btop \
    eza bat fd-find ripgrep fzf zoxide tig neofetch gparted vlc ffmpeg audacity \
    inkscape gimp krita obs-studio syncthing timeshift python3-pip python3-venv \
    docker.io docker-compose flatpak fonts-powerline ninja-build cmake gcc g++ \
    make pkg-config libssl-dev net-tools iproute2 ncat socat
)

msg "Installing core & dev packages"
install_pkgs "${CORE_PKGS[@]}" || warn "Some core packages failed to install"

# Docker group for desktop user
usermod -aG docker "$SUDO_USER" || warn "Failed to add user to docker group"

# ─────────────────────────────────[ Power tools ]────────────────────────────────────
POWER_PKGS=(tlp powertop thermald)
msg "Installing power / performance tools"
install_pkgs "${POWER_PKGS[@]}"
systemctl enable tlp thermald --now || warn "Failed to enable power management services"

# ────────────────────────────────[ Pentest tools ]──────────────────────────────────
PENTEST_PKGS=(
    nmap wireshark netdiscover gobuster dirb wfuzz sqlmap hydra \
    bettercap mitmproxy john hashcat nikto tcpdump tshark dsniff aircrack-ng \
    reaver wifite burpsuite zaproxy metasploit-framework dnsenum theharvester \
    steg-crypt steghide stegosuite enum4linux crackmapexec set exploitdb \
    nuclei subfinder amass feroxbuster ffuf
)

fallback_install() {
    local pkg="$1"
    msg "Fallback install for $pkg"
    case "$pkg" in
        burpsuite)
            # Install Burp Suite Community Edition from Kali repository
            echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" | tee /etc/apt/sources.list.d/kali.list
            curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor | tee /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg > /dev/null
            apt-get update
            apt-get install -y burpsuite ;;
        zaproxy)
            # Install OWASP ZAP using flatpak
            flatpak install -y flathub org.zaproxy.ZAP ;;
        metasploit-framework)
            # Install Metasploit Framework from official installer
            curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | bash -s - ;;
        nuclei)
            # Install Go first if not present
            if ! command -v go &> /dev/null; then
                curl -sL https://go.dev/dl/go1.21.6.linux-amd64.tar.gz | tar -C /usr/local -xzf -
                echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /home/"$SUDO_USER"/.zshrc
                echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /home/"$SUDO_USER"/.bashrc
                export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
            fi
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ;;
        subfinder)
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
        amass)
            go install -v github.com/owasp-amass/amass/v4/...@master ;;
        feroxbuster)
            curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash ;;
        ffuf)
            go install github.com/ffuf/ffuf/v2@latest ;;
        crackmapexec)
            python3 -m pip install crackmapexec ;;
        enum4linux)
            git clone --depth 1 https://github.com/CiscoCXSecurity/enum4linux /opt/enum4linux 
            ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux ;;
        wifite)
            git clone --depth 1 https://github.com/derv82/wifite2 /opt/wifite2
            ln -sf /opt/wifite2/wifite.py /usr/local/bin/wifite ;;
        *)
            err "No fallback available for $pkg" ;;
    esac
}

msg "Installing pentest tools (with fallbacks)"
for pkg in "${PENTEST_PKGS[@]}"; do
    if ! install_pkgs "$pkg"; then
        fallback_install "$pkg"
    fi
done

# Install Go for various tools
msg "Installing Go"
if ! command -v go &> /dev/null; then
    curl -sL https://go.dev/dl/go1.21.6.linux-amd64.tar.gz | tar -C /usr/local -xzf -
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /home/"$SUDO_USER"/.zshrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /home/"$SUDO_USER"/.bashrc
fi

# ───────────────────────────────[ Reverse-engineering ]──────────────────────────────
RE_PKGS=(
    ghidra radare2 cutter gdb gdb-multiarch strace ltrace binutils hexedit binwalk \
    apktool dex2jar jd-gui openjdk-17-jre-headless uncompyle6 checksec \
    python3-capstone python3-unicorn
)

msg "Installing reverse-engineering arsenal"
install_pkgs "${RE_PKGS[@]}" || warn "Some RE packages failed to install"

# ────────────────────────────────────[ Flatpak ]────────────────────────────────────
msg "Configuring Flatpak & Flathub"
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

# ──────────────────────────────────[ Oh-My-Zsh ]────────────────────────────────────
msg "Setting up Oh-My-Zsh for $SUDO_USER"
if [ ! -d "/home/$SUDO_USER/.oh-my-zsh" ]; then
    sudo -u "$SUDO_USER" sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    chsh -s "$(command -v zsh)" "$SUDO_USER"
fi

# ────────────────────────────────[ Python extras ]────────────────────────────────────
msg "Installing Python pentest libraries"
PYTHON_PKGS=(
    pwntools
    name-that-hash
    requests
    beautifulsoup4
    scapy
    impacket
    pycryptodome
    python-nmap
    paramiko
)

# Create a virtual environment for security tools
VENV_PATH="/opt/security-tools-venv"
python3 -m venv "$VENV_PATH"
source "$VENV_PATH/bin/activate"

# Install packages in the virtual environment
"$VENV_PATH/bin/pip" install --upgrade pip
for pkg in "${PYTHON_PKGS[@]}"; do
    "$VENV_PATH/bin/pip" install --upgrade "$pkg" || warn "Failed to install Python package: $pkg"
done

# Create symlinks for commonly used tools
for script in "$VENV_PATH/bin/"*; do
    if [[ -f "$script" && -x "$script" ]]; then
        ln -sf "$script" "/usr/local/bin/$(basename "$script")"
    fi
done

# Add the virtual environment to PATH for all users
echo "export PATH=$VENV_PATH/bin:\$PATH" > /etc/profile.d/security-tools-venv.sh

# Fix permissions
chown -R root:root "$VENV_PATH"
chmod -R 755 "$VENV_PATH"

deactivate

msg "All done! Please log out and back in for all changes to take effect."
msg "Some tools might require a system reboot."
