#!/bin/bash

# VPS Güvenlik ve Performans Denetim Scripti - Evrensel Sürüm
# Bu script, VPS'inizin güvenliğini ve performansını denetler ve iyileştirmeler için rapor sunar.
# Desteklenen dağıtımlar: Debian/Ubuntu, Red Hat/CentOS/Fedora, Arch Linux, SUSE/openSUSE

# Renkli çıktı fonksiyonları
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
echo -e "${BLUE}
               _______
         _.-'       \`-._
       .'               \`.
     _/                   \_
    /  .-\"\"\"-.     .-\"\"\"-.  \\
   /  /       \\   /       \\  \\
  |   |       |   |       |   |
  |   |       |   |       |   |
   \\  \\       /   \\       /  /
    \\_`._   .'     `._   _.'
       \`-._         _.'
           \`-.___.-' 
  ${GREEN}DESIGNED BY EREN (G4L1LEO) AKKUŞ™${WHITE}
"
echo_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

echo_error() {
    echo -e "${RED}[✗] $1${NC}"
}

echo_warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

echo_info() {
    echo -e "${BLUE}[i] $1${NC}"
}

# Dağıtım tespiti
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_FAMILY="unknown"
        
        # Dağıtım ailesini tespit et
        if [[ "$ID" == "debian" || "$ID" == "ubuntu" || "$ID_LIKE" == *"debian"* ]]; then
            DISTRO_FAMILY="debian"
        elif [[ "$ID" == "rhel" || "$ID" == "centos" || "$ID" == "fedora" || "$ID_LIKE" == *"rhel"* || "$ID_LIKE" == *"fedora"* ]]; then
            DISTRO_FAMILY="redhat"
        elif [[ "$ID" == "arch" || "$ID_LIKE" == *"arch"* ]]; then
            DISTRO_FAMILY="arch"
        elif [[ "$ID" == "opensuse" || "$ID" == "suse" || "$ID_LIKE" == *"suse"* ]]; then
            DISTRO_FAMILY="suse"
        fi
    else
        # /etc/os-release bulunamadıysa alternatif tespit yöntemi
        if [ -f /etc/debian_version ]; then
            DISTRO="debian"
            DISTRO_FAMILY="debian"
        elif [ -f /etc/redhat-release ]; then
            DISTRO="rhel"
            DISTRO_FAMILY="redhat"
        elif [ -f /etc/arch-release ]; then
            DISTRO="arch"
            DISTRO_FAMILY="arch"
        elif [ -f /etc/SuSE-release ]; then
            DISTRO="suse"
            DISTRO_FAMILY="suse"
        else
            DISTRO="unknown"
            DISTRO_FAMILY="unknown"
        fi
    fi
    
    echo_info "Tespit edilen dağıtım: $DISTRO (Aile: $DISTRO_FAMILY)"
    return 0
}

# Paket yöneticisi komutları
install_package() {
    local package=$1
    case $DISTRO_FAMILY in
        debian)
            apt update -qq
            apt install -y "$package"
            ;;
        redhat)
            if command -v dnf >/dev/null; then
                dnf install -y "$package"
            else
                yum install -y "$package"
            fi
            ;;
        arch)
            pacman -Sy --noconfirm "$package"
            ;;
        suse)
            zypper --non-interactive install "$package"
            ;;
        *)
            echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Paket kurulumu desteklenmiyor."
            return 1
            ;;
    esac
    return $?
}

check_updates() {
    case $DISTRO_FAMILY in
        debian)
            apt update -qq
            UPDATES=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
            SECURITY_UPDATES=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
            ;;
        redhat)
            if command -v dnf >/dev/null; then
                dnf check-update -q > /tmp/updates.txt 2>/dev/null
                UPDATES=$(grep -v "^$" /tmp/updates.txt | wc -l)
                SECURITY_UPDATES=$(grep -i security /tmp/updates.txt | wc -l)
            else
                yum check-update -q > /tmp/updates.txt 2>/dev/null
                UPDATES=$(grep -v "^$" /tmp/updates.txt | wc -l)
                SECURITY_UPDATES=$(grep -i security /tmp/updates.txt | wc -l)
            fi
            ;;
        arch)
            pacman -Sy --quiet
            UPDATES=$(pacman -Qu | wc -l)
            SECURITY_UPDATES=0  # Arch'da özel bir güvenlik güncellemesi işareti yok
            ;;
        suse)
            zypper --non-interactive refresh > /dev/null
            UPDATES=$(zypper --non-interactive list-updates | grep "^v" | wc -l)
            SECURITY_UPDATES=$(zypper --non-interactive list-patches --category security | grep -v "^#" | wc -l)
            ;;
        *)
            echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Güncellemeler kontrol edilemiyor."
            UPDATES="Bilinmiyor"
            SECURITY_UPDATES="Bilinmiyor"
            ;;
    esac
}

apply_updates() {
    case $DISTRO_FAMILY in
        debian)
            apt upgrade -y
            ;;
        redhat)
            if command -v dnf >/dev/null; then
                dnf upgrade -y
            else
                yum upgrade -y
            fi
            ;;
        arch)
            pacman -Syu --noconfirm
            ;;
        suse)
            zypper --non-interactive update
            ;;
        *)
            echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Güncellemeler uygulanamıyor."
            return 1
            ;;
    esac
    return $?
}

setup_firewall() {
    case $DISTRO_FAMILY in
        debian|arch)
            install_package "ufw"
            ;;
        redhat)
            if command -v dnf >/dev/null; then
                dnf install -y firewalld
            else
                yum install -y firewalld
            fi
            ;;
        suse)
            zypper --non-interactive install firewalld
            ;;
        *)
            echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Güvenlik duvarı kurulumu desteklenmiyor."
            return 1
            ;;
    esac
    return $?
}

configure_firewall() {
    local ssh_port=$1
    
    case $DISTRO_FAMILY in
        debian|arch)
            if command -v ufw >/dev/null; then
                ufw allow "$ssh_port"/tcp
                ufw delete allow 22/tcp 2>/dev/null
                ufw --force enable
                echo_success "UFW güvenlik duvarı etkinleştirildi ve SSH portuna ($ssh_port) izin verildi."
                return 0
            fi
            ;;
        redhat|suse)
            if command -v firewall-cmd >/dev/null; then
                systemctl enable firewalld
                systemctl start firewalld
                firewall-cmd --permanent --add-port="$ssh_port"/tcp
                [ "$ssh_port" != "22" ] && firewall-cmd --permanent --remove-service=ssh
                firewall-cmd --reload
                echo_success "Firewalld güvenlik duvarı etkinleştirildi ve SSH portuna ($ssh_port) izin verildi."
                return 0
            fi
            ;;
    esac
    
    echo_error "Güvenlik duvarı yapılandırılamadı."
    return 1
}

setup_fail2ban() {
    case $DISTRO_FAMILY in
        debian)
            install_package "fail2ban"
            ;;
        redhat)
            if command -v dnf >/dev/null; then
                dnf install -y epel-release
                dnf install -y fail2ban
            else
                yum install -y epel-release
                yum install -y fail2ban
            fi
            ;;
        arch)
            pacman -Sy --noconfirm fail2ban
            ;;
        suse)
            zypper --non-interactive install fail2ban
            ;;
        *)
            echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Fail2ban kurulumu desteklenmiyor."
            return 1
            ;;
    esac
    
    # Servis başlatma
    systemctl enable fail2ban
    systemctl start fail2ban
    return $?
}

configure_fail2ban() {
    local ssh_port=$1
    
    # SSH jail yapılandırması
    mkdir -p /etc/fail2ban
    
    case $DISTRO_FAMILY in
        debian)
            cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF
            ;;
        redhat|arch|suse)
            cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/secure
maxretry = 5
bantime = 3600
EOF
            # Red Hat bazlı sistemlerde log dosyası farklı olabilir
            if [ ! -f /var/log/secure ]; then
                if [ -f /var/log/auth.log ]; then
                    sed -i 's|/var/log/secure|/var/log/auth.log|' /etc/fail2ban/jail.local
                elif [ -f /var/log/messages ]; then
                    sed -i 's|/var/log/secure|/var/log/messages|' /etc/fail2ban/jail.local
                fi
            fi
            ;;
        *)
            echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Fail2ban yapılandırması desteklenmiyor."
            return 1
            ;;
    esac
    
    systemctl restart fail2ban
    return $?
}

# Başlık ve giriş
clear
echo "==============================================="
echo "     VPS GÜVENLİK VE PERFORMANS DENETİMİ      "
echo "==============================================="
echo ""
echo "Bu araç VPS'inizin güvenlik ve performans durumunu denetler."
echo "Lütfen tüm kontroller bitene kadar bekleyin."
echo ""

# Root kontrolü
if [ "$(id -u)" -ne 0 ]; then
    echo_error "Bu script root yetkileri ile çalıştırılmalıdır."
    echo "Lütfen 'sudo bash $0' komutuyla yeniden çalıştırın."
    exit 1
fi

# Dağıtım tespiti
detect_distro

# Rapor için klasör oluştur
REPORT_DIR="/root/vps_audit_reports"
REPORT_FILE="$REPORT_DIR/vps_audit_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$REPORT_DIR"

# Rapor başlığı
{
    echo "VPS GÜVENLİK VE PERFORMANS DENETİMİ"
    echo "Tarih: $(date)"
    echo "Sunucu: $(hostname)"
    echo "IP Adresi: $(hostname -I | awk '{print $1}')"
    echo "Dağıtım: $DISTRO (Aile: $DISTRO_FAMILY)"
    echo "==============================================="
    echo ""
} > "$REPORT_FILE"

# ===== GÜVENLİK KONTROLLERİ =====
echo "===== GÜVENLİK KONTROLLERİ ====="
{
    echo "===== GÜVENLİK KONTROLLERİ ====="
    echo ""
} >> "$REPORT_FILE"

# SSH Yapılandırması
echo_info "SSH Yapılandırmasını kontrol ediliyor..."
{
    echo "--- SSH YAPILANDIRMASI ---"
} >> "$REPORT_FILE"

SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSH_CONFIG" ]; then
    # Root girişi kontrolü
    ROOT_LOGIN=$(grep -i "^PermitRootLogin" "$SSH_CONFIG" | awk '{print $2}')
    if [ -z "$ROOT_LOGIN" ] || [ "$ROOT_LOGIN" == "yes" ]; then
        echo_warn "Root SSH girişi aktif."
        {
            echo "[!] Root SSH girişi aktif. Güvenlik riski oluşturabilir."
            echo "    Önerilen: PermitRootLogin no"
        } >> "$REPORT_FILE"
    else
        echo_success "Root SSH girişi devre dışı."
        {
            echo "[✓] Root SSH girişi devre dışı."
        } >> "$REPORT_FILE"
    fi
    
    # Parola doğrulama kontrolü
    PASSWORD_AUTH=$(grep -i "^PasswordAuthentication" "$SSH_CONFIG" | awk '{print $2}')
    if [ -z "$PASSWORD_AUTH" ] || [ "$PASSWORD_AUTH" == "yes" ]; then
        echo_warn "SSH parola doğrulaması aktif."
        {
            echo "[!] SSH parola doğrulaması aktif. Anahtar tabanlı kimlik doğrulama daha güvenlidir."
            echo "    Önerilen: PasswordAuthentication no"
        } >> "$REPORT_FILE"
    else
        echo_success "SSH parola doğrulaması devre dışı (anahtar tabanlı kimlik doğrulama kullanılıyor)."
        {
            echo "[✓] SSH parola doğrulaması devre dışı (anahtar tabanlı kimlik doğrulama kullanılıyor)."
        } >> "$REPORT_FILE"
    fi
    
    # SSH port kontrolü
    SSH_PORT=$(grep -i "^Port" "$SSH_CONFIG" | awk '{print $2}')
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=22
    fi
    
    if [ "$SSH_PORT" == "22" ]; then
        echo_warn "SSH varsayılan port (22) kullanılıyor."
        {
            echo "[!] SSH varsayılan port (22) kullanılıyor. Güvenlik için değiştirilmesi önerilir."
        } >> "$REPORT_FILE"
        
        # SSH port değiştirme seçeneği
        echo ""
        read -p "SSH portunu değiştirmek ister misiniz? (E/h): " CHANGE_PORT
        if [[ "$CHANGE_PORT" =~ ^[Ee]$ ]] || [[ -z "$CHANGE_PORT" ]]; then
            read -p "Yeni SSH port numarası girin: " NEW_PORT
            
            # Port numarası geçerliliğini kontrol et
            if [[ "$NEW_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -gt 1024 ] && [ "$NEW_PORT" -lt 65535 ]; then
                # SSH yapılandırmasını yedekle
                cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"
                
                # SSH yapılandırmasını güncelle
                if grep -q "^Port " "$SSH_CONFIG"; then
                    sed -i "s/^Port .*/Port $NEW_PORT/" "$SSH_CONFIG"
                else
                    echo "Port $NEW_PORT" >> "$SSH_CONFIG"
                fi
                
                echo_success "SSH port $NEW_PORT olarak değiştirildi. Değişikliğin etkin olması için SSH servisini yeniden başlatın."
                {
                    echo "[✓] SSH port $NEW_PORT olarak değiştirildi."
                } >> "$REPORT_FILE"
                
                # Güvenlik duvarı kuralını güncelle
                case $DISTRO_FAMILY in
                    debian|arch)
                        if command -v ufw >/dev/null && ufw status | grep -q "active"; then
                            ufw allow "$NEW_PORT"/tcp
                            ufw delete allow 22/tcp 2>/dev/null
                            echo_success "UFW kuralları güncellendi: Port $NEW_PORT izin verildi."
                            {
                                echo "[✓] UFW kuralları güncellendi: Port $NEW_PORT izin verildi."
                            } >> "$REPORT_FILE"
                        fi
                        ;;
                    redhat|suse)
                        if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
                            firewall-cmd --permanent --add-port="$NEW_PORT"/tcp
                            firewall-cmd --permanent --remove-service=ssh
                            firewall-cmd --reload
                            echo_success "Firewalld kuralları güncellendi: Port $NEW_PORT izin verildi."
                            {
                                echo "[✓] Firewalld kuralları güncellendi: Port $NEW_PORT izin verildi."
                            } >> "$REPORT_FILE"
                        fi
                        ;;
                esac
                
                # SSH portu güncellenirse, değişkeni güncelle
                SSH_PORT=$NEW_PORT
            else
                echo_error "Geçersiz port numarası! Port 1024-65535 arasında olmalıdır."
                {
                    echo "[✗] SSH port değiştirme başarısız: Geçersiz port numarası."
                } >> "$REPORT_FILE"
            fi
        fi
    else
        echo_success "SSH varsayılan olmayan port ($SSH_PORT) kullanılıyor."
        {
            echo "[✓] SSH varsayılan olmayan port ($SSH_PORT) kullanılıyor."
        } >> "$REPORT_FILE"
    fi
else
    echo_error "SSH yapılandırma dosyası bulunamadı: $SSH_CONFIG"
    {
        echo "[✗] SSH yapılandırma dosyası bulunamadı: $SSH_CONFIG"
    } >> "$REPORT_FILE"
fi

echo ""

# Güvenlik Duvarı Kontrolü
echo_info "Güvenlik duvarı durumu kontrol ediliyor..."
{
    echo "--- GÜVENLİK DUVARI DURUMU ---"
} >> "$REPORT_FILE"

FIREWALL_ACTIVE=false

case $DISTRO_FAMILY in
    debian|arch)
        if command -v ufw >/dev/null; then
            UFW_STATUS=$(ufw status | grep "Status:" | awk '{print $2}')
            if [ "$UFW_STATUS" == "active" ]; then
                echo_success "UFW güvenlik duvarı aktif."
                {
                    echo "[✓] UFW güvenlik duvarı aktif."
                    echo "    UFW kuralları:"
                    ufw status numbered >> "$REPORT_FILE"
                } >> "$REPORT_FILE"
                FIREWALL_ACTIVE=true
            else
                echo_warn "UFW güvenlik duvarı devre dışı."
                {
                    echo "[!] UFW güvenlik duvarı devre dışı. Güvenlik için etkinleştirilmesi önerilir."
                    echo "    Etkinleştirmek için: sudo ufw enable"
                } >> "$REPORT_FILE"
            fi
        else
            echo_warn "UFW güvenlik duvarı kurulu değil."
            {
                echo "[!] UFW güvenlik duvarı kurulu değil."
            } >> "$REPORT_FILE"
        fi
        ;;
    redhat|suse)
        if command -v firewall-cmd >/dev/null; then
            if systemctl is-active --quiet firewalld; then
                echo_success "Firewalld güvenlik duvarı aktif."
                {
                    echo "[✓] Firewalld güvenlik duvarı aktif."
                    echo "    Firewalld kuralları:"
                    firewall-cmd --list-all >> "$REPORT_FILE"
                } >> "$REPORT_FILE"
                FIREWALL_ACTIVE=true
            else
                echo_warn "Firewalld güvenlik duvarı devre dışı."
                {
                    echo "[!] Firewalld güvenlik duvarı devre dışı. Güvenlik için etkinleştirilmesi önerilir."
                    echo "    Etkinleştirmek için: sudo systemctl enable --now firewalld"
                } >> "$REPORT_FILE"
            fi
        else
            echo_warn "Firewalld güvenlik duvarı kurulu değil."
            {
                echo "[!] Firewalld güvenlik duvarı kurulu değil."
            } >> "$REPORT_FILE"
        fi
        ;;
    *)
        echo_error "Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Güvenlik duvarı durumu kontrol edilemiyor."
        {
            echo "[✗] Bilinmeyen dağıtım ailesi: $DISTRO_FAMILY. Güvenlik duvarı durumu kontrol edilemiyor."
        } >> "$REPORT_FILE"
        ;;
esac

if [ "$FIREWALL_ACTIVE" = false ]; then
    # Güvenlik duvarı kurulum/etkinleştirme seçeneği
    echo "Güvenlik duvarını kurmak/etkinleştirmek ister misiniz? (E/h): "
    read ENABLE_FIREWALL
    if [[ "$ENABLE_FIREWALL" =~ ^[Ee]$ ]] || [[ -z "$ENABLE_FIREWALL" ]]; then
        setup_firewall
        configure_firewall "$SSH_PORT"
    fi
fi

echo ""

# Fail2ban Kontrolü
echo_info "Fail2ban durumu kontrol ediliyor..."
{
    echo "--- FAIL2BAN DURUMU ---"
} >> "$REPORT_FILE"

if command -v fail2ban-client >/dev/null; then
    if systemctl is-active --quiet fail2ban; then
        echo_success "Fail2ban aktif."
        {
            echo "[✓] Fail2ban aktif."
            echo "    Fail2ban durumu:"
            fail2ban-client status >> "$REPORT_FILE"
        } >> "$REPORT_FILE"
    else
        echo_warn "Fail2ban kurulu fakat çalışmıyor."
        {
            echo "[!] Fail2ban kurulu fakat çalışmıyor."
            echo "    Başlatmak için: sudo systemctl start fail2ban"
        } >> "$REPORT_FILE"
    fi
else
    echo_warn "Fail2ban kurulu değil."
    {
        echo "[!] Fail2ban kurulu değil. Brute force saldırılarına karşı korunma için kurulması önerilir."
        echo "    Kurulum, dağıtımınıza bağlı olarak değişir."
    } >> "$REPORT_FILE"
    
    # Fail2ban kurulum seçeneği
    echo "Fail2ban kurmak ister misiniz? (E/h): "
    read INSTALL_FAIL2BAN
    if [[ "$INSTALL_FAIL2BAN" =~ ^[Ee]$ ]] || [[ -z "$INSTALL_FAIL2BAN" ]]; then
        setup_fail2ban
        configure_fail2ban "$SSH_PORT"
        echo_success "Fail2ban kuruldu ve SSH için yapılandırıldı."
        {
            echo "[✓] Fail2ban kuruldu ve SSH için yapılandırıldı."
        } >> "$REPORT_FILE"
    fi
fi

echo ""

# Sistem Güncellemeleri Kontrolü
echo_info "Sistem güncellemeleri kontrol ediliyor..."
{
    echo "--- SİSTEM GÜNCELLEMELERİ ---"
} >> "$REPORT_FILE"

check_updates

if [[ "$UPDATES" =~ ^[0-9]+$ ]] && [ "$UPDATES" -eq 0 ]; then
    echo_success "Sistem güncel. Bekleyen güncelleme yok."
    {
        echo "[✓] Sistem güncel. Bekleyen güncelleme yok."
    } >> "$REPORT_FILE"
elif [[ "$UPDATES" =~ ^[0-9]+$ ]]; then
    echo_warn "Bekleyen $UPDATES güncelleme mevcut ($SECURITY_UPDATES güvenlik güncellemesi)."
    {
        echo "[!] Bekleyen $UPDATES güncelleme mevcut ($SECURITY_UPDATES güvenlik güncellemesi)."
        echo "    Güncelleme komutu dağıtımınıza göre değişir."
    } >> "$REPORT_FILE"
    
    # Güncelleme seçeneği
    echo "Sistemi güncellemek ister misiniz? (E/h): "
    read UPDATE_SYSTEM
    if [[ "$UPDATE_SYSTEM" =~ ^[Ee]$ ]] || [[ -z "$UPDATE_SYSTEM" ]]; then
        echo "Sistem güncelleniyor..."
        apply_updates
        echo_success "Sistem güncellendi."
        {
            echo "[✓] Sistem güncellendi."
        } >> "$REPORT_FILE"
    fi
else
    echo_warn "Güncellemeler kontrol edilemedi: $UPDATES"
    {
        echo "[!] Güncellemeler kontrol edilemedi: $UPDATES"
    } >> "$REPORT_FILE"
fi

echo ""

# Çalışan Servisler Analizi
echo_info "Çalışan servisler analiz ediliyor..."
{
    echo "--- ÇALIŞAN SERVİSLER ---"
    systemctl list-units --type=service --state=running | grep ".service" | awk '{print $1}' >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

echo_success "Çalışan servisler analiz edildi."

echo ""

# Açık Portlar Kontrolü
echo_info "Açık portlar tespit ediliyor..."
{
    echo "--- AÇIK PORTLAR ---"
    if command -v netstat >/dev/null; then
        netstat -tuln | grep "LISTEN" >> "$REPORT_FILE"
    elif command -v ss >/dev/null; then
        ss -tuln >> "$REPORT_FILE"
    else
        echo "[!] Ağ araçları (netstat/ss) bulunamadı." >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

echo_success "Açık portlar tespit edildi."

echo ""

# Sudo Loglama Kontrolü
echo_info "Sudo loglama durumu kontrol ediliyor..."
{
    echo "--- SUDO LOGLAMA DURUMU ---"
} >> "$REPORT_FILE"

SUDOERS_INCLUDES="/etc/sudoers.d"
SUDO_LOG_ENABLED=false

if grep -q "Defaults.*logfile" /etc/sudoers 2>/dev/null; then
    SUDO_LOG_ENABLED=true
fi

if [ -d "$SUDOERS_INCLUDES" ]; then
    for file in "$SUDOERS_INCLUDES"/*; do
        if [ -f "$file" ] && grep -q "Defaults.*logfile" "$file" 2>/dev/null; then
            SUDO_LOG_ENABLED=true
        fi
    done
fi

if [ "$SUDO_LOG_ENABLED" = true ]; then
    echo_success "Sudo loglama aktif."
    {
        echo "[✓] Sudo loglama aktif."
    } >> "$REPORT_FILE"
else
    echo_warn "Sudo loglama aktif değil."
    {
        echo "[!] Sudo loglama aktif değil. Güvenlik ve denetim için etkinleştirilmesi önerilir."
        echo "    /etc/sudoers.d/99-logging dosyası oluşturularak etkinleştirilebilir:"
        echo "    Defaults logfile=/var/log/sudo.log"
    } >> "$REPORT_FILE"
fi

echo ""

# Parola Politikası Kontrolü
echo_info "Parola politikası kontrol ediliyor..."
{
    echo "--- PAROLA POLİTİKASI ---"
} >> "$REPORT_FILE"

case $DISTRO_FAMILY in
    debian)
        if command -v libpam-pwquality >/dev/null || grep -q "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null; then
            echo_success "Parola kalite kontrolü aktif."
            {
                echo "[✓] Parola kalite kontrolü aktif."
                echo "    Mevcut yapılandırma:"
                grep "pam_pwquality.so" /etc/pam.d/common-password >> "$REPORT_FILE"
            } >> "$REPORT_FILE"
        else
            echo_warn "Parola kalite kontrolü aktif değil."
            {
                echo "[!] Parola kalite kontrolü aktif değil. Güçlü parolalar için etkinleştirilmesi önerilir."
          echo "[!] Parola kalite kontrolü aktif değil. Güçlü parolalar için etkinleştirilmesi önerilir."
                echo "    Kurulum için: sudo apt install libpam-pwquality"
            } >> "$REPORT_FILE"
        fi
        ;;
    redhat)
        if grep -q "pam_pwquality.so" /etc/pam.d/system-auth 2>/dev/null; then
            echo_success "Parola kalite kontrolü aktif."
            {
                echo "[✓] Parola kalite kontrolü aktif."
                echo "    Mevcut yapılandırma:"
                grep "pam_pwquality.so" /etc/pam.d/system-auth >> "$REPORT_FILE"
            } >> "$REPORT_FILE"
        else
            echo_warn "Parola kalite kontrolü aktif değil."
            {
                echo "[!] Parola kalite kontrolü aktif değil. Güçlü parolalar için etkinleştirilmesi önerilir."
                echo "    Kurulum için: sudo dnf install libpwquality"
            } >> "$REPORT_FILE"
        fi
        ;;
    arch)
        if grep -q "pam_pwquality.so" /etc/pam.d/passwd 2>/dev/null; then
            echo_success "Parola kalite kontrolü aktif."
            {
                echo "[✓] Parola kalite kontrolü aktif."
                echo "    Mevcut yapılandırma:"
                grep "pam_pwquality.so" /etc/pam.d/passwd >> "$REPORT_FILE"
            } >> "$REPORT_FILE"
        else
            echo_warn "Parola kalite kontrolü aktif değil."
            {
                echo "[!] Parola kalite kontrolü aktif değil. Güçlü parolalar için etkinleştirilmesi önerilir."
                echo "    Kurulum için: sudo pacman -S libpwquality"
            } >> "$REPORT_FILE"
        fi
        ;;
    suse)
        if grep -q "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null; then
            echo_success "Parola kalite kontrolü aktif."
            {
                echo "[✓] Parola kalite kontrolü aktif."
                echo "    Mevcut yapılandırma:"
                grep "pam_pwquality.so" /etc/pam.d/common-password >> "$REPORT_FILE"
            } >> "$REPORT_FILE"
        else
            echo_warn "Parola kalite kontrolü aktif değil."
            {
                echo "[!] Parola kalite kontrolü aktif değil. Güçlü parolalar için etkinleştirilmesi önerilir."
                echo "    Kurulum için: sudo zypper install libpwquality"
            } >> "$REPORT_FILE"
        fi
        ;;
    *)
        echo_warn "Parola politikası bu dağıtımda kontrol edilemiyor: $DISTRO_FAMILY"
        {
            echo "[!] Parola politikası bu dağıtımda kontrol edilemiyor: $DISTRO_FAMILY"
        } >> "$REPORT_FILE"
        ;;
esac

echo ""

# SUID Dosyaları Kontrolü
echo_info "SUID dosyaları tespit ediliyor..."
{
    echo "--- SUID DOSYALARI ---"
    echo "SUID dosyalarının tam listesi rapor dosyasında bulunabilir."
} >> "$REPORT_FILE"

SUID_FILES=$(find / -type f -perm -4000 -ls 2>/dev/null)
echo "$SUID_FILES" >> "$REPORT_FILE"

SUID_COUNT=$(echo "$SUID_FILES" | wc -l)
echo_success "$SUID_COUNT adet SUID dosyası tespit edildi."

echo ""

# ===== PERFORMANS İZLEME =====
echo "===== PERFORMANS İZLEME ====="
{
    echo ""
    echo "===== PERFORMANS İZLEME ====="
    echo ""
} >> "$REPORT_FILE"

# Disk Alanı Kullanımı
echo_info "Disk alanı kullanımı kontrol ediliyor..."
{
    echo "--- DİSK ALANI KULLANIMI ---"
    df -h >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

ROOT_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$ROOT_USAGE" -gt 90 ]; then
    echo_warn "Kök dizin (/) %$ROOT_USAGE dolu! Kritik seviye."
elif [ "$ROOT_USAGE" -gt 80 ]; then
    echo_warn "Kök dizin (/) %$ROOT_USAGE dolu! Dikkat edilmeli."
else
    echo_success "Disk alanı kullanımı normal (%$ROOT_USAGE)."
fi

echo ""

# Bellek Kullanımı
echo_info "Bellek kullanımı kontrol ediliyor..."
{
    echo "--- BELLEK KULLANIMI ---"
    free -h >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

MEM_TOTAL=$(free | awk 'NR==2 {print $2}')
MEM_USED=$(free | awk 'NR==2 {print $3}')
MEM_USAGE=$((MEM_USED * 100 / MEM_TOTAL))

if [ "$MEM_USAGE" -gt 90 ]; then
    echo_warn "Bellek kullanımı %$MEM_USAGE! Kritik seviye."
elif [ "$MEM_USAGE" -gt 80 ]; then
    echo_warn "Bellek kullanımı %$MEM_USAGE! Dikkat edilmeli."
else
    echo_success "Bellek kullanımı normal (%$MEM_USAGE)."
fi

echo ""

# CPU Kullanımı
echo_info "CPU kullanımı kontrol ediliyor..."
{
    echo "--- CPU KULLANIMI ---"
    top -bn1 | head -20 >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

# CPU boşta kalma süresi, farklı dağıtımlarda farklı formatlarda olabilir
CPU_IDLE=$(top -bn1 | grep "%Cpu" | awk '{print $8}')
if [ -z "$CPU_IDLE" ]; then
    CPU_IDLE=$(top -bn1 | grep "%Cpu" | awk '{for(i=1;i<=NF;i++) if($i ~ /id/) {print $(i-1)}}')
fi

if [ -n "$CPU_IDLE" ]; then
    CPU_USAGE=$(echo "100 - $CPU_IDLE" | bc 2>/dev/null || echo "N/A")
else
    CPU_USAGE="N/A"
fi

if [ "$CPU_USAGE" != "N/A" ]; then
    if (( $(echo "$CPU_USAGE > 90" | bc -l) )); then
        echo_warn "CPU kullanımı %$CPU_USAGE! Kritik seviye."
    elif (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
        echo_warn "CPU kullanımı %$CPU_USAGE! Dikkat edilmeli."
    else
        echo_success "CPU kullanımı normal (%$CPU_USAGE)."
    fi
else
    echo_warn "CPU kullanımı hesaplanamadı."
fi

echo ""

# Aktif İnternet Bağlantıları
echo_info "Aktif internet bağlantıları kontrol ediliyor..."
{
    echo "--- AKTİF BAĞLANTILAR ---"
    if command -v netstat >/dev/null; then
        CONN_TOOL="netstat"
        netstat -an | grep "ESTABLISHED" | head -20 >> "$REPORT_FILE"
    elif command -v ss >/dev/null; then
        CONN_TOOL="ss"
        ss -tan | grep "ESTAB" | head -20 >> "$REPORT_FILE"
    else
        CONN_TOOL="none"
        echo "[!] Ağ araçları (netstat/ss) bulunamadı." >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

case $CONN_TOOL in
    netstat)
        CONN_COUNT=$(netstat -an 2>/dev/null | grep "ESTABLISHED" | wc -l || echo "N/A")
        ;;
    ss)
        CONN_COUNT=$(ss -tan 2>/dev/null | grep "ESTAB" | wc -l || echo "N/A")
        ;;
    *)
        CONN_COUNT="N/A"
        ;;
esac

if [ "$CONN_COUNT" != "N/A" ]; then
    echo_success "$CONN_COUNT aktif bağlantı tespit edildi."
else
    echo_warn "Aktif bağlantılar hesaplanamadı."
fi

echo ""

# Sistemin Yükleme Zamanı
echo_info "Sistem yükleme zamanı kontrol ediliyor..."
{
    echo "--- SİSTEM YÜKLEME ZAMANI ---"
    uptime >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
} >> "$REPORT_FILE"

UPTIME=$(uptime -p 2>/dev/null || uptime)
echo_success "Sistem yükleme zamanı: $UPTIME"

echo ""

# Ek dağıtım özel kontroller
case $DISTRO_FAMILY in
    debian)
        # Debian/Ubuntu özel kontrolleri
        echo_info "Debian/Ubuntu özel kontrolleri yapılıyor..."
        {
            echo "--- DEBIAN/UBUNTU ÖZEL KONTROLLERİ ---"
        } >> "$REPORT_FILE"
        
        # AppArmor durumu
        if command -v apparmor_status >/dev/null; then
            if apparmor_status | grep -q "apparmor module is loaded"; then
                echo_success "AppArmor yüklü ve aktif."
                {
                    echo "[✓] AppArmor yüklü ve aktif."
                } >> "$REPORT_FILE"
            else
                echo_warn "AppArmor yüklü fakat aktif değil."
                {
                    echo "[!] AppArmor yüklü fakat aktif değil."
                    echo "    Etkinleştirmek için: sudo systemctl enable --now apparmor"
                } >> "$REPORT_FILE"
            fi
        else
            echo_warn "AppArmor kurulu değil."
            {
                echo "[!] AppArmor kurulu değil. Ek güvenlik katmanı sağlar."
                echo "    Kurulum için: sudo apt install apparmor apparmor-utils"
            } >> "$REPORT_FILE"
        fi
        ;;
    redhat)
        # RHEL/CentOS/Fedora özel kontrolleri
        echo_info "RHEL/CentOS/Fedora özel kontrolleri yapılıyor..."
        {
            echo "--- RHEL/CENTOS/FEDORA ÖZEL KONTROLLERİ ---"
        } >> "$REPORT_FILE"
        
        # SELinux durumu
        if command -v getenforce >/dev/null; then
            SELINUX_STATUS=$(getenforce 2>/dev/null)
            if [ "$SELINUX_STATUS" = "Enforcing" ]; then
                echo_success "SELinux Enforcing modunda aktif."
                {
                    echo "[✓] SELinux Enforcing modunda aktif."
                } >> "$REPORT_FILE"
            elif [ "$SELINUX_STATUS" = "Permissive" ]; then
                echo_warn "SELinux Permissive modunda. Enforcing moduna geçilmesi önerilir."
                {
                    echo "[!] SELinux Permissive modunda. Enforcing moduna geçilmesi önerilir."
                    echo "    Değiştirmek için: sudo setenforce 1"
                    echo "    Kalıcı değişiklik için /etc/selinux/config dosyasını düzenleyin."
                } >> "$REPORT_FILE"
            else
                echo_warn "SELinux devre dışı."
                {
                    echo "[!] SELinux devre dışı. Güvenlik için etkinleştirilmesi önerilir."
                    echo "    /etc/selinux/config dosyasını düzenleyerek etkinleştirin."
                } >> "$REPORT_FILE"
            fi
        else
            echo_warn "SELinux kurulu değil veya kontrol edilemiyor."
            {
                echo "[!] SELinux kurulu değil veya kontrol edilemiyor."
            } >> "$REPORT_FILE"
        fi
        ;;
    arch)
        # Arch Linux özel kontrolleri
        echo_info "Arch Linux özel kontrolleri yapılıyor..."
        {
            echo "--- ARCH LINUX ÖZEL KONTROLLERİ ---"
        } >> "$REPORT_FILE"
        
        # Pacman güncel mi?
        if pacman -Qs pacman-contrib >/dev/null 2>&1; then
            echo_success "pacman-contrib paketi kurulu."
            {
                echo "[✓] pacman-contrib paketi kurulu."
            } >> "$REPORT_FILE"
        else
            echo_warn "pacman-contrib paketi kurulu değil."
            {
                echo "[!] pacman-contrib paketi kurulu değil. Paket yönetimi için yararlı araçlar içerir."
                echo "    Kurulum için: sudo pacman -S pacman-contrib"
            } >> "$REPORT_FILE"
        fi
        ;;
    suse)
        # SUSE/openSUSE özel kontrolleri
        echo_info "SUSE/openSUSE özel kontrolleri yapılıyor..."
        {
            echo "--- SUSE/OPENSUSE ÖZEL KONTROLLERİ ---"
        } >> "$REPORT_FILE"
        
        # AppArmor durumu (SUSE'de varsayılan olarak gelir)
        if command -v apparmor_status >/dev/null; then
            if apparmor_status | grep -q "apparmor module is loaded"; then
                echo_success "AppArmor yüklü ve aktif."
                {
                    echo "[✓] AppArmor yüklü ve aktif."
                } >> "$REPORT_FILE"
            else
                echo_warn "AppArmor yüklü fakat aktif değil."
                {
                    echo "[!] AppArmor yüklü fakat aktif değil."
                    echo "    Etkinleştirmek için: sudo systemctl enable --now apparmor"
                } >> "$REPORT_FILE"
            fi
        else
            echo_warn "AppArmor kurulu değil."
            {
                echo "[!] AppArmor kurulu değil. Ek güvenlik katmanı sağlar."
                echo "    Kurulum için: sudo zypper install apparmor-utils"
            } >> "$REPORT_FILE"
        fi
        ;;
esac

echo ""

# Sonuç Raporu
echo "===== SONUÇ RAPORU ====="
{
    echo ""
    echo "===== SONUÇ RAPORU ====="
    echo "Denetim tamamlandı. Ayrıntılı rapor: $REPORT_FILE"
    echo ""
} >> "$REPORT_FILE"

echo "Denetim tamamlandı. Ayrıntılı rapor: $REPORT_FILE"
echo ""
echo "Önemli güvenlik önerileri:"
echo "1. SSH ayarlarını güvenli hale getirin (root girişini kapatın, anahtar tabanlı doğrulama kullanın)"
echo "2. Güvenlik duvarını etkinleştirin ve yalnızca gerekli portlara izin verin"
echo "3. Fail2ban kurarak brute force saldırılarını engelleyin"
echo "4. Sistemi düzenli olarak güncelleyin"
echo "5. Güçlü parola politikası uygulayın"
echo ""
echo "VPS'inizi düzenli olarak denetlemeyi unutmayın!"
