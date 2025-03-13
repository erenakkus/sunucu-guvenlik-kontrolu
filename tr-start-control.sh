#!/bin/bash

# Renk tanımlamaları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
WHITE='\033[0m'

# Saturn çizimi
clear
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

# İşlem kayıtlarını tutacak değişken
LOG=""

# Dil seçimi
echo -e "${BLUE}Dil Seçin: (1) Türkçe (2) English${WHITE}"
read -p "Seçiminiz (1/2): " LANG_CHOICE

if [ "$LANG_CHOICE" -eq 1 ]; then
    LANG="TR"
elif [ "$LANG_CHOICE" -eq 2 ]; then
    LANG="EN"
else
    echo -e "${RED}Geçersiz seçim!${WHITE}"
    exit 1
fi

# Sistem bilgilerini al
SYSTEM_INFO=$(uname -a)
IP_INFO=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)

LOG+="\n${BLUE}İşletim Sistemi: $SYSTEM_INFO${WHITE}"
LOG+="\n${BLUE}IP Adresi: $IP_INFO${WHITE}"
LOG+="\n${BLUE}Bilgisayar Adı: $HOSTNAME${WHITE}"

# İşletim sistemi türünü belirleme
if [ -f /etc/debian_version ]; then
    DISTRO="Debian"
    LOG+="\n${GREEN}Debian tabanlı sistem tespit edildi.${WHITE}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="RHEL"
    LOG+="\n${GREEN}RHEL tabanlı sistem tespit edildi.${WHITE}"
else
    LOG+="\n${RED}Desteklenmeyen sistem!${WHITE}"
    echo -e "$LOG"
    exit 1
fi

# SSH Konfigürasyonu
ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
PASSWORD_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')

if [ "$ROOT_LOGIN" != "no" ]; then
    LOG+="\n${RED}HATA: Root girişi etkin!${WHITE}"
else
    LOG+="\n${GREEN}OK: Root girişi devre dışı.${WHITE}"
fi

if [ "$PASSWORD_AUTH" != "no" ]; then
    LOG+="\n${RED}HATA: Parola ile kimlik doğrulama etkin!${WHITE}"
else
    LOG+="\n${GREEN}OK: Parola ile giriş kapalı.${WHITE}"
fi

if [ "$SSH_PORT" == "22" ]; then
    LOG+="\n${YELLOW}Uyarı: SSH varsayılan port 22'de çalışıyor!${WHITE}"
else
    LOG+="\n${GREEN}OK: SSH portu değiştirilmiş.${WHITE}"
fi

# Güvenlik duvarı kontrolü
if [ "$DISTRO" == "Debian" ]; then
    UFW_STATUS=$(ufw status | grep "Status" | awk '{print $2}')
    if [ "$UFW_STATUS" != "active" ]; then
        LOG+="\n${RED}HATA: UFW etkin değil!${WHITE}"
    else
        LOG+="\n${GREEN}OK: UFW etkin.${WHITE}"
    fi
elif [ "$DISTRO" == "RHEL" ]; then
    FIREWALL_STATUS=$(systemctl is-active firewalld)
    if [ "$FIREWALL_STATUS" != "active" ]; then
        LOG+="\n${RED}HATA: Firewalld etkin değil!${WHITE}"
    else
        LOG+="\n${GREEN}OK: Firewalld etkin.${WHITE}"
    fi
fi

# Fail2ban kontrolü
FAIL2BAN_STATUS=$(systemctl is-active fail2ban)
if [ "$FAIL2BAN_STATUS" != "active" ]; then
    LOG+="\n${RED}HATA: Fail2ban etkin değil!${WHITE}"
else
    LOG+="\n${GREEN}OK: Fail2ban etkin.${WHITE}"
fi

# Güncelleme durumu
if [ "$DISTRO" == "Debian" ]; then
    UPDATE_STATUS=$(apt-get -s upgrade | grep "upgraded," | wc -l)
    if [ "$UPDATE_STATUS" -eq 0 ]; then
        LOG+="\n${GREEN}OK: Sistem güncel.${WHITE}"
    else
        LOG+="\n${RED}GÜNCELLEME GEREKLİ!${WHITE}"
    fi
elif [ "$DISTRO" == "RHEL" ]; then
    UPDATE_STATUS=$(yum check-update | wc -l)
    if [ "$UPDATE_STATUS" -eq 0 ]; then
        LOG+="\n${GREEN}OK: Sistem güncel.${WHITE}"
    else
        LOG+="\n${RED}GÜNCELLEME GEREKLİ!${WHITE}"
    fi
fi

# Performans bilgileri
DISK_SPACE=$(df -h / | grep -v Filesystem | awk '{print $5}')
MEMORY_USAGE=$(free -h | grep Mem | awk '{print $3 "/" $2}')
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')

LOG+="\n${BLUE}Disk Kullanımı: $DISK_SPACE${WHITE}"
LOG+="\n${BLUE}RAM Kullanımı: $MEMORY_USAGE${WHITE}"
LOG+="\n${BLUE}CPU Kullanımı: $CPU_USAGE%${WHITE}"

# Güvenlik tavsiyeleri
LOG+="\n\n${GREEN}Önerilen işlemler:${WHITE}"
LOG+="\n- SSH root girişini kapatın."
LOG+="\n- SSH için parola girişini devre dışı bırakın."
LOG+="\n- Varsayılan SSH portunu değiştirin."
LOG+="\n- Güvenlik duvarını etkinleştirin (UFW veya Firewalld)."
LOG+="\n- Fail2ban'ı aktif hale getirin."
LOG+="\n- Sistem güncellemelerini düzenli yapın."

# Güncellemeleri uygulama seçeneği
echo -e "${YELLOW}Güvenlik güncellemeleri otomatik uygulansın mı? (Evet/Hayır)${WHITE}"
read -p "Seçiminiz: " UPDATE_ANSWER
if [[ "$UPDATE_ANSWER" == "Evet" || "$UPDATE_ANSWER" == "evet" ]]; then
    LOG+="\n${GREEN}Sistem güncelleniyor...${WHITE}"
    if [ "$DISTRO" == "Debian" ]; then
        sudo apt-get update && sudo apt-get upgrade -y
    elif [ "$DISTRO" == "RHEL" ]; then
        sudo yum update -y
    fi
else
    LOG+="\n${BLUE}Güncellemeler atlandı.${WHITE}"
fi

# Tüm işlemleri liste halinde gösterme
echo -e "$LOG"
