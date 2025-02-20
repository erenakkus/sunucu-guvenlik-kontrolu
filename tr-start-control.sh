#!/bin/bash

# Renkler tanımlanıyor
KIRMIZI='\033[0;31m'
YESIL='\033[0;32m'
SARI='\033[0;33m'
MAVI='\033[0;34m'
Beyaz='\033[0m'

# Satürn çizimi
clear
echo -e "${MAVI}
               _______
         _.-'       \`-._
       .'               \`.
     _/                   \_
    /  .-"""-.     .-"""-.  \
   /  /       \   /       \  \
  |   |       |   |       |   |
  |   |       |   |       |   |
   \  \       /   \       /  /
    \_`._   .'     `._   _.'
       \`-._         _.-'
           \`-.___.-' 
  ${YESIL}DESIGNED BY EREN (G4L1LEO) AKKUŞ™${Beyaz}
"

# Kullanıcıya dil seçimi soruluyor
echo -e "${MAVI}Dil Seçin: (1) Türkçe (2) English${Beyaz}"
read -p "Seçiminizi yapın (1/2): " LANG_CHOICE

# Eğer Türkçe seçildiyse
if [ "$LANG_CHOICE" -eq 1 ]; then
    LANG="TR"
    mesaj_turkce() {
        echo -e "$1"
    }
elif [ "$LANG_CHOICE" -eq 2 ]; then
    LANG="EN"
    mesaj_ingilizce() {
        echo -e "$1"
    }
else
    echo -e "${KIRMIZI}Geçersiz seçim!${Beyaz}"
    exit 1
fi

# Fonksiyon: Mesajları yavaşça yazdırma
yazdir() {
    if [ "$LANG" == "TR" ]; then
        mesaj_turkce "$1"
    else
        mesaj_ingilizce "$1"
    fi
    sleep 1  # 1 saniye bekleme
}

# Sistem bilgilerini yazdırma
SYSTEM_INFO=$(uname -a)
IP_INFO=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)

yazdir "${MAVI}İşletim Sistemi: $SYSTEM_INFO${Beyaz}"
yazdir "${MAVI}IP Adresi: $IP_INFO${Beyaz}"
yazdir "${MAVI}Bilgisayar Adı: $HOSTNAME${Beyaz}"

# Sistem tipi kontrol ediliyor
if [ -f /etc/debian_version ]; then
    DISTRO="Debian"
    yazdir "${MAVI}Debian tabanlı sistem tespit edildi.${Beyaz}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="RHEL"
    yazdir "${MAVI}RHEL tabanlı sistem tespit edildi.${Beyaz}"
else
    yazdir "${KIRMIZI}Desteklenmeyen bir sistem!${Beyaz}"
    exit 1
fi

# Başlangıç mesajı
yazdir "${MAVI}Kontroller başlatılıyor...${Beyaz}"

# 1. SSH Yapılandırması
yazdir "${MAVI}SSH Yapılandırması Kontrol Ediliyor...${Beyaz}"

# Root login durumu
ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$ROOT_LOGIN" != "no" ]; then
    yazdir "${KIRMIZI}HATA: Root girişi etkin!${Beyaz}"
    yazdir "${KIRMIZI}Çözüm: /etc/ssh/sshd_config dosyasını açın ve 'PermitRootLogin no' olarak değiştirin.${Beyaz}"
else
    yazdir "${YESIL}TAMAM: Root girişi devre dışı.${Beyaz}"
fi

# Parola ile kimlik doğrulama
PASSWORD_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$PASSWORD_AUTH" != "no" ]; then
    yazdir "${KIRMIZI}HATA: Parola ile kimlik doğrulama etkin!${Beyaz}"
    yazdir "${KIRMIZI}Çözüm: /etc/ssh/sshd_config dosyasını açın ve 'PasswordAuthentication no' olarak değiştirin.${Beyaz}"
else
    yazdir "${YESIL}TAMAM: Parola ile kimlik doğrulama devre dışı.${Beyaz}"
fi

# Varsayılan port kullanımı
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$SSH_PORT" == "22" ]; then
    yazdir "${SARI}Uyarı: SSH varsayılan 22. portu üzerinde çalışıyor!${Beyaz}"
    yazdir "${SARI}Çözüm: SSH portunu değiştirmek için /etc/ssh/sshd_config dosyasına yeni bir port numarası girin.${Beyaz}"
else
    yazdir "${YESIL}TAMAM: SSH portu değiştirildi.${Beyaz}"
fi

# 2. Güvenlik Duvarı (Firewall) Durumu Kontrolü
yazdir "${MAVI}Firewall Durumu Kontrol Ediliyor...${Beyaz}"

if [ "$DISTRO" == "Debian" ]; then
    UFW_STATUS=$(ufw status | grep "Status" | awk '{print $2}')
    if [ "$UFW_STATUS" != "active" ]; then
        yazdir "${KIRMIZI}HATA: UFW etkin değil!${Beyaz}"
        yazdir "${KIRMIZI}Çözüm: UFW'yi etkinleştirin. Komut: sudo ufw enable${Beyaz}"
    else
        yazdir "${YESIL}TAMAM: UFW etkin.${Beyaz}"
    fi
elif [ "$DISTRO" == "RHEL" ]; then
    FIREWALL_STATUS=$(systemctl is-active firewalld)
    if [ "$FIREWALL_STATUS" != "active" ]; then
        yazdir "${KIRMIZI}HATA: Firewalld etkin değil!${Beyaz}"
        yazdir "${KIRMIZI}Çözüm: Firewalld'yi etkinleştirin. Komut: sudo systemctl enable --now firewalld${Beyaz}"
    else
        yazdir "${YESIL}TAMAM: Firewalld etkin.${Beyaz}"
    fi
else
    yazdir "${KIRMIZI}Güvenlik duvarı türü tespit edilemedi.${Beyaz}"
fi

# 3. Fail2ban Yapılandırması
yazdir "${MAVI}Fail2ban Yapılandırması Kontrol Ediliyor...${Beyaz}"

FAIL2BAN_STATUS=$(systemctl is-active fail2ban)
if [ "$FAIL2BAN_STATUS" != "active" ]; then
    yazdir "${KIRMIZI}HATA: Fail2ban etkin değil!${Beyaz}"
    yazdir "${KIRMIZI}Çözüm: Fail2ban'ı etkinleştirin. Komut: sudo systemctl enable --now fail2ban${Beyaz}"
else
    yazdir "${YESIL}TAMAM: Fail2ban etkin.${Beyaz}"
fi

# 4. Güncellemeler Durumu
yazdir "${MAVI}Sistem Güncellemeleri Kontrol Ediliyor...${Beyaz}"

if [ "$DISTRO" == "Debian" ]; then
    UPDATE_STATUS=$(apt-get -s upgrade | grep "upgraded,")
    if [ -z "$UPDATE_STATUS" ]; then
        yazdir "${YESIL}TAMAM: Sistem güncel.${Beyaz}"
    else
        yazdir "${KIRMIZI}HATA: Güncellemeler mevcut!${Beyaz}"
        yazdir "${KIRMIZI}Çözüm: Güncellemeleri yapın. Komut: sudo apt-get update && sudo apt-get upgrade${Beyaz}"
    fi
elif [ "$DISTRO" == "RHEL" ]; then
    UPDATE_STATUS=$(yum check-update | grep "updates")
    if [ -z "$UPDATE_STATUS" ]; then
        yazdir "${YESIL}TAMAM: Sistem güncel.${Beyaz}"
    else
        yazdir "${KIRMIZI}HATA: Güncellemeler mevcut!${Beyaz}"
        yazdir "${KIRMIZI}Çözüm: Güncellemeleri yapın. Komut: sudo yum update${Beyaz}"
    fi
fi

# 5. Performans İzleme
yazdir "${MAVI}Performans Durumu Kontrol Ediliyor...${Beyaz}"

# Disk Alanı
DISK_SPACE=$(df -h / | grep -v Filesystem | awk '{print $5}')
yazdir "${MAVI}Disk Alanı Kullanımı: $DISK_SPACE${Beyaz}"

# Bellek Kullanımı
MEMORY_USAGE=$(free -h | grep Mem | awk '{print $3 "/" $2}')
yazdir "${MAVI}Bellek Kullanımı: $MEMORY_USAGE${Beyaz}"

# CPU Kullanımı
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
yazdir "${MAVI}CPU Kullanımı: $CPU_USAGE%${Beyaz}"

# 6. Güvenlik Tavsiyeleri ve Çözümler
yazdir "${YESIL}TAMAM: Güvenlik ve performans kontrolleri tamamlandı.${Beyaz}"

# Çözümler:
yazdir "${YESIL}Yapılabilecekler:${Beyaz}"
yazdir "${YESIL}- SSH root girişini devre dışı bırakın ve parola ile kimlik doğrulamasını kapatın.${Beyaz}"
yazdir "${YESIL}- Varsayılan SSH portunu değiştirin.${Beyaz}"
yazdir "${YESIL}- UFW'yi etkinleştirin (Debian) veya Firewalld'yi etkinleştirin (RHEL).${Beyaz}"
yazdir "${YESIL}- Fail2ban'ı etkinleştirin.${Beyaz}"
yazdir "${YESIL}- Sistem güncellemelerini düzenli olarak yapın.${Beyaz}"

# Kullanıcıya güncellemeleri yapıp yapmayacağını soruyoruz
yazdir "${SARI}Güvenlik güncellemelerini otomatik olarak uygulamak ister misiniz? (Evet/Hayır)${Beyaz}"
read -p "Cevabınızı girin: " GUNCELLEME
if [[ "$GUNCELLEME" == "Evet" || "$GUNCELLEME" == "evet" ]]; then
    yazdir "${YESIL}Güncellemeler başlatılıyor...${Beyaz}"
    if [ "$DISTRO" == "Debian" ]; then
        sudo apt-get update && sudo apt-get upgrade -y
    elif [ "$DISTRO" == "RHEL" ]; then
        sudo yum update -y
    fi
else
    yazdir "${MAVI}Güncellemeler atlandı.${Beyaz}"
fi
