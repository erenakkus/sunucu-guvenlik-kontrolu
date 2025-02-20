# VPS Güvenlik Denetimi Scripti

VPS (Sanal Özel Sunucu) güvenliği ve performansını denetlemek için kapsamlı bir Bash scripti. Bu araç, çeşitli güvenlik kontrolleri yapar ve iyileştirmeler için ayrıntılı bir rapor sunar.

## Özellikler

### Güvenlik Kontrolleri

- **SSH Yapılandırması**
  - Root girişi durumu
  - Parola doğrulama
  - Varsayılan port kullanımı
- **Güvenlik Duvarı Durumu (UFW)**
- **Fail2ban Yapılandırması**
  - Başarısız giriş denemeleri
- **Sistem Güncellemeleri Durumu**
- **Çalışan Servisler Analizi**
- **Açık Portlar Tespiti**
- **Sudo Loglama Yapılandırması**
- **Parola Politikası Zorunluluğu**
- **SUID Dosyaları Tespiti**

### Performans İzleme

- **Disk Alanı Kullanımı**
- **Bellek Kullanımı**
- **CPU Kullanımı**
- **Aktif İnternet Bağlantıları**

## Gereksinimler

- Ubuntu/Debian tabanlı Linux sistemi
- Root erişimi veya sudo ayrıcalıkları
- Temel paketler (çoğu önceden yüklü):
  - ufw
  - systemd
  - netstat
  - grep
  - awk

## Kurulum

### Script'i İndirme

Script'i aşağıdaki komut ile indirebilirsiniz:

```bash
wget https://raw.githubusercontent.com/erenakkus/sunucu-guvenlik-kontrolu/b5f6735d0eba08e6a42f56ef0ebcf075ca053e46/en-start-control.sh
```


Script’i Çalıştırılabilir Yapma
Script’i çalıştırılabilir hale getirmek için:

```bash
chmod +x en-start-control.sh
```

##Script'in Çalıştırılması
###Script'i çalıştırın:

```bash
bash en-start-control.sh
```

##Script, aşağıdaki işlemleri yapacaktır:

Tüm güvenlik kontrollerini gerçekleştirir
Sonuçları renkli şekilde gerçek zamanlı gösterir:
Çıktı Formatı
Gerçek Zamanlı Konsol Çıktısı
Tüm kontrol sonuçları
Başarısız kontroller için spesifik öneriler
Sistem kaynak kullanım istatistikleri
Denetim zaman damgası
Eşikler
Kaynak Kullanım Eşikleri
Çalışan Servisler:
Özelleştirme
Script'teki aşağıdaki değişkenleri düzenleyerek eşikleri değiştirebilirsiniz:

Kaynak kullanım eşikleri
Başarısız giriş denemesi eşikleri
Servis sayısı eşikleri
Açık port eşikleri
En İyi Uygulamalar
Denetimi düzenli olarak çalıştırın (örneğin, haftalık)
Oluşturulan raporu dikkatlice inceleyin
FAIL durumu görülen kontrolleri hemen çözün
WARN durumu görülen kontrolleri bakım sırasında inceleyin
Script’i güvenlik politikalarınıza göre güncel tutun
Sınırlamalar
Sadece Debian/Ubuntu ve RHEL tabanlı sistemler için tasarlanmıştır
Root/sudo erişimi gerektirir
Bazı kontroller, belirli ortamlar için özelleştirilebilir
Profesyonel güvenlik denetiminin yerine geçmez

###Katkı
Sorunlar ve iyileştirme talepleri göndermekten çekinmeyin!

###Lisans
Bu proje GNU Lisansı altında lisanslanmıştır - detaylar için LICENSE dosyasını inceleyin.

###Güvenlik Uyarısı
Bu script, yaygın güvenlik sorunlarını tespit etmeye yardımcı olur, ancak tek başına güvenlik önleminiz olmamalıdır. Her zaman:

Sisteminizi güncel tutun
Logları düzenli olarak izleyin
Güvenlik en iyi uygulamalarını takip edin
Kritik sistemler için profesyonel güvenlik denetimleri yaptırın
Destek
Destek için: eren@erenakkus.net

Script çıktısını ve sistem bilgilerinizi sağlayın
Güvende kalın! 🔒

