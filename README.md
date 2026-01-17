# SoftwareENG-Project
Malware Incident Response System 

Projede ki sistem bir demo sürümdür. Geliştirilmeye devam etmektedir.

Projede EICAR Kullanılmaktadır fakat sisteminizde herhangi bir virüs programı veya Windows güvenlik duvarı açık olursa diye 
sistemde karantinaya alınmasını istediğimiz durumda 'test_virusu.txt' diye bir dosya açıp yüklediğimizde sistem karantiyana almaktadır.

Sistem log kayıtlarını tutup 'PDF Rapor Al' tıkladığında ise PDF olarak rapor çıktısı vermektedir.

Sistem VIRUSTOTAL üstünden API olarak koruma almaktadır.
API_KEY = "BURAYA_API_KEY_GELECEK"  # <--- API KEY BURAYA!
Kısmından API'dan hizmet alınmaktadır. Lütfen kendi API keyinizi  VIRUSTOTAL'den alarak işlem yapınız.

HoneyPot çalışma mantığı.

Tuzaklama (The Decoy): Ağ üzerinde gerçek bir sunucu, veritabanı veya IoT cihazı gibi görünen sahte bir sistem kurulur.

Zafiyet Simülasyonu: Bu sisteme bilerek "kolay lokma" izlenimi verilir. Örneğin:

Zayıf şifreli bir SSH portu (admin / 123456).

Yamanmamış (eski sürüm) bir Windows sunucusu.

"Müşteri_Verileri.sql" gibi ilgi çekici dosya isimleri.

İzleme ve Loglama (Monitoring): Saldırgan tuzağa düştüğünde sistem alarm vermez, aksine saldırganın "içeride" olduğunu sanmasına izin verir. Arka planda ise saldırganın her tuş vuruşu (keystroke), yüklediği dosyalar ve kullandığı komutlar kaydedilir.

İzolasyon: Honey Pot, gerçek ağdan (Production Network) izole edilmiştir. Saldırgan içeride at koşturduğunu sanırken aslında sanal bir fanusun içindedir ve gerçek verilere ulaşamaz.
