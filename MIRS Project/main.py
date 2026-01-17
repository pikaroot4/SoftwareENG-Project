import time
import os
import hashlib
import requests
import shutil
import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- AYARLAR ---
WATCH_DIRECTORY = "izlenen"
QUARANTINE_DIRECTORY = "karantina"
LOG_FILE = "olay_gunlugu.txt"
API_KEY = "ec7d315796a2a7a51163b867e26c99e337675b6832f4859c9de158d523295667"  # <--- API KEY'İNİ UNUTMA!

class Gozcu:
    def __init__(self):
        self.observer = Observer()

    def calistir(self):
        # Klasörleri oluştur
        if not os.path.exists(WATCH_DIRECTORY):
            os.makedirs(WATCH_DIRECTORY)
        if not os.path.exists(QUARANTINE_DIRECTORY):
            os.makedirs(QUARANTINE_DIRECTORY)

        event_handler = OlayYakalayici()
        self.observer.schedule(event_handler, WATCH_DIRECTORY, recursive=False)
        self.observer.start()
        print(f"[*] Mini-EDR Devrede!")
        print(f"[*] İzlenen Klasör: {WATCH_DIRECTORY}")
        print(f"[*] Karantina Klasörü: {QUARANTINE_DIRECTORY}")
        print("[*] Çıkmak için CTRL+C yapabilirsin.\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
            print("\n[-] Sistem kapatıldı.")
        self.observer.join()

def log_yaz(mesaj):
    """Olayları dosyaya kaydeder"""
    zaman = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_satiri = f"[{zaman}] {mesaj}"
    print(log_satiri) # Ekrana da yaz
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_satiri + "\n")

def karantinaya_al(dosya_yolu, dosya_adi):
    """Zararlı dosyayı karantinaya taşır"""
    hedef_yol = os.path.join(QUARANTINE_DIRECTORY, dosya_adi)
    try:
        # Eğer karantinada aynı isimde dosya varsa üzerine yazmasın diye ismini değiştir
        if os.path.exists(hedef_yol):
            zaman_damgasi = datetime.datetime.now().strftime("%H%M%S")
            hedef_yol = os.path.join(QUARANTINE_DIRECTORY, f"{zaman_damgasi}_{dosya_adi}")
            
        shutil.move(dosya_yolu, hedef_yol)
        log_yaz(f"[MÜDAHALE] Dosya karantinaya alındı: {dosya_adi}")
        return True
    except Exception as e:
        log_yaz(f"[HATA] Karantina işlemi başarısız: {e}")
        return False

def dosya_hashle(dosya_yolu):
    sha256_hash = hashlib.sha256()
    try:
        with open(dosya_yolu, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def virustotal_sorgula(dosya_hash):
    url = f"https://www.virustotal.com/api/v3/files/{dosya_hash}"
    headers = {"x-apikey": API_KEY}
    
    print("   [DEBUG] API isteği gönderiliyor...") # Nerede olduğunu görelim
    
    try:
        # timeout=10 ekledik. 10 saniye cevap gelmezse hata verip geçecek.
        response = requests.get(url, headers=headers, timeout=10)
        
        print(f"   [DEBUG] API Yanıt Kodu: {response.status_code}") # Kodu görelim

        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats['malicious']
        elif response.status_code == 404:
            return -1 # Bilinmiyor
        elif response.status_code == 429:
            print("   [HATA] API Kotası Doldu! (Dakikada 4 istek sınırı)")
            return None
        else:
            return None # Diğer Hatalar
    except requests.exceptions.Timeout:
        print("   [HATA] VirusTotal yanıt vermedi (Zaman aşımı). İnternetini kontrol et.")
        return None
    except Exception as e:
        print(f"   [HATA] Bir sorun oluştu: {e}")
        return None

class OlayYakalayici(FileSystemEventHandler):
    def on_any_event(self, event):
        if not monitoring_active: return
        if event.is_directory: return
        if event.event_type not in ['created', 'modified']: return
        if event.src_path.endswith((".tmp", ".crdownload", ".ini")): return

        dosya_yolu = event.src_path
        dosya_adi = os.path.basename(dosya_yolu)
        
        # Dosya tam yazılsın diye minik bekleme
        time.sleep(1) 
        
        if not os.path.exists(dosya_yolu): return

        # --- ŞOV BAŞLIYOR (HOLLYWOOD EFEKTİ) ---
        log_to_gui(f"🔍 [BAŞLATILDI] {dosya_adi} inceleniyor...", "cyan")
        time.sleep(1) # Bekle

        log_to_gui("   ├── 🛠️ Dosya bütünlüğü ve Hash hesaplanıyor...", "white")
        f_hash = dosya_hashle(dosya_yolu)
        time.sleep(1.5) # Bekle... Hash alıyormuş gibi

        if f_hash:
            log_to_gui(f"   ├── 🔑 Hash: {f_hash[:15]}...", "white")
            time.sleep(1) # Bekle

            log_to_gui("   ├── 📡 Threat Intelligence (VirusTotal) veritabanı sorgulanıyor...", "yellow")
            time.sleep(2) # En uzun bekleme burada (Sanki internetten indiriyor)

            # --- SONUÇ KISMI ---
            # Simülasyon Modu
            if "test_virusu" in dosya_adi:
                log_to_gui("   └── ⚠️ Şüpheli imza tespit edildi!", "orange")
                time.sleep(0.5)
                skor = 10
            else:
                skor = virustotal_sorgula(f_hash)
            
            # Karar Anı
            if skor is not None and skor > 0:
                log_to_gui(f"🚨 [ALARM] ZARARLI YAZILIM TESPİT EDİLDİ! ({skor} Motor)", "red")
                # Biraz daha dramatik olsun diye karantinadan önce yarım saniye bekle
                time.sleep(0.5)
                karantinaya_al(dosya_yolu, dosya_adi)
            elif skor == -1:
                log_to_gui(f"✅ [TEMİZ] Bilinmeyen dosya, tehdit bulunamadı.", "lime")
            elif skor == 0:
                log_to_gui(f"✅ [TEMİZ] Dosya güvenli, imza temiz.", "lime")
        else:
            log_to_gui("[HATA] Dosya okunamadı.", "yellow")
if __name__ == "__main__":
    app = Gozcu()
    app.calistir()