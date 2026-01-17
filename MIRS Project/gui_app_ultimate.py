import os
import time
import hashlib
import requests
import shutil
import datetime
import threading
import winsound  # Ses için (Sadece Windows)
import customtkinter as ctk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tkinter import filedialog, messagebox
from fpdf import FPDF  # PDF Raporu için

# --- AYARLAR ---
WATCH_DIRECTORY = "izlenen"
QUARANTINE_DIRECTORY = "karantina"
HONEYPOT_DIRECTORY = "BAL_KUPU_GIZLI" # Tuzak Klasör
LOG_FILE = "olay_gunlugu.txt"
API_KEY = "BURAYA_API_KEY_GELECEK"  # <--- API KEY BURAYA!

# --- BEYAZ LİSTE (Bu dosyalara asla dokunulmaz) ---
BEYAZ_LISTE = ["sirket_verisi.docx", "guvenli_uygulama.exe", "yonetici_notu.txt"]

# --- GLOBAL DEĞİŞKENLER ---
monitoring_active = False
observer = None
total_scanned = 0
threats_blocked = 0
incident_history = [] # PDF Raporu için hafıza

# Arayüz Ayarları
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class MiniEDRApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛡️ SENTINEL v4.0 - ULTIMATE EDITION")
        self.geometry("1000x650")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SOL MENÜ ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_lbl = ctk.CTkLabel(self.sidebar, text="SENTINEL\nSECURITY", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_lbl.pack(pady=(30, 20))

        self.switch_var = ctk.StringVar(value="off")
        self.switch = ctk.CTkSwitch(self.sidebar, text="Korumayı Başlat", command=self.toggle_monitoring,
                                    variable=self.switch_var, onvalue="on", offvalue="off")
        self.switch.pack(pady=15)

        self.btn_scan = ctk.CTkButton(self.sidebar, text="📂 Manuel Tarama", command=self.manuel_tarama_baslat)
        self.btn_scan.pack(pady=10, padx=20)

        # PDF Rapor Butonu (YENİ)
        self.btn_report = ctk.CTkButton(self.sidebar, text="📄 PDF Raporu Al", command=self.rapor_olustur, fg_color="#E07A5F")
        self.btn_report.pack(pady=10, padx=20)

        self.lbl_info = ctk.CTkLabel(self.sidebar, text="v4.0 Ultimate\n+Honeypot\n+Whitelist", text_color="gray", font=("Arial", 10))
        self.lbl_info.pack(side="bottom", pady=20)

        # --- SAĞ ANA EKRAN ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        # İstatistik Kartları
        self.stats_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.stats_frame.pack(fill="x", pady=(0, 20))

        self.create_stat_card("ANALİZ EDİLEN", "0", "#1f6aa5", self.stats_frame, "lbl_scanned")
        self.create_stat_card("ENGELLENEN", "0", "#d32f2f", self.stats_frame, "lbl_threat")
        self.create_stat_card("HoneyPot", "Online", "#ffa500", self.stats_frame, "lbl_honey")

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self.main_frame)
        self.progress.pack(fill="x", pady=(0, 10))
        self.progress.set(0)

        self.status_lbl = ctk.CTkLabel(self.main_frame, text="Sistem Hazır", anchor="w")
        self.status_lbl.pack(fill="x")

        # Log Ekranı
        self.log_box = ctk.CTkTextbox(self.main_frame, font=("Consolas", 11))
        self.log_box.pack(fill="both", expand=True, pady=(10, 0))
        self.log_yaz("Sistem başlatıldı. Bekleniyor...", "INFO")

    def create_stat_card(self, title, value, color, parent, attr_name):
        card = ctk.CTkFrame(parent, fg_color="#2B2B2B")
        card.pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkLabel(card, text=title, font=("Arial", 11)).pack(pady=(10,0))
        lbl = ctk.CTkLabel(card, text=value, font=("Arial", 28, "bold"), text_color=color)
        lbl.pack(pady=(0,10))
        setattr(self, attr_name, lbl)

    # --- FONKSİYONLAR ---
    def log_yaz(self, mesaj, tur="INFO"):
        zaman = datetime.datetime.now().strftime("%H:%M:%S")
        ikon = {"INFO": "ℹ️", "WARN": "⚠️", "DANGER": "🚨", "SUCCESS": "✅", "HONEY": "🍯"}.get(tur, "ℹ️")
        full_msg = f"[{zaman}] {ikon} {mesaj}\n"
        self.log_box.insert("end", full_msg)
        self.log_box.see("end")
        
        # Olay geçmişine ekle (PDF için)
        incident_history.append({"time": zaman, "msg": mesaj, "type": tur})

    def alarm_cal(self):
        # Arka planda ses çalar (UI donmasın diye thread içinde)
        def sound_thread():
            try:
                # 3 kısa bip sesi (Siren efekti)
                for _ in range(3):
                    winsound.Beep(1000, 200)
                    winsound.Beep(1500, 200)
            except: pass
        threading.Thread(target=sound_thread, daemon=True).start()

    def rapor_olustur(self):
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt="SENTINEL EDR - OLAY RAPORU", ln=1, align='C')
            pdf.cell(200, 10, txt=f"Tarih: {datetime.datetime.now()}", ln=1, align='C')
            pdf.ln(10)

            for olay in incident_history:
                pdf.set_text_color(0, 0, 0)
                if olay["type"] == "DANGER": pdf.set_text_color(255, 0, 0)
                if olay["type"] == "HONEY": pdf.set_text_color(255, 165, 0)
                
                # Türkçe karakter sorunu olmasın diye basit ASCII çeviri (Demo için)
                clean_msg = olay["msg"].encode('latin-1', 'replace').decode('latin-1')
                pdf.cell(0, 10, txt=f"[{olay['time']}] [{olay['type']}] {clean_msg}", ln=1)

            filename = f"Rapor_{datetime.datetime.now().strftime('%H%M%S')}.pdf"
            pdf.output(filename)
            messagebox.showinfo("Rapor", f"PDF Raporu oluşturuldu:\n{filename}")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def toggle_monitoring(self):
        if self.switch_var.get() == "on":
            self.monitor_thread_baslat()
            self.switch.configure(text="Korumayı Durdur")
        else:
            self.sistemi_durdur()
            self.switch.configure(text="Korumayı Başlat")

    def monitor_thread_baslat(self):
        global monitoring_active
        if not monitoring_active:
            threading.Thread(target=self.gozcu_baslat, daemon=True).start()

    def gozcu_baslat(self):
        global observer, monitoring_active
        # Klasörleri oluştur
        for d in [WATCH_DIRECTORY, QUARANTINE_DIRECTORY, HONEYPOT_DIRECTORY]:
            if not os.path.exists(d): os.makedirs(d)

        event_handler = OlayYakalayici(self)
        observer = Observer()
        # İki klasörü de izle: Normal izlenen ve Bal Küpü
        observer.schedule(event_handler, WATCH_DIRECTORY, recursive=False)
        observer.schedule(event_handler, HONEYPOT_DIRECTORY, recursive=False)
        
        observer.start()
        monitoring_active = True
        self.log_yaz("Gerçek Zamanlı Koruma & Honeypot Aktif", "SUCCESS")
        self.status_lbl.configure(text="DURUM: Real-Time Protection + Honeypot", text_color="#00ff00")

    def sistemi_durdur(self):
        global monitoring_active, observer
        if monitoring_active and observer:
            observer.stop()
            observer.join()
            monitoring_active = False
            self.log_yaz("Sistem durduruldu.", "WARN")
            self.status_lbl.configure(text="DURUM: Pasif", text_color="gray")

    def manuel_tarama_baslat(self):
        dosya_yolu = filedialog.askopenfilename()
        if dosya_yolu:
            threading.Thread(target=self.analiz_proseduru, args=(dosya_yolu,), daemon=True).start()

    # --- ANALİZ MOTORU ---
    def analiz_proseduru(self, dosya_yolu, is_honeypot=False):
        dosya_adi = os.path.basename(dosya_yolu)
        
        # 1. HONEPOT KONTROLÜ (En Yüksek Öncelik)
        if is_honeypot:
            self.alarm_cal()
            self.log_yaz(f"BAL KÜPÜ İHLALİ! Tuzak dosyaya dokunuldu: {dosya_adi}", "HONEY")
            self.status_lbl.configure(text="SALDIRI TESPİT EDİLDİ (HONEYPOT)!", text_color="orange")
            self.karantinaya_al(dosya_yolu, dosya_adi)
            self.stats_guncelle(0, 1)
            messagebox.showwarning("İHLAL", "Honeypot (Tuzak) tetiklendi!")
            return

        # 2. WHITELIST KONTROLÜ
        if dosya_adi in BEYAZ_LISTE:
            self.log_yaz(f"Beyaz Liste dosyası algılandı: {dosya_adi}", "SUCCESS")
            return

        # 3. NORMAL ANALİZ SÜRECİ
        self.status_lbl.configure(text=f"Analiz ediliyor: {dosya_adi}", text_color="cyan")
        self.progress.configure(progress_color="cyan")
        self.progress.set(0.2)
        
        self.log_yaz(f"Analiz Başladı: {dosya_adi}")
        time.sleep(0.5)
        
        f_hash = self.dosya_hashle(dosya_yolu)
        self.progress.set(0.5)
        
        if f_hash:
            # Simülasyon
            if "test_virusu" in dosya_adi:
                skor = 10
            else:
                skor = self.virustotal_sorgula(f_hash)

            self.progress.set(0.9)
            
            if skor is not None and skor > 0:
                self.progress.configure(progress_color="red")
                self.alarm_cal() # SESLİ ALARM!
                self.log_yaz(f"ZARARLI TESPİT EDİLDİ! ({skor} Motor)", "DANGER")
                self.status_lbl.configure(text="TEHDİT ENGELLENDİ!", text_color="red")
                self.karantinaya_al(dosya_yolu, dosya_adi)
                self.stats_guncelle(1, 1)
                messagebox.showwarning("ALARM", f"Zararlı Yazılım Engellendi:\n{dosya_adi}")
            else:
                self.progress.configure(progress_color="green")
                self.log_yaz("Dosya Temiz.", "SUCCESS")
                self.status_lbl.configure(text="Güvenli", text_color="green")
                self.stats_guncelle(1, 0)
        
        self.progress.set(0)
        if monitoring_active: self.status_lbl.configure(text="DURUM: Aktif", text_color="#00ff00")

    def dosya_hashle(self, dosya_yolu):
        sha256 = hashlib.sha256()
        try:
            with open(dosya_yolu, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except: return None

    def virustotal_sorgula(self, dosya_hash):
        url = f"https://www.virustotal.com/api/v3/files/{dosya_hash}"
        headers = {"x-apikey": API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()['data']['attributes']['last_analysis_stats']['malicious']
            elif response.status_code == 404: return -1
            else: return None
        except: return None

    def karantinaya_al(self, dosya_yolu, dosya_adi):
        hedef_yol = os.path.join(QUARANTINE_DIRECTORY, dosya_adi)
        try:
            if os.path.exists(hedef_yol):
                zaman = datetime.datetime.now().strftime("%H%M%S")
                hedef_yol = os.path.join(QUARANTINE_DIRECTORY, f"{zaman}_{dosya_adi}")
            shutil.move(dosya_yolu, hedef_yol)
            self.log_yaz(f"Dosya izole edildi: {dosya_adi}", "SUCCESS")
        except: pass

    def stats_guncelle(self, scan_add, threat_add):
        global total_scanned, threats_blocked
        total_scanned += scan_add
        threats_blocked += threat_add
        self.lbl_scanned.configure(text=str(total_scanned))
        self.lbl_threat.configure(text=str(threats_blocked))

# --- WATCHDOG ---
class OlayYakalayici(FileSystemEventHandler):
    def __init__(self, app_instance):
        self.app = app_instance

    def on_any_event(self, event):
        if event.is_directory: return
        if event.event_type not in ['created', 'modified']: return
        if event.src_path.endswith((".tmp", ".crdownload")): return
        
        dosya_yolu = event.src_path
        
        # HONEYPOT KONTROLÜ
        # Eğer olay "BAL_KUPU_GIZLI" klasöründe olduysa, direk HONEYPOT alarmı ver
        if HONEYPOT_DIRECTORY in dosya_yolu:
             # Beklemeden alarm ver!
             self.app.analiz_proseduru(dosya_yolu, is_honeypot=True)
             return

        time.sleep(1)
        if os.path.exists(dosya_yolu):
            self.app.analiz_proseduru(dosya_yolu, is_honeypot=False)

if __name__ == "__main__":
    app = MiniEDRApp()
    app.mainloop()