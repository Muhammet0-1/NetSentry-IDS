import logging
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, conf

# === NetSentry: Lightweight Intrusion Detection System ===
# Developed by: LordMs
# Purpose: Detect Port Scans (SYN Flood/Scan) in real-time.

# Loglama ayarları
logging.basicConfig(
    filename='netsentry_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - [ALERT] - %(message)s'
)

# Tarama tespiti için eşik değer (Threshold)
# Aynı IP'den 15'ten fazla SYN paketi gelirse alarm ver.
SCAN_THRESHOLD = 15
packet_counts = defaultdict(int)
detected_ips = set()

def detect_syn_scan(packet):
    """
    Paketleri analiz eder ve SYN taraması yapan IP'leri tespit eder.
    """
    try:
        # Sadece IP ve TCP katmanı olan paketlere bak
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            tcp_layer = packet[TCP]

            # TCP Bayraklarını Kontrol Et
            # 'S' = SYN (Synchronization) -> Bağlantı başlatma isteği
            if tcp_layer.flags == 'S':
                packet_counts[src_ip] += 1
                
                # Eğer eşik değeri aşıldıysa ve daha önce raporlanmadıysa
                if packet_counts[src_ip] > SCAN_THRESHOLD and src_ip not in detected_ips:
                    msg = f"POTENTIAL PORT SCAN DETECTED! Source IP: {src_ip} -> Target: {packet[IP].dst}"
                    print(f"\n🚨 {msg}")
                    logging.warning(msg)
                    detected_ips.add(src_ip) # Sürekli spam yapmasın diye listeye ekle

    except Exception as e:
        pass

def start_ids():
    print(f"""
    █▀▀█ █▀▀ ▀▀█▀▀ █▀▀ █▀▀ █▀▀▄ ▀▀█▀▀ █▀▀█ █░░█
    █░░█ █▀▀ ░░█░░ ▀▀█ █▀▀ █░░█ ░░█░░ █▄▄▀ █▄▄█
    ▀░░▀ ▀▀▀ ░░▀░░ ▀▀▀ ▀▀▀ ▀░░▀ ░░▀░░ ▀░▀▀ ▄▄▄█
        --- Network Intrusion Detection System ---
        Monitoring Interface: {conf.iface}
    """)
    print("[*] Sistem aktif. Ağ trafiği dinleniyor...")
    print("[*] Çıkmak için Ctrl+C yapın.\n")

    # Scapy ile dinleme (Sniffing)
    # store=False: Belleği şişirmemek için paketleri saklama
    sniff(filter="tcp", prn=detect_syn_scan, store=False)

if __name__ == "__main__":
    # Ağ dinleme işlemi root yetkisi gerektirir!
    try:
        start_ids()
    except KeyboardInterrupt:
        print("\n[-] NetSentry durduruldu.")
    except PermissionError:
        print("\n[!] HATA: Ağ kartını dinlemek için 'sudo' yetkisi gereklidir.")
        print("    Lütfen komutu şöyle çalıştırın: sudo ./venv/bin/python net_sentry.py")
