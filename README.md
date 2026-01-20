# 👁️ NetSentry - Lightweight IDS

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Network](https://img.shields.io/badge/Network-Scapy-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Type-Intrusion%20Detection-red?style=for-the-badge)

**NetSentry**, ağ trafiğini gerçek zamanlı analiz eden ve şüpheli aktiviteleri (özellikle Port Taramalarını) tespit eden hafif siklet bir Saldırı Tespit Sistemi (IDS) aracıdır.

Python **Scapy** kütüphanesi kullanılarak geliştirilmiştir. Ağ paketlerinin TCP başlıklarını (Headers) ve Bayraklarını (Flags) analiz ederek imza tabanlı tespit yapar.

## 🚀 Özellikler

* **Real-time Sniffing:** Ağ kartı üzerinden geçen trafiği anlık izler.
* **SYN Scan Detection:** Nmap vb. araçlarla yapılan port taramalarını (TCP SYN Flooding) yakalar.
* **Logging:** Tespit edilen saldırgan IP adreslerini `netsentry_alerts.log` dosyasına kaydeder.

## ⚙️ Kurulum ve Kullanım

Bu araç, ağ kartına doğrudan erişim (Raw Socket) gerektirdiği için **root** yetkileriyle çalıştırılmalıdır.

```bash
# Bağımlılıkları yükle
pip install scapy

# Aracı başlat (Sanal ortam yoluyla)
sudo ./venv/bin/python net_sentry.py
