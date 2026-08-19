# NetSentry IDS

NetSentry, canlı ağ trafiğindeki TCP bağlantı başlatma metadata'sını gözlemleyen küçük,
savunma amaçlı bir saldırı tespit aracıdır. Saf SYN paketlerindeki yoğunluk ve hedef port
çeşitliliğini eşiklerle değerlendirir; trafiği engellemez, firewall değiştirmez ve paket
payload'larını kendi durumunda saklamaz, loglamaz veya raporlamaz.

> [!IMPORTANT]
> Bu araç tek başına bir güvenlik sınırı değildir. Alarmlar olası davranışları gösterir ve
> bağlam sahibi bir operatör tarafından doğrulanmalıdır.

## Desteklenen tespitler

| Kural | Varsayılan | Sinyal | Başlıca yanlış pozitif kaynakları |
| --- | --- | --- | --- |
| `tcp_syn_port_scan` | 60 saniyede 16 benzersiz hedef port | Kaynağın ilk SYN paketleriyle temas ettiği farklı hedef portlar | Sağlık kontrolü, servis keşfi, yüksek fan-out istemciler |
| `tcp_syn_rate` | 10 saniyede 100 ilk SYN | Aynı kaynaktan gözlenen toplam ilk SYN sayısı | Yoğun istemciler, NAT arkasındaki kullanıcılar, yeniden iletimler |

Yalnızca TCP `SYN=1` ve diğer bayraklar kapalı olan ilk bağlantı paketleri değerlendirilir.
ACK/RST içeren paketler sayılmaz. Kurallar TCP el sıkışmasının sonucunu veya uygulama
katmanını incelemez; bu nedenle bir alarm başarılı saldırı kanıtı değildir. Eşikler ağın
normal trafiğine göre ayarlanmalıdır.

## Kurulum

Python 3.10 veya üzeri ve Scapy gerekir. Linux'ta BPF filtreleri için sistemin libpcap
paketine de ihtiyaç duyulabilir.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
netsentry --help
```

Geliştirme bağımlılıkları:

```bash
python -m pip install -e '.[dev]'
```

## Yetkiler ve çalıştırma

Canlı paket yakalama çoğu Linux sisteminde root veya uygun `CAP_NET_RAW` yeteneği ister;
arayüzün promiscuous mod ayarı bazı ortamlarda ayrıca `CAP_NET_ADMIN` gerektirebilir. En az
yetkili, kuruma uygun bir çalıştırma yöntemi kullanın; genel Python yorumlayıcısına kalıcı
capability vermek diğer Python kodlarını da yetkilendirebilir. NetSentry eksik yetkiyi ve
bulunamayan arayüzü açıklayıcı bir hatayla bildirir.

```bash
sudo install -d -m 0700 -o root -g root /var/log/netsentry
sudo .venv/bin/netsentry \
  --interface eth0 \
  --output /var/log/netsentry/alerts.jsonl
```

Belirli korunan hedeflere daraltılmış örnek:

```bash
sudo .venv/bin/netsentry \
  --interface eth0 \
  --target-ip 192.0.2.10 \
  --target-port 443 \
  --output /var/log/netsentry/alerts.jsonl
```

`192.0.2.10`, dokümantasyon için ayrılmış örnek adrestir. Kendi izinli ortamınıza ait
değerleri kullanın. Ctrl+C veya SIGTERM temiz bir kapanış başlatır. Araç aktif müdahale
özelliği içermez.

### Temel seçenekler

| Seçenek | Varsayılan | Açıklama |
| --- | --- | --- |
| `--interface` | Scapy varsayılanı | Yakalama arayüzü |
| `--bpf-filter` | kapalı | İsteğe bağlı, libpcap tarafından derlenecek BPF filtresi |
| `--scan-threshold`, `--scan-window` | `16`, `60` | Benzersiz port eşiği ve saniye penceresi |
| `--syn-threshold`, `--syn-window` | `100`, `10` | SYN sayısı eşiği ve saniye penceresi |
| `--alert-cooldown` | `120` | Aynı kural/kaynak için yeniden alarm süresi |
| `--state-ttl` | `300` | Etkin olmayan kaynak durumunun yaşam süresi |
| `--max-sources` | `4096` | Bellekteki en fazla kaynak sayısı |
| `--max-events-per-source` | `256` | Kaynak başına SYN-rate kuyruğu kapasitesi |
| `--max-ports-per-source` | `256` | Kaynak başına hedef-port recency kapasitesi |
| `--target-ip`, `--target-port` | tümü | Tekrarlanabilir hedef seçicileri |
| `--output` | `netsentry_alerts.jsonl` | JSON Lines alarm dosyası |
| `--no-file-output` | kapalı | Kalıcı alarm yazımını kapatır |
| `--quiet` | kapalı | Konsol alarm çıktısını kapatır |

Eşikler en az 2, portlar 1–65535 ve zaman değerleri sonlu/pozitif olmalıdır. Durum TTL'i
en uzun kural penceresinden veya alarm cooldown süresinden kısa olamaz. BPF sözdiziminin
son doğrulaması, seçilen yakalama backend'i/libpcap tarafından yapılır. Scoped IPv6
hedefleri (`fe80::1%eth0` gibi) kabul edilmez; scopesuz adresi `--target-ip`, arayüzü ayrı
`--interface` seçeneğiyle belirtin.

SYN-rate olay kapasitesi rate eşiğinden, hedef-port recency kapasitesi de port-scan
eşiğinden küçük olamaz. Bu iki sınırlı yapı bağımsızdır: aynı hedef porta yapılan tekrarlar
rate kuyruğunda sayılır, ancak benzersiz port kanıtını silmez. Port tekrarları ilgili portun
monotonic son-görülme zamanını yeniler; scan window dışındaki portlar süresi dolunca temizlenir.

Varsayılan olarak kernel/libpcap BPF prefilter uygulanmaz; desteklenen L2/L3/TCP zincirleri
`ScapyPacketParser` tarafından doğrulanır ve diğer paketler metadata üretilmeden yok sayılır.
Yüksek trafikli ortamlarda operatör açıkça `--bpf-filter` verebilir. Ancak libpcap filtreleri
protokol zincirini parser ile aynı şekilde takip etmeyebilir; aşırı dar bir filtre VLAN-tagged
veya IPv6 extension-header içeren TCP paketlerini parser'a ulaşmadan eleyip tespit kaçırabilir.
Özel filtreyi ortamın link-layer türleriyle ve beklenen IPv6 zincirleriyle doğrulayın.

## Alarm biçimi

Her satır tek bir JSON nesnesidir. Aşağıdaki örnek sentetiktir:

```json
{"destination_ip":"192.0.2.10","reason":"source contacted many distinct TCP destination ports with initial SYN packets","rule_id":"tcp_syn_port_scan","severity":"medium","signals":{"threshold":16,"unique_destination_ports":16,"window_seconds":60.0},"source_ip":"198.51.100.23","timestamp":"2026-01-01T00:00:15Z"}
```

Reporter absolute yolları kök dizin descriptor'ından, göreli yolları sabitlenmiş çalışma dizini
descriptor'ından başlayarak bileşen bileşen açar. Her ancestor `O_DIRECTORY | O_NOFOLLOW`
ile doğrulanır; yolun herhangi bir yerindeki symlink reddedilir. Son çıktı dizini ve dosya
descriptor olarak sabitlenir, dosya yalnızca bu dizine göre açılır. Dizin etkin kullanıcıya ait
olmalı ve grup/diğer kullanıcılar tarafından yazılabilir olmamalıdır. Yeni dosya `0600`
oluşturulur. Mevcut hedef yalnızca normal, tek hard-link'e sahip, etkin kullanıcıya ait ve
izinleri `0600` değerini aşmayan bir dosyaysa kabul edilir; izinleri kendiliğinden değiştirilmez.
FIFO, socket, device ve dizin hedefleri reddedilir. Gerekli güvenli descriptor/bayrak desteği
olmayan platformlarda araç güvensiz pathname yöntemine dönmek yerine hata verir.

Özellikle `sudo` ile çalıştırırken varsayılan göreli çıktı yolu kullanıcı tarafından yönetilen
bir çalışma dizininde güvenlik kontrolünden geçmeyebilir. Yukarıdaki gibi root'a ait `0700`
bir çıktı dizini belirtin. Capability ile yetkisiz kullanıcı olarak çalıştırılıyorsa çıktı dizini
o etkin kullanıcıya ait olmalıdır.

## Mimari

Kod `src/netsentry` altında ayrılmıştır:

- `capture.py`: Varsayılan filtresiz Scapy canlı yakalama ve isteğe bağlı BPF aktarımı
- `parser.py`: IPv4/IPv6 + TCP nesnelerini güvenli metadata'ya dönüştürme
- `state.py`: Ayrı, TTL/pencere ve boyut sınırlarına sahip SYN-rate ve port-recency durumu
- `rules.py` / `detector.py`: test edilebilir SYN kuralları ve orkestrasyon
- `engine.py`: ayrıştırma, hedef filtreleme, tespit ve alarm hattı
- `reporting.py`: konsol ve JSONL raporlama
- `config.py` / `cli.py`: doğrulama ve komut satırı

Yakalama katmanı motorun geri kalanından ayrıdır; testler gerçek arayüz yerine sentetik
`PacketMetadata` ve fake ayrıştırıcı kullanır.

## Gizlilik ve güvenli varsayılanlar

`Payload persistence and reporting are disabled`: NetSentry payload'ı analiz etmez, kendi
durum yapısında saklamaz, loglamaz veya raporlamaz. Alarmda yalnızca zaman, kural, gerekçe,
kaynak/hedef IP ve toplu sayaçlar bulunur. IP adresleri yine de kişisel veya hassas veri
sayılabilir; çıktı dosyasını erişim kontrollü tutun, saklama süresi belirleyin ve kurumunuzun
mevzuatına uyun.

Bu, payload yakalamanın veya süreç belleğine hiç girmemesinin garanti edildiği anlamına
gelmez. Scapy `sniff` tam paketi ve payload baytlarını süreç belleğinde geçici olarak
materialize edebilir. `store=False`, Scapy'nin sonuç listesinde yakalanan paketleri
biriktirmesini engeller; header-only capture uygulamaz. NetSentry'nin kendi durum tablosu
yalnızca gereken TCP/IP metadata'sını tutar ve süre/boyut sınırlarıyla temizler. Algılama
pencereleri, durum TTL'i ve cooldown hesapları sistem saati değişikliklerinden etkilenmeyen
monotonic saatle yürütülür; JSONL zaman damgası için ayrı wall-clock zamanı kullanılır.

## Sınırlamalar

- Yalnızca yakalama noktasında görülebilen IPv4/IPv6 TCP ilk SYN metadata'sını inceler.
- Dış IP protokolü TCP olmayan ICMP/ICMPv6 alıntıları, UDP ve IP encapsulation içindeki TCP
  katmanları değerlendirilmez.
- IPv6 Hop-by-Hop, Routing, Destination Options ve parçalanmamış Fragment extension zincirleri
  desteklenir; AH/ESP ve parçalanmış IPv6 trafiği güvenli biçimde yok sayılır.
- Dağıtık veya çok yavaş taramalar eşik altında kalabilir; NAT tek bir kaynağı kalabalık gösterebilir.
- SYN yeniden iletimlerini TCP akışı olarak birleştirmez.
- Paket kaybı, asimetrik yönlendirme ve NIC offload davranışı sonuçları etkileyebilir.
- Uygulama katmanı saldırısı, UDP/ICMP anomalisi, başarılı bağlantı ve exploit tespiti yapmaz.
- Firewall veya paket engelleme özelliği yoktur.

## Test ve kalite kontrolleri

Testler gerçek ağ yakalama, tarama veya firewall değişikliği yapmaz:

```bash
python -m pytest
ruff check .
mypy
python -m compileall -q src tests net_sentry.py
python -m build
```

GitHub Actions aynı kontrolleri Python 3.10–3.13 üzerinde çalıştırır.

## Yasal kullanım

Yalnızca sahibi olduğunuz veya izleme izni aldığınız ağlarda kullanın. Paket yakalama ve IP
metadata'sı işleme bulunduğunuz yerde yasal, sözleşmesel ve kurumsal yükümlülüklere tabi
olabilir. Yetkilendirme, bildirim, veri minimizasyonu ve saklama gereksinimlerini kullanım
öncesinde değerlendirmek kullanıcının sorumluluğundadır.

## Katkı ve güvenlik

Katkı süreci için [CONTRIBUTING.md](CONTRIBUTING.md), güvenlik bildirimi için
[SECURITY.md](SECURITY.md), sürüm notları için [CHANGELOG.md](CHANGELOG.md) dosyasına bakın.

## Lisans

[MIT License](LICENSE)
