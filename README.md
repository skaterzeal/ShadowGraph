# ShadowGraph

<p align="center">
  <strong>AI-Driven Attack Path & Vulnerability Chaining Engine</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go_1.25+-00ADD8?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/DB-SQLite_(Pure_Go)-003B57?style=for-the-badge&logo=sqlite" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-0.2.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/CGO-Not_Required-orange?style=for-the-badge" />
</p>

---

## Nedir?

ShadowGraph, **tek bir binary** dosyadan çalışan, sıfır dışa bağımlılık prensibiyle geliştirilmiş açık kaynaklı bir sızma testi ve ağ keşif aracıdır. Hedef sistemlerdeki açık portları, servisleri, zafiyetleri ve bilinen exploit'leri tespit ederek bunları **graf tabanlı saldırı yolu haritası** üzerinde görselleştirir. DFS (Depth-First Search) algoritmasıyla saldırı zincirlerini otomatik tespit eder ve risk skorlaması yapar.

### Rakiplerden Farkı

ShadowGraph, Nmap veya Nessus gibi araçlardan farklı olarak **tarama sonuçlarını bir graf veri yapısında** modeller. Bu sayede sadece "port X açık, CVE-Y var" demek yerine, **"hedefe port X üzerinden ulaşılır → servis Y çalışıyor → CVE-Z zafiyeti var → bu zafiyet için bilinen exploit mevcut → diğer CVE'lerle zincirlenerek RCE elde edilebilir"** şeklinde tam saldırı yollarını ve zincirlerini ortaya koyar.

---

## Temel Özellikler

### Tarama Motoru
- **Concurrent TCP Port Tarama** — Goroutine worker pool ile yüzlerce portu eşzamanlı tarama (varsayılan 100 worker)
- **UDP Port Tarama** — DNS (53), SNMP (161), NTP (123), TFTP (69) için özel payload'larla tarama
- **Banner Grabbing** — HTTP, HTTPS, SSH, FTP, SMTP, MySQL, Redis, MongoDB ve daha fazlası
- **300+ Servis İmzası** — Web sunucuları, veritabanları, mesaj kuyrukları, CI/CD, container, IoT/SCADA dahil
- **OS Fingerprinting** — ICMP TTL + TCP TTL fallback ile işletim sistemi tespiti
- **DNS / Reverse DNS** — IP ↔ Hostname çift yönlü çözümleme
- **IPv6 Desteği** — Dual-stack tarama

### Hedef Yönetimi
- **Tek IP / Domain** — `192.168.1.1` veya `example.com`
- **CIDR Blok Desteği** — `192.168.1.0/24` notasyonu ile subnet tarama (maks /16)
- **Virgülle Ayrılmış Liste** — `"10.0.0.1,10.0.0.2,example.com"`
- **Dosyadan Toplu Hedef** — Her satırda bir hedef, `#` ile yorum desteği

### Zafiyet Tespiti
- **NVD Live CVE Sorgulama** — NIST Ulusal Zafiyet Veritabanına anlık REST API sorgusu
- **ExploitDB / Metasploit Eşleştirme** — 30+ bilinen exploit ile versiyon tabanlı eşleşme
- **CDN/WAF False Positive Koruması** — Cloudflare, Akamai, Fastly, CloudFront ve 25+ CDN/WAF servisi otomatik tespit edilir; banner'ları gerçek uygulamayı yansıtmadığından CVE sorgusu atlanarak false positive önlenir

### AI Saldırı Yolu Analizi
- **Graf Tabanlı DFS** — Target → Port → Service → CVE zincirlerini otomatik keşfeder
- **Risk Skorlama (0-10)** — CVE severity + port kritikliği + servis yaşı formülü
- **Zincirleme Saldırı Tespiti** — Birden fazla CVE'nin birleştirilmesiyle RCE, veri sızıntısı ve eskalasyon senaryoları
- **Öncelikli Remediation** — Tespit edilen risklere göre otomatik iyileştirme önerileri
- **Ollama Entegrasyonu (BYOLAI)** — Yerel LLM ile narrative zenginleştirme; Ollama kurulu değilse otomatik rule-based fallback
- **Çoklu Sağlayıcı Desteği** — `--provider ollama` veya `--provider rule-based` ile seçim; config dosyasından varsayılan ayarlanabilir

### Raporlama & Görselleştirme
- **İnteraktif Web Dashboard** — Vis.js tabanlı kırılımlı ağaç haritası, arama, filtreleme, scan seçici dropdown
- **Dashboard AI Paneli** — Dashboard üzerinden analiz çalıştırma (RUN butonu), sonuçları anlık görüntüleme
- **Otomatik Tarayıcı Açma** — `ui` komutu veya `scan --ui` ile varsayılan tarayıcı otomatik açılır
- **Refresh Butonu** — Dashboard üzerinde manuel yenileme ile güncel terminal çıktılarını yansıtma
- **HTML Profesyonel Rapor** — Executive summary, risk matrisi, CVE tablosu, exploit listesi, AI analiz bölümü, SVG ağ haritası
- **JSON / CSV Export** — Tarama verilerini yapılandırılmış formatlarda dışa aktarma
- **Tarama Karşılaştırma (Diff)** — İki tarama arasındaki farkları raporlama

### Harici Araç Entegrasyonu
- **Nmap XML Import** — `nmap -oX` çıktısını içe aktarma (NSE script CVE çıkarma dahil)
- **Masscan JSON Import** — `masscan --output-format json` çıktısını içe aktarma
- **Otomatik Format Tespiti** — XML/JSON dosya formatını otomatik algılama

### Plugin Sistemi
- **YAML Tabanlı Plugin'ler** — Özel tarama scriptleri tanımlama
- **Placeholder Desteği** — `{target}`, `{port}`, `{service}` değişkenleri
- **Timeout Kontrolü** — Her plugin için maksimum çalışma süresi
- **Trigger Mekanizması** — Hangi servis/port/durumda çalışacağını belirleme

### Tarama İzolasyonu
- **Scan ID Bazlı Veri Ayrımı** — Her tarama benzersiz ID alır; tüm node/edge'ler bu ID altına yazılır
- **Scan Seçimi** — `--scan-id N` ile UI, analyze ve export komutlarında belirli bir tarama seçilebilir
- **Scan Listesi** — `shadowgraph scans` komutuyla geçmiş taramalar listelenebilir

### Altyapı
- **Sıfır CGO Bağımlılık** — Pure Go SQLite (modernc.org/sqlite), her platformda derlenir
- **YAML Konfigürasyon** — NVD API key, proxy, worker sayısı, rate limit, AI sağlayıcı, logging ayarları
- **Ortam Değişkeni Override** — `SHADOWGRAPH_NVD_KEY`, `SHADOWGRAPH_PROXY`, `OLLAMA_HOST`, `SHADOWGRAPH_AI_PROVIDER`
- **SIEM-Uyumlu JSON Loglama** — Yapılandırılmış log çıktısı, dosya rotasyonu
- **Cross-Platform Build** — Windows, Linux, macOS (amd64 + arm64)
- **GitHub Actions CI/CD** — Tag push ile otomatik multi-platform release (`release.yml`)
- **Docker Desteği** — Multi-stage Alpine Dockerfile (~15 MB), izole çalışma ortamı
- **Güvenlik Ağı (Safety Net)** — Büyük subnet onayı, `--max-retries`, rate limiting
- **Graceful Shutdown** — Tarama sırasında güvenli sonlandırma

---

## Kurulum

### Gereksinimler
- Go 1.25+ (derleme için)
- İnternet bağlantısı (NVD API sorguları için — opsiyonel, `--no-nvd` ile devre dışı bırakılabilir)

### Kaynak Koddan Derleme

```bash
git clone https://github.com/shadowgraph/core.git
cd core
go mod tidy
make build
```

Derlenmiş binary `./shadowgraph` (Linux/macOS) veya `shadowgraph.exe` (Windows) olarak oluşur.

### Cross-Platform Build

```bash
make build-all
```

Bu komut `dist/` dizinine şu binary'leri üretir:

| Platform | Mimari | Dosya |
|---|---|---|
| Windows | amd64 | `shadowgraph-windows-amd64.exe` |
| Linux | amd64 | `shadowgraph-linux-amd64` |
| Linux | arm64 | `shadowgraph-linux-arm64` |
| macOS | amd64 | `shadowgraph-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `shadowgraph-darwin-arm64` |

### Makefile Komutları

```bash
make build       # Mevcut platform için derle
make build-all   # Tüm platformlar için derle
make clean       # Derleme çıktılarını temizle
make tidy        # Go modüllerini düzenle
make test        # Testleri çalıştır
make run-scan TARGET=192.168.1.1   # Hızlı tarama
make run-ui      # Dashboard'u başlat
```

### Docker ile Çalıştırma

ShadowGraph'i izole bir ortamda çalıştırmak için Docker kullanabilirsiniz:

```bash
# Image'i derle
docker build -t shadowgraph .

# Tarama çalıştır (NET_RAW capability gerekli)
docker run --rm --cap-add=NET_RAW -v $(pwd)/data:/data shadowgraph scan -t 192.168.1.1

# Dashboard başlat (port forwarding ile)
docker run --rm --cap-add=NET_RAW -v $(pwd)/data:/data -p 8080:8080 shadowgraph ui --no-open

# Analiz çalıştır
docker run --rm -v $(pwd)/data:/data shadowgraph analyze
```

**Notlar:**
- Veritabanı ve config `/data` dizininde tutulur; `-v` ile volume mount önerilir
- TCP/UDP taramaları için `--cap-add=NET_RAW` gereklidir
- Image boyutu ~15 MB (multi-stage Alpine build)

### GitHub Releases

Derlemek istemiyorsanız, [Releases](https://github.com/shadowgraph/core/releases) sekmesinden platformunuza uygun binary'yi doğrudan indirebilirsiniz. Her `v*.*.*` tag'i push edildiğinde GitHub Actions otomatik olarak tüm platformlar için binary derleyip yayınlar.

---

## Kullanım

### Komut Listesi

```
shadowgraph [komut] [flagler]

Komutlar:
  scan      Ağ taraması (tek IP, CIDR, çoklu hedef)
  import    Nmap XML / Masscan JSON içe aktarma
  analyze   AI saldırı yolu analizi
  ui        İnteraktif web dashboard
  export    JSON / CSV / HTML rapor oluşturma
  diff      İki tarama karşılaştırması
  plugin    YAML plugin/script yönetimi
  scans     Geçmiş taramaları listeler (ID, hedef, profil, başlangıç/bitiş)
```

---

### `scan` — Ağ Taraması

Hedef sistemleri tarar, açık portları, servisleri, zafiyetleri ve exploit'leri tespit eder.

```bash
# Tek hedef (varsayılan profil: standard, 100 port)
shadowgraph scan -t 192.168.1.1

# Domain tarama
shadowgraph scan -t example.com

# CIDR subnet tarama (tüm /24 bloğu)
shadowgraph scan -t 192.168.1.0/24

# Virgülle ayrılmış çoklu hedef
shadowgraph scan -t "10.0.0.1,10.0.0.2,example.com"

# Dosyadan toplu hedef yükleme
shadowgraph scan --target-file targets.txt

# Hızlı tarama (Top 10 port, 1s timeout)
shadowgraph scan -t 192.168.1.1 --profile quick

# Tam port taraması (1-65535)
shadowgraph scan -t 10.0.0.5 --profile full

# Gizli tarama (yavaş, IDS/IPS atlatma modeli)
shadowgraph scan -t target.com --profile stealth

# Özel port listesi
shadowgraph scan -t target.com --ports 80,443,8080,9200

# Port aralığı
shadowgraph scan -t target.com --ports 1-1000

# 200 eşzamanlı worker ile tarama
shadowgraph scan -t 192.168.1.0/24 --workers 200

# Rate limiting (portlar arası 50ms bekleme)
shadowgraph scan -t target.com --rate-limit 50

# NVD CVE sorgusunu devre dışı bırakma (offline tarama)
shadowgraph scan -t 192.168.1.1 --no-nvd

# Kombine kullanım
shadowgraph scan --target-file targets.txt --profile full --workers 200 --rate-limit 10

# Tarama bitince dashboard'u otomatik aç
shadowgraph scan -t 192.168.1.1 --ui

# Büyük subnet onayını atla
shadowgraph scan -t 10.0.0.0/16 --yes
```

**Flagler:**

| Flag | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--target` | `-t` | — | Hedef IP, domain, CIDR veya virgülle ayrılmış liste |
| `--target-file` | — | — | Hedef listesi dosyası (her satır bir hedef) |
| `--profile` | `-P` | `standard` | Tarama profili: `quick`, `standard`, `full`, `stealth` |
| `--ports` | — | — | Özel port listesi (örn: `80,443` veya `1-1000`) |
| `--timeout` | — | Profil değeri | Bağlantı timeout süresi (ms) |
| `--workers` | `-w` | `100` | Eşzamanlı goroutine worker sayısı |
| `--rate-limit` | — | `0` | Portlar arası minimum bekleme süresi (ms) |
| `--no-nvd` | — | `false` | NVD CVE sorgusunu devre dışı bırak |
| `--ui` | — | `false` | Tarama bitince dashboard'ı bu scan ile otomatik aç |
| `--ui-port` | — | `8080` | `--ui` kullanıldığında dashboard port numarası |
| `--yes` | `-y` | `false` | Büyük subnet onayı gibi soruları atla |
| `--max-retries` | — | `2` | Başarısız port/banner/NVD sorguları için yeniden deneme sayısı |

**Tarama Profilleri:**

| Profil | Port Sayısı | Timeout | Açıklama |
|---|---|---|---|
| `quick` | 10 | 1s | En yaygın 10 port (hızlı keşif) |
| `standard` | 100 | 3s | Kurumsal ağlarda yaygın 100 port |
| `full` | 65.535 | 3s | Tüm portlar (kapsamlı tarama) |
| `stealth` | 100 | 5s | Yavaş tarama + port arası gecikme (IDS atlatma) |

**Hedef Dosyası Formatı** (`targets.txt`):

```
# Kurumsal ağ taraması
192.168.1.1
192.168.1.0/24
10.0.0.1
example.com
# Boş satırlar ve # ile başlayan satırlar yoksayılır
```

---

### `import` — Harici Araç Çıktısı İçe Aktarma

Nmap XML veya Masscan JSON çıktılarını ShadowGraph veritabanına aktarır.

```bash
# Nmap XML içe aktarma
nmap -sV -oX scan_result.xml target.com
shadowgraph import -f scan_result.xml

# Masscan JSON içe aktarma
masscan 192.168.1.0/24 -p1-65535 --output-format json -oJ masscan.json
shadowgraph import -f masscan.json
```

Dosya formatı (XML/JSON) otomatik algılanır. Nmap çıktısından NSE script sonuçlarındaki CVE ID'leri de çıkarılır.

**Flagler:**

| Flag | Kısa | Açıklama |
|---|---|---|
| `--file` | `-f` | İçe aktarılacak dosya yolu (zorunlu) |

---

### `analyze` — AI Saldırı Yolu Analizi

Tarama sonuçlarını graf üzerinde analiz ederek saldırı yollarını, zincirleme saldırı senaryolarını ve risk skorlarını hesaplar.

```bash
# Konsol çıktısı olarak analiz (en son tarama)
shadowgraph analyze

# Belirli bir taramayı analiz etme
shadowgraph analyze --scan-id 3

# Analiz sonucunu JSON olarak kaydetme
shadowgraph analyze --output attack_report.json

# Ollama (yerel LLM) ile zenginleştirilmiş analiz
shadowgraph analyze --provider ollama

# Ollama + belirli scan + JSON çıktı
shadowgraph analyze --scan-id 3 --provider ollama --output report.json
```

**Sağlayıcılar (Providers):**

| Sağlayıcı | Açıklama |
|---|---|
| `rule-based` | Varsayılan. Hızlı, deterministik, internet gerektirmez |
| `ollama` | Yerel LLM ile narrative zenginleştirme. Ollama kurulu olmalı; kurulu değilse otomatik `rule-based` fallback |

**Analiz Çıktısı:**
- Tespit edilen saldırı yolları (target → port → service → CVE)
- Her yol için risk skoru (0-10 arası)
- Complexity ve Impact değerlendirmesi
- Zincirleme saldırı senaryoları (RCE chain, data leak, multi-vuln escalation)
- Önceliklendirilmiş remediation önerileri

**Risk Skorlama Formülü:**
- CVE severity ağırlığı: CRITICAL=10, HIGH=8, MEDIUM=5, LOW=2
- Port kritikliği bonusu: SSH(22), RDP(3389), SMB(445) gibi portlar +2
- Birden fazla CVE zincirleme bonusu
- Genel skor 0-10 arası normalize edilir

**Flagler:**

| Flag | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--output` | `-o` | — | Analiz raporunu JSON dosyasına kaydet |
| `--scan-id` | — | En son tarama | Analiz edilecek scan ID |
| `--provider` | — | Config değeri | AI sağlayıcı: `rule-based`, `ollama` |
| `--no-save` | — | `false` | Analizi veritabanına kaydetme |

---

### `ui` — İnteraktif Web Dashboard

Tarama sonuçlarını görsel ve interaktif bir web panelinde sunar. Komut çalıştırıldığında varsayılan tarayıcı otomatik açılır.

```bash
# Dashboard başlat (tarayıcı otomatik açılır)
shadowgraph ui

# Belirli bir scan göster
shadowgraph ui --scan-id 3

# Farklı port üzerinde başlat
shadowgraph ui --port 9090

# Tarayıcıyı otomatik açma
shadowgraph ui --no-open
```

**Dashboard Özellikleri:**
- **Scan Seçici Dropdown** — Üst menüden geçmiş taramalar arasında geçiş yapma
- **Kırılımlı Ağaç Haritası** — Başlangıçta sadece hedefler görünür; tıkladıkça portlar, servisler, CVE'ler ve exploit'ler açılır
- **Akıllı Renklendirme** — Zafiyeti olan portlar kırmızı, güvenli portlar yeşil, CVE'ler kırmızı, exploit'ler mor, CDN/WAF shield'lar turuncu
- **AI Analiz Paneli** — Seçili scan için AI analizini görüntüleme; RUN butonu ile anlık analiz başlatma
- **Refresh Butonu** — Yeni tarama verilerini, analiz sonuçlarını ve scan listesini yeniden yükleme
- **Arama** — IP, port numarası, CVE ID, servis adı ile anlık filtreleme
- **Filtre Butonları** — ALL, HOSTS, PORTS, VULNS, EXPLOITS, SHIELDS
- **EXPAND ALL / COLLAPSE ALL** — Tüm düğümleri aç/kapa
- **Network Overview** — Toplam cihaz, açık port, servis, zafiyet, exploit ve CDN/WAF sayıları
- **Risk Göstergesi** — Genel sağlık durumu ve risk seviyesi
- **Export** — Tarayıcının print fonksiyonu ile PDF çıktısı oluşturma
- **Share** — Dashboard linkini panoya kopyalama

**Flagler:**

| Flag | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--port` | `-p` | `8080` | Dashboard port numarası |
| `--scan-id` | — | En son tarama | Gösterilecek scan ID |
| `--no-open` | — | `false` | Varsayılan tarayıcıyı otomatik açma |

**Not:** Dashboard yalnızca `127.0.0.1` (localhost) üzerinde çalışır. Kimlik doğrulama yoktur çünkü araç tamamen yerel kullanım içindir.

---

### `export` — Rapor Oluşturma

Tarama sonuçlarını farklı formatlarda dışa aktarır.

```bash
# JSON rapor
shadowgraph export --format json --output rapor.json

# CSV rapor
shadowgraph export --format csv --output rapor.csv

# HTML profesyonel rapor (executive summary, risk matrisi, CVE tablosu, exploit listesi, AI analiz)
shadowgraph export --format html --output rapor.html

# Belirli bir taramayı raporla
shadowgraph export --format html --scan-id 3 --output rapor.html

# Kayıtlı tarama listesini görüntüleme
shadowgraph export --format scans
```

**Flagler:**

| Flag | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--format` | `-f` | `json` | Çıktı formatı: `json`, `csv`, `html`, `scans` |
| `--output` | `-o` | Otomatik | Çıktı dosya yolu |
| `--scan-id` | — | En son tarama | Hangi scan ID raporlansın |

**HTML Rapor İçeriği:**
- Executive Summary: Taranan hedef, açık port, servis, CVE, exploit ve kritik zafiyet sayıları
- Risk Matrisi: CRITICAL, HIGH, MEDIUM dağılımı
- AI Attack Path Analysis: Saldırı yüzeyi analizi, risk skoru, zincirleme saldırı senaryoları ve öneriler (analiz yapılmışsa)
- Ağ Topolojisi: SVG formatlı görsel ağ haritası (snapshot)
- Hedef Bilgileri: Hostname, IP, OS tablosu
- Zafiyet Detayları & Remediation: CVE ID, severity, CVSS, açıklama ve iyileştirme önerisi
- Bilinen Exploit'ler: Exploit ID, kaynak, tür ve açıklama
- CDN/WAF Korumalı Servisler: False positive olarak atlanan servislerin listesi

---

### `diff` — Tarama Karşılaştırma

İki farklı taramayı karşılaştırarak yeni eklenen, kaldırılan ve değişen öğeleri raporlar.

```bash
# Tarama ID'lerini öğrenmek için
shadowgraph scans
# veya
shadowgraph export --format scans

# İki taramayı karşılaştır
shadowgraph diff --scan-a 1 --scan-b 2
```

**Flagler:**

| Flag | Açıklama |
|---|---|
| `--scan-a` | Eski tarama ID'si (zorunlu) |
| `--scan-b` | Yeni tarama ID'si (zorunlu) |

---

### `plugin` — Plugin Yönetimi

YAML tabanlı özel tarama scriptleri oluşturma ve yönetme.

```bash
# Yüklü plugin'leri listele
shadowgraph plugin

# Örnek plugin oluştur (./plugins dizinine)
shadowgraph plugin --init

# Özel dizinden plugin'leri yükle
shadowgraph plugin --dir /path/to/plugins
```

**Flagler:**

| Flag | Açıklama |
|---|---|
| `--init` | Örnek plugin dosyası oluştur |
| `--dir` | Plugin dizini (varsayılan: `./plugins`) |

**Örnek Plugin YAML:**

```yaml
name: http-headers-check
description: HTTP güvenlik header'larını kontrol eder
version: "1.0"
author: ShadowGraph
trigger:
  service: http
  port: 80,443,8080
commands:
  - cmd: "curl -sI http://{target}:{port}"
    description: "HTTP header'larını al"
timeout: 30
```

**Placeholder'lar:**

| Placeholder | Açıklama |
|---|---|
| `{target}` | Hedef IP veya domain |
| `{port}` | Port numarası |
| `{service}` | Tespit edilen servis adı |

---

## Konfigürasyon

ShadowGraph, YAML formatında konfigürasyon dosyası destekler. Aşağıdaki konumlardan otomatik okunur:

1. `./config.yaml` (çalışma dizini)
2. `~/.shadowgraph/config.yaml` (home dizini)

### Örnek `config.yaml`

```yaml
# NVD API anahtarı (opsiyonel, rate limit'i artırır)
# https://nvd.nist.gov/developers/request-an-api-key adresinden alınabilir
nvd_api_key: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Varsayılan tarama profili
default_profile: standard

# Proxy ayarları (kurumsal ağlar için)
proxy:
  http: "http://proxy.company.com:8080"
  https: "http://proxy.company.com:8080"

# Web Dashboard ayarları
ui:
  port: 8080

# Tarama motoru ayarları
scan:
  workers: 100          # Eşzamanlı goroutine sayısı
  rate_limit_ms: 0      # Portlar arası bekleme (ms), 0 = yok

# Plugin sistemi
plugins:
  dir: "plugins"        # Plugin dizini
  enabled: true         # Plugin sistemi aktif mi

# Loglama
logging:
  level: "INFO"         # DEBUG, INFO, WARN, ERROR, FATAL
  file: "shadowgraph.log"  # Log dosyası (boş = yalnızca stdout)
  json: false           # JSON formatında log
  max_size_mb: 10       # Log dosyası rotasyon boyutu

# AI Analiz sağlayıcı ayarları
ai:
  provider: "rule-based"     # "rule-based" veya "ollama"
  ollama:
    host: "http://localhost:11434"  # Ollama API adresi
    model: "llama3.1:8b"            # Kullanılacak model
    temperature: 0.2                # Üretim sıcaklığı
    timeout_sec: 120                # Maksimum bekleme süresi (saniye)

# Güvenlik ağı ayarları
safety:
  max_retries: 2                    # Başarısız sorgular için yeniden deneme
  confirm_large_subnet: true        # /16 ve üstü subnet'ler için kullanıcı onayı iste
```

### Ortam Değişkenleri

Ortam değişkenleri config dosyasını override eder:

| Değişken | Açıklama |
|---|---|
| `SHADOWGRAPH_NVD_KEY` | NVD API anahtarı |
| `SHADOWGRAPH_PROXY` | HTTP/HTTPS proxy URL'si |
| `OLLAMA_HOST` | Ollama API adresi (varsayılan: `http://localhost:11434`) |
| `SHADOWGRAPH_AI_PROVIDER` | AI sağlayıcı override (`rule-based` veya `ollama`) |

---

## CDN/WAF False Positive Koruması

Birçok web sunucusu Cloudflare, Akamai, Fastly gibi CDN/WAF servisleri arkasında çalışır. Bu servislerin banner'ları (örn. `cloudflare`) NVD'ye sorgulandığında, arkadaki gerçek uygulamayla alakasız CVE'ler döner. ShadowGraph bu sorunu otomatik olarak çözer.

**Tespit Edilen Servisler (25+):**

CDN: Cloudflare, Akamai, Fastly, CloudFront, KeyCDN, MaxCDN, StackPath, CDN77, BunnyCDN, Azure CDN, Google Cloud CDN

WAF: Sucuri, Imperva/Incapsula, Barracuda, F5 BIG-IP, FortiWeb, Wallarm, ModSecurity, AWS WAF, Azure WAF

Proxy/Cache: Varnish, Squid, Envoy, Traefik

**Çalışma Şekli:**
1. Port taraması sırasında servis banner'ı alınır
2. `IsShieldedService()` fonksiyonu hem servis adını hem de banner metnindeki CDN/WAF imzalarını (`cf-ray`, `x-amz-cf`, `x-varnish` vb.) kontrol eder
3. CDN/WAF tespit edilirse NVD CVE sorgusu ve ExploitDB eşleşmesi **atlanır**
4. Graf'a `"shield"` tipinde bir düğüm eklenir
5. Dashboard'da turuncu kalkan ikonu ile gösterilir
6. HTML raporda ayrı bir bölümde listelenir

---

## Graf Veri Modeli

ShadowGraph tüm tarama verilerini bir graf (node + edge) yapısında modeller:

### Düğüm (Node) Tipleri

| Tip | Açıklama | Dashboard İkonu | Renk |
|---|---|---|---|
| `target` | Taranan hedef (IP/domain) | Sunucu | Cyan |
| `port` | Açık port | Kapı | Yeşil (güvenli) / Kırmızı (zafiyetli) |
| `endpoint` | Tespit edilen servis | Terminal | Sarı |
| `vulnerability` | CVE zafiyeti | Bug | Kırmızı |
| `exploit` | Bilinen exploit | Yıldırım | Mor |
| `shield` | CDN/WAF koruması | Kalkan | Turuncu |

### Bağlantı (Edge) Tipleri

| Edge | Anlam |
|---|---|
| `has_port` | Hedefin açık portu |
| `runs_service` | Portun üzerinde çalışan servis |
| `vulnerable_to` | Servisin sahip olduğu zafiyet |
| `has_exploit` | Zafiyet için bilinen exploit |
| `shielded_by` | Portun CDN/WAF arkasında olması |

---

## Proje Yapısı

```
ShadowGraph/
├── main.go                              # Giriş noktası
├── go.mod                               # Go modül tanımı
├── go.sum                               # Bağımlılık hash'leri
├── Makefile                             # Build ve yardımcı komutlar
├── Dockerfile                           # Multi-stage Docker build
├── .dockerignore                        # Docker build ignore
├── LICENSE                              # MIT Lisans
├── README.md                            # Bu dosya
│
├── .github/                             # GitHub CI/CD ve şablonlar
│   ├── workflows/
│   │   ├── ci.yml                       # Sürekli entegrasyon (test + build)
│   │   └── release.yml                  # Tag push ile otomatik release
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml               # Hata bildirimi şablonu
│   │   ├── feature_request.yml          # Özellik isteği şablonu
│   │   └── config.yml                   # Issue seçici ayarı
│   └── pull_request_template.md          # PR şablonu
│
├── cmd/                                 # CLI komutları (Cobra)
│   ├── root.go                          # Kök komut, banner ve yardım
│   ├── scan.go                          # scan komutu — ağ taraması
│   ├── scans.go                         # scans komutu — geçmiş tarama listesi
│   ├── importcmd.go                     # import komutu — Nmap/Masscan aktarma
│   ├── analyze.go                       # analyze komutu — AI saldırı analizi
│   ├── ui.go                            # ui komutu — web dashboard (go:embed)
│   ├── export.go                        # export komutu — rapor oluşturma
│   ├── diff.go                          # diff komutu — tarama karşılaştırma
│   ├── plugin.go                        # plugin komutu — script yönetimi
│   └── frontend/                        # Gömülü web arayüzü (go:embed)
│       ├── index.html                   # Dashboard HTML
│       ├── app.js                       # Dashboard JavaScript
│       └── styles.css                   # Dashboard CSS
│
├── docs/                                # Dokümantasyon
│   ├── PLUGINS.md                       # Plugin geliştirme kılavuzu
│   └── VERIFICATION.md                  # Doğrulama testleri
│
├── internal/                            # İç paketler
│   ├── ai/
│   │   ├── attackpath.go                # DFS saldırı yolu analizi, risk skoru, zincir tespiti
│   │   ├── attackpath_test.go           # Analiz birim testleri
│   │   └── providers/                   # AI sağlayıcı katmanı
│   │       ├── provider.go              # Sağlayıcı arayüzü + fallback mekanizması
│   │       ├── factory.go               # Sağlayıcı fabrikası
│   │       ├── rulebased.go             # Kural tabanlı analiz (varsayılan)
│   │       └── ollama.go                # Ollama yerel LLM entegrasyonu
│   ├── auth/
│   │   └── auth.go                      # JWT token üretimi ve doğrulama (gelecek kullanım)
│   ├── config/
│   │   └── config.go                    # YAML konfigürasyon + ortam değişkenleri
│   ├── db/
│   │   ├── db.go                        # SQLite bağlantı, scan CRUD
│   │   ├── api.go                       # Graph JSON API (node + edge, scan filtreleme)
│   │   ├── analysis.go                  # AI analiz kaydetme/okuma
│   │   └── migration.go                 # Versiyonlu DB migration sistemi
│   ├── diff/
│   │   └── diff.go                      # Tarama fark karşılaştırması
│   ├── importer/
│   │   └── nmap.go                      # Nmap XML + Masscan JSON parser
│   ├── logger/
│   │   └── logger.go                    # Yapılandırılmış loglama (JSON, dosya, rotasyon)
│   ├── plugin/
│   │   └── plugin.go                    # YAML plugin sistemi
│   ├── report/
│   │   ├── report.go                    # JSON / CSV export
│   │   └── html_report.go               # HTML profesyonel rapor (AI + SVG dahil)
│   └── scanner/
│       ├── scanner.go                   # Ana tarama motoru (concurrent TCP/UDP)
│       ├── cidr.go                      # CIDR blok genişletme + dosya hedef yükleme
│       ├── cve_api.go                   # NVD REST API v2.0 istemcisi
│       ├── exploit_db.go                # ExploitDB / Metasploit eşleştirme
│       ├── fingerprint.go               # OS fingerprinting (TTL)
│       ├── ports.go                     # Port listeleri, profiller, UDP payload'lar
│       └── service_db.go                # 300+ servis imzası + CDN/WAF tespit
│
└── plugins/                             # Plugin dizini (opsiyonel)
    └── *.yaml                           # YAML plugin tanımları
```

---

## Tipik Kullanım Senaryosu

```bash
# 1. Hedef ağı tara (scan ID otomatik oluşur)
shadowgraph scan -t 192.168.1.0/24 --profile standard --workers 150

# 2. Nmap sonuçlarını da içe aktar (opsiyonel)
nmap -sV -sC -oX detailed_scan.xml 192.168.1.0/24
shadowgraph import -f detailed_scan.xml

# 3. Geçmiş taramaları listele
shadowgraph scans

# 4. AI saldırı yolu analizini çalıştır
shadowgraph analyze --scan-id 1 --output attack_paths.json

# 5. Dashboard'da görselleştir (tarayıcı otomatik açılır)
shadowgraph ui --scan-id 1

# 6. Profesyonel rapor oluştur
shadowgraph export --format html --scan-id 1 --output security_report.html

# 7. Bir süre sonra tekrar tara ve karşılaştır
shadowgraph scan -t 192.168.1.0/24
shadowgraph diff --scan-a 1 --scan-b 2

# Alternatif: Tarama + Dashboard tek komutla
shadowgraph scan -t 192.168.1.1 --ui
```

---

## Bilinen Exploit Veritabanı

ShadowGraph, yaygın kullanılan yazılımlardaki bilinen exploit'leri otomatik eşleştirir:

| Yazılım | Exploit | Kaynak |
|---|---|---|
| Apache 2.4.49-50 | Path Traversal & RCE | ExploitDB (EDB-50383) |
| Apache mod_proxy | SSRF | Metasploit |
| Nginx 0.6.18-1.13.2 | Integer Overflow | ExploitDB |
| OpenSSH 2.3-7.6 | Username Enumeration | ExploitDB |
| OpenSSH 8.5-9.7 | RegreSSHion RCE | ExploitDB (EDB-51994) |
| vsftpd 2.3.4 | Backdoor Command Execution | Metasploit |
| ProFTPD 1.3.5 | mod_copy RCE | Metasploit |
| Log4j | Log4Shell RCE | Metasploit |
| Spring Framework | Spring4Shell RCE | ExploitDB |
| Exchange Server | ProxyLogon/ProxyShell | Metasploit |
| Drupal | Drupalgeddon2 RCE | Metasploit |
| ve 20+ daha... | | |

---

## Yasal Uyarı

Bu araç **yalnızca yasal ve yetkili güvenlik testleri** için tasarlanmıştır. İzinsiz ağ taraması birçok ülkede yasadışıdır. Kullanıcı, aracı yalnızca kendi sahip olduğu veya yazılı izin aldığı sistemlerde kullanmalıdır. Geliştiriciler, aracın kötüye kullanımından doğabilecek yasal sonuçlardan sorumlu değildir.

---

## Katkıda Bulunma

Pull request'ler ve issue'lar memnuniyetle karşılanır. Katkıda bulunmak için:

1. Repo'yu fork edin
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Değişikliklerinizi commit edin
4. Branch'inizi push edin (`git push origin feature/yeni-ozellik`)
5. Pull Request açın

---

## Lisans

MIT License — Detaylar için [LICENSE](LICENSE) dosyasına bakın.
