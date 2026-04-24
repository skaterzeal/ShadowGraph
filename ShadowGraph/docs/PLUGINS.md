# ShadowGraph Plugin Sistemi

ShadowGraph, YAML tabanlı **plugin** (eklenti) sistemi ile tarama sırasında
özel komutlar/scriptler çalıştırmanıza olanak tanır. Plugin'ler Go kodu
yazmadan, sadece bir YAML dosyası oluşturarak genişletilebilir.

> Kısa tanım: Bir plugin; **trigger**'a (port/servis) göre tetiklenen, sırayla
> çalışan kabuk komutlarından oluşan bir dosyadır. Komutlar hedef/port/servis
> gibi placeholder'lar ile parametrelenir.

## İçindekiler

- [Hızlı başlangıç](#hızlı-başlangıç)
- [Plugin dosya yapısı](#plugin-dosya-yapısı)
- [Alan referansı](#alan-referansı)
- [Placeholder'lar ve ortam değişkenleri](#placeholderlar-ve-ortam-değişkenleri)
- [Trigger (tetikleyici) eşleşme mantığı](#trigger-eşleşme-mantığı)
- [Komut akışı ve hata davranışı](#komut-akışı-ve-hata-davranışı)
- [Zaman aşımı](#zaman-aşımı)
- [Kategoriler](#kategoriler)
- [Örnekler](#örnekler)
- [CLI komutları](#cli-komutları)
- [Güvenlik notları](#güvenlik-notları)
- [Sınırlamalar](#sınırlamalar)

## Hızlı başlangıç

1. Örnek plugin oluşturun:

   ```bash
   shadowgraph plugin --init
   ```

   Bu komut `./plugins/http-headers-check.yaml` dosyasını yaratır.

2. Yüklü plugin'leri listeleyin:

   ```bash
   shadowgraph plugin
   ```

3. Özel bir dizinden yüklemek isterseniz:

   ```bash
   shadowgraph plugin --dir /etc/shadowgraph/plugins
   ```

Plugin'ler, tarama sırasında port/servis eşleşmesine göre otomatik
çalıştırılır. Plugin yazmak için Go bilmenize gerek yoktur — sadece YAML.

## Plugin dosya yapısı

Plugin'ler tek bir YAML dosyası olarak tanımlanır:

```yaml
name: http-headers-check
description: HTTP güvenlik header'larını kontrol eder
author: ShadowGraph Community
version: "1.0"
category: recon
triggers:
  - http
  - https
  - "80"
  - "443"
timeout: 15
commands:
  - name: "Security Headers Check"
    run: "curl -sI -o /dev/null -w '%{http_code}' --max-time 5 http://{target}:{port}"
    on_fail: continue
  - name: "HSTS Header"
    run: "curl -sI --max-time 5 http://{target}:{port} | grep -i strict-transport"
    on_fail: continue
```

Dosya adı serbesttir, ancak `.yaml` veya `.yml` uzantısı ile bitmelidir.
Plugin dizini varsayılan olarak çalışma dizinindeki `./plugins` klasörüdür.

## Alan referansı

| Alan          | Tip        | Zorunlu | Açıklama |
|---------------|------------|---------|----------|
| `name`        | string     | ✅      | Plugin'in benzersiz adı. Loglarda görünür. |
| `description` | string     | ✅      | Kısa açıklama. `shadowgraph plugin` listesinde gösterilir. |
| `author`      | string     | ⛔ (önerilen) | Plugin yazarı. |
| `version`     | string     | ⛔ (önerilen) | Anlamsal versiyon (ör. `"1.0"`). |
| `category`    | string     | ⛔      | Kategori etiketi: `recon`, `vuln`, `exploit`, `aux`, `report`. |
| `triggers`    | []string   | ✅      | Tetikleyici port numaraları / servis adları. Bkz. [trigger eşleşme](#trigger-eşleşme-mantığı). |
| `timeout`     | int (sn)   | ⛔      | Plugin'in toplam yürütme süresi için tavsiye edilen üst sınır (saniye). Varsayılan 30. |
| `commands`    | []Step     | ✅      | Sırayla çalıştırılacak komut adımları. En az bir adım olmalı. |

### Step (komut adımı) alanları

| Alan      | Tip    | Zorunlu | Açıklama |
|-----------|--------|---------|----------|
| `name`    | string | ✅      | Adımın insan-okur adı. |
| `run`     | string | ✅      | Kabukta çalıştırılacak komut. |
| `args`    | string | ⛔      | `run` sonuna boşlukla eklenir; opsiyonel parametreler için. |
| `on_fail` | string | ⛔      | `continue` (devam et) veya boş/`abort` (durdur). Varsayılan durdurmadır. |

## Placeholder'lar ve ortam değişkenleri

Her komut, çalıştırılmadan önce şu placeholder'larla genişletilir:

| Placeholder   | Açıklama                          |
|---------------|-----------------------------------|
| `{target}`    | Hedef adres (IP veya hostname)    |
| `{port}`      | Tetikleyen port numarası          |
| `{service}`   | Tetikleyen servis adı             |
| `$SG_TARGET`  | `{target}` ile aynı değer         |
| `$SG_PORT`    | `{port}` ile aynı değer           |
| `$SG_SERVICE` | `{service}` ile aynı değer        |

Ek olarak, komut çalışırken bu değerler ortam değişkeni olarak da
ayarlanır:

```bash
SG_TARGET=10.0.0.5
SG_PORT=443
SG_SERVICE=https
```

Böylece kendi scriptlerinizde `$SG_TARGET` gibi alışılmış değişkenleri
kullanabilirsiniz.

## Trigger eşleşme mantığı

Bir plugin'in çalıştırılabilmesi için `triggers` dizisinden en az birinin
aşağıdaki koşullardan **herhangi** birini sağlaması yeterlidir:

- Trigger `*` ise (wildcard — her zaman çalışır).
- Trigger, servis adına bire bir eşit (küçük/büyük harf duyarsız).
- Trigger, port numarasına bire bir eşit (string karşılaştırma).
- Trigger ifadesi, servis adının bir alt dizesi ise (ör. trigger `http`,
  servis `nginx-http-proxy` → eşleşir).

Trigger değerleri karşılaştırılırken küçük harfe normalize edilir.

> **Performans ipucu**: Çok geniş tetikleyiciler (`*` veya tek harfli alt
> diziler) pahalı olabilir. Mümkün olduğunca spesifik port/servis adları
> kullanın.

## Komut akışı ve hata davranışı

- Komutlar `commands` dizisindeki **sırayla** çalıştırılır.
- Her adım için `exec.Command("sh", "-c", cmd)` çağrılır; çıktı
  (stdout+stderr birleşik) toplanır.
- Adım başarısız olursa:
  - `on_fail: continue` ise uyarı basılır, sonraki adım çalışır.
  - Aksi halde plugin başarısız sayılır ve kalan adımlar atlanır.
- Tüm adımlar başarılıysa `PluginResult.Success = true` döner.

## Zaman aşımı

`timeout` alanı plugin'in toplam yürütme süresi için tavsiye edilen üst
sınırdır. Bireysel `run` komutlarının kendi iç zaman aşımını yönetmesi
önerilir (örn. `curl --max-time 5`, `nmap --host-timeout 30s`).

> ⚠️  Şu an için `timeout` değeri plugin yürütücüsü tarafından zorla
> uygulanmaz; sadece dokümante edilen bir beklentidir. Planlanan
> iyileştirmelerde `context.WithTimeout` ile sert limit getirilecektir.

## Kategoriler

`category` alanı için kullanılan etiketler:

- `recon` — bilgi toplama (header check, banner grab, vs.)
- `vuln` — zafiyet tarama (nmap NSE, nikto, vb.)
- `exploit` — sömürü denemeleri (**dikkatli kullanın, yetkiniz olduğundan emin olun**)
- `aux` — yardımcı araçlar (log toplama, format dönüşümleri)
- `report` — raporlama adımları

Kategori zorunlu değildir, ama `shadowgraph plugin` çıktısında görünür ve
gelecekte filtreleme için kullanılabilir.

## Örnekler

### 1) HTTP güvenlik header kontrolü

```yaml
name: http-headers-check
description: HTTP güvenlik header'larını kontrol eder
author: ShadowGraph Community
version: "1.0"
category: recon
triggers: [http, https, "80", "443", "8080"]
timeout: 15
commands:
  - name: "HTTP Status"
    run: "curl -sI -o /dev/null -w '%{http_code}\\n' --max-time 5 http://{target}:{port}"
    on_fail: continue
  - name: "HSTS Header"
    run: "curl -sI --max-time 5 http://{target}:{port} | grep -i strict-transport"
    on_fail: continue
```

### 2) SSH banner grab

```yaml
name: ssh-banner
description: SSH servisinin banner bilgisini yakalar
category: recon
triggers: [ssh, "22"]
timeout: 5
commands:
  - name: "Banner"
    run: "timeout 3 bash -c 'cat < /dev/tcp/{target}/{port}'"
    on_fail: continue
```

### 3) Nmap NSE vuln scriptleri

```yaml
name: nmap-vuln
description: Nmap NSE vuln kategorisini çalıştırır
category: vuln
triggers: ["*"]
timeout: 120
commands:
  - name: "NSE vuln"
    run: "nmap -Pn --script vuln -p {port} {target}"
    on_fail: continue
```

## CLI komutları

```bash
# Yüklü plugin'leri listele (varsayılan dizin: ./plugins)
shadowgraph plugin

# Örnek plugin oluştur (http-headers-check.yaml)
shadowgraph plugin --init

# Alternatif bir plugin dizininden yükle
shadowgraph plugin --dir /etc/shadowgraph/plugins
```

Plugin dizini mevcut değilse sessizce atlanır — hata verilmez.

## Güvenlik notları

Plugin'ler doğrudan **kabuk komutu** çalıştırır (`sh -c ...`). Bu çok
güçlü, ama aynı zamanda risklidir:

- Yalnızca **güvenilir kaynaklardan** gelen plugin'leri yükleyin.
- `curl | sh` gibi uzak-script çalıştıran plugin'lerden kaçının.
- Üretim ortamlarında plugin dizinini salt-okunur tutun ve dosya
  sahipliğini kısıtlayın (ör. `chown root:root`, `chmod 644`).
- Yetkisiz sistemlerde **exploit** kategorisindeki plugin'leri
  çalıştırmayın.
- Placeholder değerleri hedef adrestir — **kullanıcı girdisi**
  niteliğindedir; komutlarınızı yazarken shell metacharacter sorunlarına
  karşı dikkatli olun (çift tırnak, uygun kaçışlar).
- Plugin çıktısı tarama loglarına kaydedilir; hassas veri basmamaya özen
  gösterin.

## Sınırlamalar

Mevcut implementasyonun bilinen kısıtları (gelecekte geliştirilebilir):

- `timeout` alanı sert olarak uygulanmıyor (bkz. yukarıdaki not).
- Plugin başına `context.Context` iptali ileri sürümde gelecek.
- Tekrarlı (`parallel`) adım çalıştırma yok; komutlar her zaman seri.
- YAML şema doğrulaması minimal — eksik/bozuk alanlar çalışma zamanında
  tespit edilebilir.
- Adımlar arası **iletişim** (bir adımın çıktısını diğerine vermek) yok;
  gerekirse `run` alanında tek bir kabuk pipeline'ı yazın.

---

Yeni plugin fikirleriniz varsa PR açmaktan veya issue oluşturmaktan
çekinmeyin. İyi avlar! 🕵️
