# ShadowGraph 5 Bug Fix Planı

## Tespit Edilen Sorunlar ve Kök Nedenleri

### 1. Ollama Provider Çalışmıyor (rule-based'a düşüyor)
**Kök neden:** `analyze.go` L118'de health check timeout 5 saniye. Ancak asıl sorun Ollama'nın `http://localhost:11434` yerine `http://127.0.0.1:11434`'te çalışması olabilir. Windows'ta `localhost` çözümlemesi IPv6'ya (`::1`) yönlenip Ollama'nın IPv4 (`127.0.0.1`) adresine ulaşamaması çok yaygın bir sorun. Ayrıca hata mesajı ekrana yazdırılıyor ama çok hızlı geçiyor olabilir.

**Çözüm:**
- `providers/ollama.go` L33: Default host'u `http://127.0.0.1:11434` olarak değiştir
- `providers/provider.go` L112: Default config'i de `http://127.0.0.1:11434` yap
- `config/config.go` L64: Default config'i de güncelle
- Health check başarısız olursa DAHA belirgin hata mesajı yazdır

---

### 2. Risk Skorlama Yanlış — Zincirleme Saldırı Skoru Yansımıyor
**Kök neden:** `attackpath.go` L137-149'da genel risk skoru YALNIZCA bireysel path skorlarından hesaplanıyor. `detectChainedAttacks` fonksiyonu 9.0 risk buluyor AMA bu skor `OverallRiskScore`'a hiç yansımıyor! Ayrıca `severity` alanı "N/A" veya boş olduğunda default case'e düşüp 2.5 veriyor - NVD'den gelen severity formatı tam eşleşmiyor olabilir.

**Çözüm (attackpath.go):**
- L148 sonrasına: Zincirleme saldırı risk skorunu overall score'a dahil et
- Formül: `max(path_risk, max_chain_risk)` → en yüksek chain risk'ini göz ardı etme
- `generateRecommendations`: Risk level hesabında chained attacks'i de dikkate al
- `calculatePathRisk`: Severity eşleşmesini daha toleranslı yap (sayısal CVSS desteği ekle)

---

### 3. PDF/Print Çıktısı Eksik — Sadece 1 Sayfa, Alt Paneller Yok
**Kök neden:** `styles.css` L59'da `@media print` kuralı çok basit. `.bot` grid layout `display:block` olmuş ama:
- `overflow:hidden` kaldırılmamış (content clipping)
- `height:100vh` kaldırılmamış (1 sayfaya sıkıştırıyor)
- Renk/arka plan yazdırılmıyor (tarayıcılar varsayılan olarak arka plan rengi yazdırmaz)
- SCAN RESULTS, AI ANALYSIS, PORTS & VULNS tabloları overflow gizliyor

**Çözüm (styles.css):**
- Print mode'da `height:auto`, `overflow:visible !important` uygula
- `.pan`, `.tc` için overflow hidden kaldır
- Tüm panellere `page-break-inside: avoid` ekle
- Arka plan renkleri için `-webkit-print-color-adjust: exact` ekle
- Network haritası için sabit yükseklik ayarla
- Tablo, badge, gauge renklerini print-friendly yap

---

### 4. Servis İsimleri "Bulunamadı" Olarak Görünüyor  
**Kök neden:** Kullanıcının kastettiği muhtemelen dashboard'daki SCAN RESULTS tablosunda hostname/device sütununun boş veya hatalı gösterilmesi. `app.js` L93'te `pd.hostname||t.label.split('\n')[0]` kullanılıyor — hostname data'da yoksa label'dan alıyor. Bu kısım sorunsuz görünüyor, ama kullanıcı screenshot'ından görebildiğim kadarıyla veriler doğru görünüyor. Bu sorun tarama sonucuyla ilgili olabilir, eğer banner alınamadıysa servis "Unknown" olarak kaydediliyor. Bu daha çok scanner tarafında bir konu.

> [!NOTE]
> Bu sorun için kullanıcıdan daha fazla detay gerekebilir. Eğer dashboard'daki servis isimleri kastetiliyorsa, kodda sorun yok. Eğer tarama sırasında servis tespit edilemiyorsa, scanner/service_db.go'daki imza eşleşmesi konusu.

---

### 5. PORTS & VULNS Tablosunda Portlar Renksiz
**Kök neden:** `app.js` L103-104'te portlar her zaman yeşil (`#10b981`) ile gösteriliyor. Zafiyet bulunan portların kırmızı olması gerekiyor ama `hasVulnChild()` fonksiyonu sadece graf ağacı için kullanılıyor, tablo renderında kullanılmıyor.

**Çözüm (app.js):**
- Port satırlarında `hasVulnChild(n.id)` kontrolü ekle
- Zafiyetli portları kırmızı, temiz olanları yeşil göster

---

## Proposed Changes

### Dosya Değişiklikleri

#### [MODIFY] [attackpath.go](file:///d:/Projects/ai/ShadowGraph/internal/ai/attackpath.go)
- Zincirleme saldırı risk skorunu overall score'a dahil et
- Severity eşleşmesinde sayısal CVSS desteği ekle  
- Recommendation logic'te chained attack bilincini ekle

#### [MODIFY] [ollama.go](file:///d:/Projects/ai/ShadowGraph/internal/ai/providers/ollama.go)
- Default host: `http://127.0.0.1:11434`

#### [MODIFY] [provider.go](file:///d:/Projects/ai/ShadowGraph/internal/ai/providers/provider.go)
- DefaultConfig host: `http://127.0.0.1:11434`

#### [MODIFY] [config.go](file:///d:/Projects/ai/ShadowGraph/internal/config/config.go)
- Default Ollama host: `http://127.0.0.1:11434`

#### [MODIFY] [analyze.go](file:///d:/Projects/ai/ShadowGraph/cmd/analyze.go)
- Ollama fallback hata mesajını daha belirgin yap

#### [MODIFY] [styles.css](file:///d:/Projects/ai/ShadowGraph/cmd/frontend/styles.css)
- Print media queries: overflow/height düzeltmeleri, çok sayfalı print desteği

#### [MODIFY] [app.js](file:///d:/Projects/ai/ShadowGraph/cmd/frontend/app.js)
- PORTS & VULNS tablosunda zafiyetli portları kırmızı göster

## Verification Plan

### Automated Tests
```bash
go test ./internal/ai/... -v
go build -ldflags="-s -w" -o shadowgraph.exe .
```

### Manual Verification
1. `shadowgraph analyze --provider ollama` → Ollama'ya bağlanmalı
2. `shadowgraph analyze` → Chained attack risk'i overall score'a yansımalı
3. Dashboard'da EXPORT PDF → Tüm paneller görünmeli, çok sayfa çıkmalı
4. Dashboard'da PORTS & VULNS → Zafiyetli portlar kırmızı, temiz olanlar yeşil
