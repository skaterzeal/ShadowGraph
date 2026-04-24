# Son Build & Smoke Test Checklist

Bu dosya, 5 fazlık iyileştirme çalışmasının ardından projenin sağlıklı
derlendiğini ve temel özelliklerin çalıştığını doğrulamak için uçtan uca
gidilmesi gereken adımları listeler. Komutlar proje kök dizininde
(`ShadowGraph/`) çalıştırılmalıdır.

İzin / ağ / yerel kurulum gerektiren adımlar (`docker build`, `git push`,
`go install`, Ollama kurulumu vb.) kasıtlı olarak listenin sonunda
bırakılmıştır — bu adımları siz çalıştırın.

---

## 1) Statik kontroller

```bash
go fmt ./...
go vet ./...
go build ./...
```

Beklenen: hepsi hatasız tamamlanır. `go build ./...` aşamasında
`cmd/frontend` altındaki `index.html`, `app.js`, `styles.css` dosyaları
embed edilir.

## 2) Testler

```bash
go test ./...
```

Yeni eklenen test dosyaları:

- `internal/ai/providers/provider_test.go`
- `internal/ai/providers/rulebased_test.go`
- `internal/ai/attackpath_test.go`
- `internal/scanner/ports_test.go`

Beklenen: tüm paketler PASS. (Yalnız `modernc.org/sqlite` kullanıldığı için
CGO gerekmez.)

### Race detector (opsiyonel ama önerilir)

```bash
go test -race ./...
```

## 3) Binary kurulumu

```bash
# Geliştirme sırasında
go run . --help

# Yerel kurulum
go install .
# veya
go build -o shadowgraph .
```

## 4) Smoke test: Tarama

Yerel bir hedef üzerinde hızlı doğrulama:

```bash
./shadowgraph scan -t 127.0.0.1 --profile quick
```

Kontrol noktaları:

- [ ] Scan tamamlanır, DB'ye `scan_id` atanır (log çıktısında görünür).
- [ ] `shadowgraph.db` dosyası oluşur / güncellenir.
- [ ] `ls -la shadowgraph.db` → dosya var.

Büyük CIDR onayı (yeni `--yes / -y` bayrağı):

```bash
./shadowgraph scan -t 10.0.0.0/16      # onay soracak
./shadowgraph scan -t 10.0.0.0/16 -y   # onay sormadan geçecek
```

## 5) Smoke test: UI

```bash
./shadowgraph ui --port 8080
# veya tarama sonrası otomatik açılış:
./shadowgraph scan -t 127.0.0.1 --ui --ui-port 8080
```

Kontrol noktaları:

- [ ] Tarayıcı otomatik açılır (eğer `--no-open` vermediyseniz).
- [ ] Sayfa `/assets/styles.css` ve `/assets/app.js` dosyalarını yükler
      (Developer Tools → Network).
- [ ] Scan dropdown doluyor, **Refresh** butonu çalışıyor.
- [ ] **Run AI Analysis** butonu AI paneline yazıyor.

## 6) Smoke test: Analyze

```bash
./shadowgraph analyze                       # default provider (config)
./shadowgraph analyze --provider rule-based
./shadowgraph analyze --provider ollama --no-save
```

Kontrol noktaları:

- [ ] Rule-based çıktı `OverallRiskScore`, `RiskLevel`,
      `Recommendations` alanlarını içeriyor.
- [ ] Ollama kurulu **değilse** otomatik rule-based'e düşüyor
      (`[yellow]` uyarı logu).
- [ ] `--no-save` vermediyseniz DB'deki `analyses` tablosuna kayıt
      gidiyor.

Ollama kurulu iseniz (ops):

```bash
ollama pull llama3.1:8b
OLLAMA_HOST=http://localhost:11434 ./shadowgraph analyze --provider ollama
```

## 7) Smoke test: HTML raporu

```bash
./shadowgraph report --format html -o ./report.html
xdg-open ./report.html   # Linux
open ./report.html       # macOS
start report.html        # Windows
```

Kontrol noktaları:

- [ ] Rapor SVG network snapshot içeriyor (radial layout).
- [ ] Vulns tablosu severity'e göre sıralı (CRITICAL → LOW).
- [ ] AI bölümü DB'den gelen en son analizi gösteriyor.
- [ ] `@media print` kuralları sayesinde yazdırma görünümü düzgün.

## 8) Plugin sistemi

```bash
./shadowgraph plugin --init
./shadowgraph plugin
```

Kontrol noktaları:

- [ ] `./plugins/http-headers-check.yaml` oluşuyor.
- [ ] `shadowgraph plugin` listesi tabloyu basıyor.
- [ ] Tarama sırasında trigger eşleşirse plugin tetikleniyor
      (stdout'ta `[⚙] Plugin ... → step: cmd` satırı görünüyor).

## 9) DB migration

Eski bir `shadowgraph.db` dosyası ile binary'yi çalıştırın. Beklenen:

- [ ] `schema_version` tablosu otomatik oluşturuluyor.
- [ ] `analyses` tablosu migrasyonla ekleniyor (v3).
- [ ] Eski kayıtlardaki `scan_id` boş değerleri backfill ediliyor
      (bkz. `backfillLegacyScanID`).

## 10) NVD rate-limiter (ops)

API key olmadan:

```bash
./shadowgraph scan -t 10.0.0.5 --enrich
# Log: "NVD: anahtarsız mod, 6.5s aralıklı sorgu"
```

API key ile (environment veya config):

```bash
export SHADOWGRAPH_NVD_API_KEY=xxxx
./shadowgraph scan -t 10.0.0.5 --enrich
# Log: "NVD: API key ile 700ms aralıklı sorgu"
```

429/503 yanıtları `max-retries` sınırına kadar exponential backoff'la
yeniden denenecek.

---

## İzin gerektiren / siz çalıştıracaksınız

### A) Docker

```bash
docker build -t shadowgraph:dev .
docker run --rm -it -v $PWD/data:/data shadowgraph:dev shadowgraph --help
```

- [ ] Multi-stage build, final imaj Alpine tabanlı.
- [ ] Konteyner non-root kullanıcı `shadow` (uid 10001) olarak çalışıyor.
- [ ] `/data` volume persist ediyor.

### B) GitHub Actions

```bash
git add .
git commit -m "feat: 5 faz iyileştirmelerini tamamla"
git push
```

Ardından GitHub üzerinde:

- [ ] `CI` workflow yeşil (build + vet + test + lint matrisi).
- [ ] Bir tag atın ve release workflow'u doğrulayın:

```bash
git tag v0.2.0
git push --tags
```

- [ ] Release workflow linux/darwin/windows × amd64/arm64 binary'lerini
      tar.gz/zip olarak yayınlıyor.
- [ ] `SHA256SUMS.txt` release assets arasında.

### C) Issue / PR şablonları

- [ ] GitHub'da **New Issue** açtığınızda Bug ve Feature formları
      görünüyor, blank issue pasif.
- [ ] **New Pull Request** açtığınızda Türkçe PR template otomatik
      dolduruluyor.

### D) Ollama (ops)

```bash
ollama serve &
ollama pull llama3.1:8b
./shadowgraph analyze --provider ollama
```

- [ ] Healthy kontrolü `/api/tags` üzerinden geçiyor.
- [ ] Ollama cevabı `ValidateResult` ile clamplenip rule-based ile
      harmanlanıyor (0.7*rule + 0.3*llm).

---

## Hızlı komut özeti

```bash
go fmt ./... && go vet ./... && go build ./... && go test ./...
./shadowgraph scan -t 127.0.0.1 --profile quick --ui --ui-port 8080
./shadowgraph analyze --provider rule-based
./shadowgraph report --format html -o report.html
./shadowgraph plugin --init && ./shadowgraph plugin
```

Tüm kutular işaretlendiğinde release için hazırsınız. İyi avlar. 🕷️
