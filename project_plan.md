# ShadowGraph İyileştirme Planı (v2 — Karmagen onayıyla)

Bu plan, `iyilestirme_onerileri.txt` ve tartışma sonuçlarına göre hazırlanmıştır. Tüm maddeler kullanıcı tarafından onaylanmıştır (18 Nisan 2026).

---

## Faz 1 — Temizlik ve Kritik Bug'lar (ÖNCELİK)

### 1.1 DB scan_id bug fix (C1)
- `scanner.go`'daki tüm `db.AddNode` → `db.AddNodeWithScan(scanID, ...)`
- Tüm `db.AddEdge` → `db.AddEdgeWithScan(scanID, ...)`
- `StartReconWithConfig` ve `scanTCPPortsConcurrent` imzasına `scanID int64` eklensin
- `scanUDPPorts`'a da `scanID` eklensin
- Tek hedef taramasında (`len(targets)==1`) da `db.CreateScan` + `db.FinishScan` çağrılsın
- Tamamlanan scan'ın ID'si stdout'a yazılsın (`Scan ID: N`)

### 1.2 --scan-id flag ve filtreleme (C2)
- `db.GetGraphData(scanID int64)` imzası değişsin; `scanID <= 0` → `MAX(id) FROM scans`
- `cmd/ui.go`'ya `--scan-id` flag'i
- `cmd/analyze.go`'ya `--scan-id` flag'i
- Yeni `shadowgraph scans` komutu (DB'deki `ListScans`'ı expose eder)
- `cmd/scan.go` satır 92-93'teki `DELETE FROM ... WHERE scan_id = 0` workaround'u silinsin

### 1.3 DB migration sistemi (Ek öneri E1)
- `schema_version` tablosu
- Numaralı migration'lar (001_initial.sql, 002_analyses.sql, ...)
- İlk migration'da mevcut tablo yapısı
- Kırılgan `ALTER TABLE ... ADD COLUMN` workaround'ları kalksın

---

## Faz 2 — UI Refactor

### 2.1 go:embed refactor (D3)
- `frontend/dashboard.html`, `frontend/style.css`, `frontend/app.js` olarak ayrıştır
- `//go:embed frontend/*` ile binary'e göm
- `cmd/ui.go` sadeleşecek

### 2.2 Refresh butonu + Scan seçici dropdown (A3 - Seçenek 1)
- Üst bara REFRESH butonu (manuel)
- Opsiyonel auto-poll toggle (5 saniye)
- Üst bara scan seçici dropdown (tüm scan'ları listeler)
- `/api/scans` endpoint'i

### 2.3 Tarayıcı auto-open + scan --ui flag (A2)
- Platform bazlı browser opener: `start` (Windows), `xdg-open` (Linux), `open` (macOS)
- `ui` komutu varsayılanda açsın, `--no-open` ile kapatılabilsin
- `scan --ui`: tarama bitince UI sunucusu başlasın, **Ctrl+C'ye kadar açık kalsın**

---

## Faz 3 — Rapor ve Analiz Entegrasyonu

### 3.1 analyze çıktısı DB'ye ve UI'a (A4)
- Yeni `analyses` tablosu (scan_id FK, created_at, summary, json_data)
- `cmd/analyze.go` sonucu DB'ye yazsın
- UI'a "ATTACK PATHS" paneli
- UI'a "Run Analysis" butonu → `/api/analyze` POST endpoint

### 3.2 HTML rapor iyileştirmesi (A1 — kısa vade, SVG snapshot)
- Executive summary (toplam zafiyet, kritik sayısı, risk skoru)
- CVE detay tablosu (her CVE için severity + desc + affected service)
- Network SVG/PNG snapshot (vis.js `network.canvas.frame.canvas.toDataURL()`)
- AI analiz sonucu embed
- `@media print` ile A4 sayfa bölünmesi

---

## Faz 4 — AI Yeniden Yapılandırma

### 4.1 Rule-based agregasyon bug fix (B1)
- "Risk 9.0 ama ciddi saldırı yolu yok" tutarsızlığının kaynağı çöz
- CVSS vector parsing
- Zincirleme bonus (2+ CVE varsa çarpım)
- Lateral movement heuristic'leri (SMB+RDP, exposed DB+web shell)

### 4.2 AI Provider Abstraction (Ö1 — sadece Ollama + rule-based)
- `internal/ai/providers/` klasörü
- `Provider` interface: `AnalyzePaths(paths []AttackPath) (*EnrichedAnalysis, error)`
- `providers/ollama.go` ve `providers/rulebased.go` (fallback)
- Config'ten seçim: `ai.provider: ollama`

### 4.3 Ollama Provider (B2, Ö3)
- Default endpoint: `http://localhost:11434`
- `OLLAMA_HOST` env var okusun
- **Ö3:** Rule-based DFS path'leri LLM'e verilir; LLM SADECE narrative/risk/remediation üretir
- Structured JSON output zorunlu (`format: "json"`)
- Model config'ten (default: `llama3.1:8b`)
- Reachability check → bağlantı yoksa rule-based fallback
- **Ö4:** Canlı test kullanıcı tarafından yapılacak

---

## Faz 5 — Dağıtım ve Topluluk

### 5.1 Safety net + NVD rate limiting (D6, Ö7)
- `--max-retries N` flag
- Exponential backoff (429/timeout'ta worker sayısı düşsün)
- `/16` veya büyük subnet için interaktif onay (y/N)
- `cve_api.go`'ya `time.Sleep` rate limiter (saniyede 5)
- **Ö7:** NVD API key desteği (config dosyasında, varsa saniyede 50)
- README'ye safety/rate-limit notu

### 5.2 GitHub Actions release (D1)
- `.github/workflows/release.yml`
- `v*` tag push'ında Windows / Linux / macOS binary
- SHA256 checksum + GitHub Releases upload
- **Not:** Push ve tag'leme kullanıcı tarafından yapılacak

### 5.3 Dockerfile (D2, Ö5)
- Multi-stage (alpine builder + alpine veya scratch runtime)
- Target boyut: 10-15 MB
- README'de `--cap-add=NET_RAW` notu (ICMP fingerprint için)
- **Not:** Build/test kullanıcı tarafından yapılacak

### 5.4 Issue/PR şablonları (D4)
- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/ISSUE_TEMPLATE/feature_request.md`
- `.github/pull_request_template.md`
- OS, komut, hata log alanları

### 5.5 Ek iyileştirmeler (E2-E5)
- Error wrapping: `fmt.Errorf("...: %w", err)` pattern
- `context.Context` propagation (scanner'a Ctrl+C temiz kapatma)
- Scanner'daki `fmt.Printf`'leri `logger` paketine bağla (stdout kalsın, ayrıca log'a gitsin)
- Kritik paketlere unit test (scanner/ports, ai/attackpath, db)

### 5.6 PLUGINS.md (D5 — EN SON)
- `internal/plugin/` kaynağından reverse-engineer
- YAML format, placeholder'lar, beklentiler
- Örnek plugin

---

## Atlanan / Ertelenen

- **E6 (API auth/token):** Enterprise sürüme ertelendi. Bu plana dahil değil.
- **PDF için chromedp:** Kısa vade (SVG snapshot + print CSS) tercih edildi; binary boyutu artırmamak için.
- **WebSocket/SSE canlı akış:** Faz 2.2'de refresh butonu yeterli görüldü; ileride eklenebilir.
- **OpenAI-compatible provider:** Şimdilik sadece Ollama + rule-based. Gerekirse sonra eklenecek (interface hazır).
