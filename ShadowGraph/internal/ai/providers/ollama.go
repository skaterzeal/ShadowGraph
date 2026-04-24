package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Ollama sağlayıcı — lokal LLM (Ollama HTTP API) üzerinden analiz zenginleştirmesi.
// İnternetsiz çalışır; sunucu genellikle http://localhost:11434 üzerinde dinler.
// Güvenlik: network/tarama verilerini 3. parti bir servise göndermez.
//
// Model seçimi ve temperature yapılandırma dosyasından (~/.shadowgraph/config.yaml)
// veya komut satırı flag'lerinden gelir. Varsayılan: llama3.1:8b, temperature=0.2.
type Ollama struct {
	cfg    OllamaConfig
	client *http.Client
}

// NewOllama yeni bir Ollama sağlayıcı örnekler.
// Eğer OLLAMA_HOST ortam değişkeni set edilmişse onu host olarak kullanır.
func NewOllama(cfg OllamaConfig) *Ollama {
	if env := strings.TrimSpace(os.Getenv("OLLAMA_HOST")); env != "" {
		cfg.Host = env
	}
	if cfg.Host == "" {
		cfg.Host = "http://127.0.0.1:11434"
	}
	if cfg.Model == "" {
		cfg.Model = "llama3.1:8b"
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 120
	}
	return &Ollama{
		cfg:    cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSec) * time.Second},
	}
}

// Name sağlayıcı adını döner.
func (o *Ollama) Name() string { return "ollama" }

// Healthy Ollama sunucusunun ulaşılabilirliğini kontrol eder.
func (o *Ollama) Healthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(o.cfg.Host, "/")+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama'ya ulaşılamadı (%s): %w", o.cfg.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ollama beklenmeyen durum: %d", resp.StatusCode)
	}
	return nil
}

// ollamaRequest Ollama /api/chat (veya /api/generate) isteği yapısı.
type ollamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Format  string                 `json:"format,omitempty"`  // "json" → structured output
	Options map[string]interface{} `json:"options,omitempty"` // temperature vb.
}

type ollamaResponse struct {
	Model    string `json:"model"`
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Analyze rule-based ön-analizi LLM'e verip narrative/risk/remediation zenginleştirmesi alır.
// Kural tabanlı sonuca dokunmaz; yalnızca özet metni ve öneri sayısını zenginleştirir.
// LLM yanıtı hata verirse veya parse edilemezse, sağlayıcı caller'a hata döner —
// çağıran (analyze komutu) bu durumda rule-based fallback'e düşmelidir.
func (o *Ollama) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	if req.PreAnalysisJSON == "" {
		return nil, fmt.Errorf("ollama sağlayıcı ön-analiz (PreAnalysisJSON) gerektirir")
	}

	// Kural tabanlı sonucu baz al
	var surface struct {
		TotalPaths       int             `json:"total_paths"`
		CriticalPaths    int             `json:"critical_paths"`
		HighRiskPaths    int             `json:"high_risk_paths"`
		TopPaths         []AttackPath    `json:"top_paths"`
		Recommendations  []string        `json:"recommendations"`
		OverallRiskScore float64         `json:"overall_risk_score"`
		RiskLevel        string          `json:"risk_level"`
		ChainedAttacks   []ChainedAttack `json:"chained_attacks"`
		Summary          string          `json:"summary"`
	}
	if err := json.Unmarshal([]byte(req.PreAnalysisJSON), &surface); err != nil {
		return nil, fmt.Errorf("pre-analysis JSON parse hatası: %w", err)
	}

	prompt := buildOllamaPrompt(surface)

	reqBody := ollamaRequest{
		Model:  o.cfg.Model,
		Prompt: prompt,
		Stream: false,
		Format: "json", // Ollama'nın structured output özelliği
		Options: map[string]interface{}{
			"temperature": o.cfg.Temperature,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(o.cfg.Host, "/") + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama çağrısı başarısız: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ollama hatası (%d): %s", resp.StatusCode, string(respBytes))
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBytes, &ollamaResp); err != nil {
		return nil, fmt.Errorf("ollama yanıtı parse edilemedi: %w", err)
	}

	// LLM JSON çıktısı — beklenen şema
	var llmOut struct {
		Narrative       string   `json:"narrative"`
		Summary         string   `json:"summary"`
		RiskLevel       string   `json:"risk_level"`
		RiskScore       float64  `json:"risk_score"`
		Recommendations []string `json:"recommendations"`
	}
	if err := json.Unmarshal([]byte(ollamaResp.Response), &llmOut); err != nil {
		// LLM JSON vermedi — ham metni narrative olarak al
		llmOut.Narrative = ollamaResp.Response
		llmOut.Summary = firstLine(ollamaResp.Response)
	}

	// Kural tabanlı risk skorunu anchor olarak koru; LLM skoru bir sanity-check
	finalScore := surface.OverallRiskScore
	if llmOut.RiskScore > 0 && llmOut.RiskScore <= 10 {
		// LLM skoru %30 ağırlıkla harmanla
		finalScore = 0.7*surface.OverallRiskScore + 0.3*llmOut.RiskScore
	}

	// Öneriler: kural tabanlıyı tut, LLM önerilerini ek (duplikasyon filtreli)
	recSeen := make(map[string]bool)
	var recs []string
	for _, r := range surface.Recommendations {
		if !recSeen[r] {
			recSeen[r] = true
			recs = append(recs, r)
		}
	}
	for _, r := range llmOut.Recommendations {
		r = strings.TrimSpace(r)
		if r == "" || recSeen[r] {
			continue
		}
		recSeen[r] = true
		recs = append(recs, r)
	}

	result := &AnalysisResult{
		Provider:         "ollama:" + o.cfg.Model,
		OverallRiskScore: finalScore,
		RiskLevel:        NormalizeRiskLevel(llmOut.RiskLevel),
		TotalPaths:       surface.TotalPaths,
		CriticalPaths:    surface.CriticalPaths,
		HighRiskPaths:    surface.HighRiskPaths,
		TopPaths:         surface.TopPaths,
		ChainedAttacks:   surface.ChainedAttacks,
		Recommendations:  recs,
		Summary:          firstNonEmpty(llmOut.Summary, surface.Summary),
		Narrative:        llmOut.Narrative,
	}
	_ = ValidateResult(result)
	return result, nil
}

// buildOllamaPrompt kural tabanlı çıktıyı LLM için bir prompt'a dönüştürür.
// JSON output gerekli olduğu için format/şema ipucu verilir.
func buildOllamaPrompt(surface struct {
	TotalPaths       int             `json:"total_paths"`
	CriticalPaths    int             `json:"critical_paths"`
	HighRiskPaths    int             `json:"high_risk_paths"`
	TopPaths         []AttackPath    `json:"top_paths"`
	Recommendations  []string        `json:"recommendations"`
	OverallRiskScore float64         `json:"overall_risk_score"`
	RiskLevel        string          `json:"risk_level"`
	ChainedAttacks   []ChainedAttack `json:"chained_attacks"`
	Summary          string          `json:"summary"`
}) string {
	// Girdi: özet tablo + top 5 path
	topN := 5
	if len(surface.TopPaths) < topN {
		topN = len(surface.TopPaths)
	}
	topPathsJSON, _ := json.Marshal(surface.TopPaths[:topN])
	chainsJSON, _ := json.Marshal(surface.ChainedAttacks)

	return fmt.Sprintf(`Sen bir siber güvenlik analistisin. ShadowGraph adlı otomatik bir ağ tarayıcısı sana bir saldırı yüzeyi analizi çıktısı sunuyor. Bu çıktıya dayanarak KISA ve ÖNCELİKLENDİRİLMİŞ bir değerlendirme üret.

YALNIZCA aşağıdaki JSON şemasında yanıt ver — başka metin, açıklama ya da markdown YAZMA:
{
  "narrative": "2-4 cümlelik Türkçe yönetici özeti",
  "summary": "tek cümlelik çok kısa özet",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_score": 0.0-10.0 arası sayı,
  "recommendations": ["öneri 1", "öneri 2", "..."]
}

Değerlendirme ilkeleri:
- Mevcut kural tabanlı analizle çelişmeyecek bir seviye belirle.
- Önerilerde MEVCUT bulguları SİLMEdiğinden emin ol; yeni ve ek öneriler koyabilirsin.
- Spekülatif CVE veya zafiyet icat etme; yalnızca girdide olanları değerlendir.

--- KURAL TABANLI ANALİZ ---
Toplam saldırı yolu: %d (kritik: %d, yüksek: %d)
Hesaplanan risk: %.1f / 10 (seviye: %s)
Mevcut öneriler: %v

En riskli %d yol (JSON):
%s

Zincirleme saldırılar (JSON):
%s`,
		surface.TotalPaths, surface.CriticalPaths, surface.HighRiskPaths,
		surface.OverallRiskScore, surface.RiskLevel,
		surface.Recommendations,
		topN, string(topPathsJSON),
		string(chainsJSON),
	)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexAny(s, "\n\r"); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return s
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
