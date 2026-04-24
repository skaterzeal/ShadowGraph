// Package providers AI sağlayıcı soyutlaması — rule-based analiz, Ollama,
// (gelecekte) OpenAI/Anthropic gibi sağlayıcıları arkasına alan bir arayüz tanımlar.
package providers

import (
	"context"
	"fmt"
	"strings"
)

// AttackPath tek bir saldırı yolunun taşınabilir gösterimi.
// internal/ai.AttackPath ile alan-isim uyumludur; JSON köprüsüyle dönüştürülebilir.
type AttackPath struct {
	Summary    string     `json:"summary"`
	RiskScore  float64    `json:"risk_score"`
	Complexity string     `json:"complexity"`
	Impact     string     `json:"impact"`
	Steps      []PathStep `json:"steps,omitempty"`
}

// PathStep bir saldırı yolundaki tek adım.
type PathStep struct {
	NodeType string            `json:"node_type"`
	Label    string            `json:"label"`
	Data     map[string]string `json:"data,omitempty"`
	Action   string            `json:"action,omitempty"`
}

// ChainedAttack zincirleme saldırı senaryosu.
type ChainedAttack struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CVEs        []string `json:"cves,omitempty"`
	RiskScore   float64  `json:"risk_score"`
	Scenario    string   `json:"scenario"`
}

// AnalysisRequest sağlayıcıya gönderilen analiz girdisi.
// Rule-based sağlayıcı Nodes/Edges'ten kendi DFS'ini çalıştırır.
// LLM sağlayıcı Paths/ChainedAttacks'i girdi kabul eder ve zenginleştirir.
type AnalysisRequest struct {
	ScanID         int64           `json:"scan_id"`
	Nodes          []Node          `json:"nodes,omitempty"`
	Edges          []Edge          `json:"edges,omitempty"`
	Paths          []AttackPath    `json:"paths,omitempty"`
	ChainedAttacks []ChainedAttack `json:"chained_attacks,omitempty"`
	// Pre-computed rule-based summary (LLM sağlayıcıya input olarak verilir)
	PreAnalysisJSON string `json:"pre_analysis_json,omitempty"`
}

// Node graph düğümü — provider-agnostic.
type Node struct {
	ID    int64             `json:"id"`
	Type  string            `json:"type"`
	Label string            `json:"label"`
	Data  map[string]string `json:"data,omitempty"`
}

// Edge graph kenarı.
type Edge struct {
	From  int64  `json:"from"`
	To    int64  `json:"to"`
	Label string `json:"label,omitempty"`
}

// AnalysisResult sağlayıcı çıktısı (kural-bazlı veya LLM).
type AnalysisResult struct {
	Provider         string          `json:"provider"`
	OverallRiskScore float64         `json:"overall_risk_score"`
	RiskLevel        string          `json:"risk_level"`
	TotalPaths       int             `json:"total_paths"`
	CriticalPaths    int             `json:"critical_paths"`
	HighRiskPaths    int             `json:"high_risk_paths"`
	TopPaths         []AttackPath    `json:"top_paths,omitempty"`
	ChainedAttacks   []ChainedAttack `json:"chained_attacks,omitempty"`
	Recommendations  []string        `json:"recommendations,omitempty"`
	Summary          string          `json:"summary"`
	// LLM çıktısı varsa (ör. Markdown narrative) burada saklanır
	Narrative string `json:"narrative,omitempty"`
}

// Provider AI analiz sağlayıcısı arayüzü.
// Implementasyonlar context.Context'e saygı göstermeli ve timeout/deadline'ı takip etmelidir.
type Provider interface {
	Name() string
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error)
	// Healthy sağlayıcının kullanıma hazır olup olmadığını kontrol eder
	// (örn. Ollama'nın HTTP endpoint'i yanıt veriyor mu).
	Healthy(ctx context.Context) error
}

// Config sağlayıcı yapılandırması (config file'dan okunur).
type Config struct {
	Provider string       `yaml:"provider" json:"provider"` // "rule-based", "ollama"
	Ollama   OllamaConfig `yaml:"ollama" json:"ollama"`
}

// OllamaConfig Ollama sağlayıcısı için yapılandırma.
type OllamaConfig struct {
	Host        string  `yaml:"host" json:"host"`                 // varsayılan http://localhost:11434
	Model       string  `yaml:"model" json:"model"`               // varsayılan llama3.1:8b
	Temperature float64 `yaml:"temperature" json:"temperature"`   // varsayılan 0.2 (deterministik)
	TimeoutSec  int     `yaml:"timeout_sec" json:"timeout_sec"`   // varsayılan 120
}

// DefaultConfig güvenli varsayılan yapılandırma.
func DefaultConfig() Config {
	return Config{
		Provider: "rule-based",
		Ollama: OllamaConfig{
			Host:        "http://127.0.0.1:11434",
			Model:       "llama3.1:8b",
			Temperature: 0.2,
			TimeoutSec:  120,
		},
	}
}

// ClassifyRisk skor → seviye haritası.
func ClassifyRisk(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Normalize LLM çıktısındaki seviye adını standartlaştırır.
func NormalizeRiskLevel(level string) string {
	l := strings.ToUpper(strings.TrimSpace(level))
	switch l {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return l
	case "SEVERE", "URGENT":
		return "CRITICAL"
	case "MODERATE":
		return "MEDIUM"
	case "MINIMAL", "INFO":
		return "LOW"
	}
	return "MEDIUM"
}

// ValidateResult LLM veya kural bazlı sağlayıcının ürettiği sonucun mantıklı olup olmadığını doğrular
// ve gerekirse alanları düzeltir (ör. risk_level ile overall_risk_score arasındaki çelişkileri giderir).
func ValidateResult(r *AnalysisResult) error {
	if r == nil {
		return fmt.Errorf("nil analysis result")
	}
	if r.OverallRiskScore < 0 {
		r.OverallRiskScore = 0
	}
	if r.OverallRiskScore > 10 {
		r.OverallRiskScore = 10
	}
	// Risk seviyesi skora göre yeniden hesaplanır (LLM yanlış yazmış olabilir)
	r.RiskLevel = ClassifyRisk(r.OverallRiskScore)
	if r.Summary == "" && len(r.Recommendations) > 0 {
		r.Summary = r.Recommendations[0]
	}
	return nil
}
