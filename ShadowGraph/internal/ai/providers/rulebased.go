package providers

import (
	"context"
	"encoding/json"
	"fmt"
)

// RuleBased sağlayıcı, mevcut DFS + heuristic tabanlı analizi (internal/ai.AnalyzeAttackPaths)
// saran ince bir adapter'dır. DB bağımlılığı olmadan çalışabilmesi için
// ham analiz JSON'ını AnalysisRequest.PreAnalysisJSON'dan okur —
// yani caller önce internal/ai.AnalyzeAttackPaths çağırıp JSON'a çevirir,
// sonra onu bu sağlayıcıya verir.
//
// Amaç: interface-uyumlu bir sağlayıcı sunmak; "ollama" seçilse bile
// rule-based fallback olarak kullanılabilsin.
type RuleBased struct{}

// NewRuleBased yeni bir rule-based sağlayıcı döner.
func NewRuleBased() *RuleBased { return &RuleBased{} }

// Name sağlayıcı adını döner.
func (r *RuleBased) Name() string { return "rule-based" }

// Analyze PreAnalysisJSON'ı parse eder ve uyumlu AnalysisResult'a dönüştürür.
// (Kural tabanlı analiz harici olarak hesaplanır; bu metod yalnızca adapter görevi görür.)
func (r *RuleBased) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	if req.PreAnalysisJSON == "" {
		return nil, fmt.Errorf("rule-based sağlayıcı PreAnalysisJSON gerektirir")
	}

	// Pre-analysis objesini (ai.AttackSurface formatı) parse et
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

	result := &AnalysisResult{
		Provider:         "rule-based",
		OverallRiskScore: surface.OverallRiskScore,
		RiskLevel:        NormalizeRiskLevel(surface.RiskLevel),
		TotalPaths:       surface.TotalPaths,
		CriticalPaths:    surface.CriticalPaths,
		HighRiskPaths:    surface.HighRiskPaths,
		TopPaths:         surface.TopPaths,
		ChainedAttacks:   surface.ChainedAttacks,
		Recommendations:  surface.Recommendations,
		Summary:          surface.Summary,
	}
	_ = ValidateResult(result)
	return result, nil
}

// Healthy rule-based her zaman hazırdır.
func (r *RuleBased) Healthy(ctx context.Context) error { return nil }
