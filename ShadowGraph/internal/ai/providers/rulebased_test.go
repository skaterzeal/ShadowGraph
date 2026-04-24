package providers

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRuleBased_AnalyzeRoundtrip(t *testing.T) {
	// Girdiyi AttackSurface benzeri JSON olarak hazırla
	input := map[string]interface{}{
		"total_paths":        3,
		"critical_paths":     1,
		"high_risk_paths":    1,
		"overall_risk_score": 8.2,
		"risk_level":         "HIGH",
		"summary":            "test özeti",
		"recommendations":    []string{"portları kapat", "yamayı uygula"},
		"top_paths":          []map[string]interface{}{},
		"chained_attacks":    []map[string]interface{}{},
	}
	j, _ := json.Marshal(input)

	p := NewRuleBased()
	res, err := p.Analyze(context.Background(), AnalysisRequest{PreAnalysisJSON: string(j)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "rule-based" {
		t.Errorf("provider: %s", res.Provider)
	}
	if res.TotalPaths != 3 {
		t.Errorf("total_paths: %d", res.TotalPaths)
	}
	if res.RiskLevel != "HIGH" {
		t.Errorf("risk_level: %q", res.RiskLevel)
	}
	if len(res.Recommendations) != 2 {
		t.Errorf("recommendations len: %d", len(res.Recommendations))
	}
}

func TestRuleBased_EmptyJSONFails(t *testing.T) {
	p := NewRuleBased()
	_, err := p.Analyze(context.Background(), AnalysisRequest{})
	if err == nil {
		t.Error("empty pre-analysis için hata bekleniyordu")
	}
}
