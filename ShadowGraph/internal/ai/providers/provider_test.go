package providers

import "testing"

func TestClassifyRisk(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "LOW"},
		{3.9, "LOW"},
		{4.0, "MEDIUM"},
		{6.9, "MEDIUM"},
		{7.0, "HIGH"},
		{8.9, "HIGH"},
		{9.0, "CRITICAL"},
		{10.0, "CRITICAL"},
	}
	for _, c := range cases {
		if got := ClassifyRisk(c.score); got != c.want {
			t.Errorf("ClassifyRisk(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestNormalizeRiskLevel(t *testing.T) {
	cases := map[string]string{
		"critical":     "CRITICAL",
		"HIGH":         "HIGH",
		" Medium ":     "MEDIUM",
		"low":          "LOW",
		"severe":       "CRITICAL",
		"URGENT":       "CRITICAL",
		"moderate":     "MEDIUM",
		"minimal":      "LOW",
		"info":         "LOW",
		"":             "MEDIUM",
		"garbage-text": "MEDIUM",
	}
	for in, want := range cases {
		if got := NormalizeRiskLevel(in); got != want {
			t.Errorf("NormalizeRiskLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateResult_ClampsAndClassifies(t *testing.T) {
	r := &AnalysisResult{
		OverallRiskScore: 12.5, // >10 olmalı clamplenmeli
		RiskLevel:        "YANLIŞ",
	}
	if err := ValidateResult(r); err != nil {
		t.Fatalf("beklenmedik hata: %v", err)
	}
	if r.OverallRiskScore != 10 {
		t.Errorf("skor clamp edilmedi: %v", r.OverallRiskScore)
	}
	if r.RiskLevel != "CRITICAL" {
		t.Errorf("seviye yeniden hesaplanmadı: %q", r.RiskLevel)
	}

	r2 := &AnalysisResult{OverallRiskScore: -3}
	if err := ValidateResult(r2); err != nil {
		t.Fatalf("beklenmedik hata: %v", err)
	}
	if r2.OverallRiskScore != 0 {
		t.Errorf("negatif skor sıfırlanmadı: %v", r2.OverallRiskScore)
	}
}

func TestValidateResult_NilFails(t *testing.T) {
	if err := ValidateResult(nil); err == nil {
		t.Error("nil için hata bekleniyordu")
	}
}

func TestNewProvider_RuleBasedDefault(t *testing.T) {
	p, err := NewProvider("rule-based", DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "rule-based" {
		t.Errorf("beklenen rule-based, alınan %s", p.Name())
	}

	// Boş ad = rule-based
	p2, err := NewProvider("", DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if p2.Name() != "rule-based" {
		t.Errorf("boş ad için rule-based bekleniyordu: %s", p2.Name())
	}
}

func TestNewProvider_UnknownErrors(t *testing.T) {
	_, err := NewProvider("openai-supercloud", DefaultConfig())
	if err == nil {
		t.Error("bilinmeyen provider için hata bekleniyordu")
	}
}
