package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// AnalysisInfo analyses tablosundaki bir kayıt (UI ve API için).
// JsonData ham analiz sonucunu içerir (top_paths, chained_attacks, recommendations vb.).
type AnalysisInfo struct {
	ID             int64   `json:"id"`
	ScanID         int64   `json:"scan_id"`
	Provider       string  `json:"provider"`
	OverallRisk    float64 `json:"overall_risk"`
	RiskLevel      string  `json:"risk_level"`
	TotalPaths     int     `json:"total_paths"`
	CriticalPaths  int     `json:"critical_paths"`
	HighRiskPaths  int     `json:"high_risk_paths"`
	Summary        string  `json:"summary"`
	CreatedAt      string  `json:"created_at"`
	JSONData       string  `json:"json_data,omitempty"` // Detay istenirse doldurulur
}

// AnalysisPayload: ai paketine bağımlılığı önlemek için minimal bir arayüz tanımı.
// ai.AttackSurface bu interface'i zaten (alan isimlendirmesi üzerinden) karşılıyor
// — ancak runtime dönüşüm için generic yaklaşım olarak struct literal kullanıyoruz.
// Bu yüzden SaveAnalysis import-cycle oluşturmasın diye yalnızca ihtiyaç duyduğu alanları
// bir yardımcı struct (SaveAnalysisInput) üzerinden alır.
type SaveAnalysisInput struct {
	OverallRiskScore float64
	RiskLevel        string
	TotalPaths       int
	CriticalPaths    int
	HighRiskPaths    int
	Summary          string      // serbest metin özet (ör. AI narrative)
	FullData         interface{} // tam analiz objesi; JSON'a serialize edilir
}

// SaveAnalysis yeni bir analiz kaydı ekler.
// Birden fazla analiz saklanır (history); "en son" için GetLatestAnalysis kullanın.
func SaveAnalysis(scanID int64, provider string, data interface{}) error {
	if scanID <= 0 {
		return fmt.Errorf("geçersiz scan_id: %d", scanID)
	}

	// Generic yaklaşım: reflection yerine JSON round-trip ile alanları çıkar
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("analiz serialize edilemedi: %w", err)
	}

	// Kısa özet alanlarını tekrar deserialize et
	var summary struct {
		OverallRiskScore float64 `json:"overall_risk_score"`
		RiskLevel        string  `json:"risk_level"`
		TotalPaths       int     `json:"total_paths"`
		CriticalPaths    int     `json:"critical_paths"`
		HighRiskPaths    int     `json:"high_risk_paths"`
		Summary          string  `json:"summary"`
		// Bazı sağlayıcılar overall_risk adını kullanabilir
		OverallRisk float64 `json:"overall_risk"`
	}
	_ = json.Unmarshal(jsonBytes, &summary)

	risk := summary.OverallRiskScore
	if risk == 0 && summary.OverallRisk > 0 {
		risk = summary.OverallRisk
	}

	// Eğer summary verilmemişse, top recommendations ve chain özetinden bir metin üret
	summaryText := summary.Summary
	if strings.TrimSpace(summaryText) == "" {
		summaryText = buildFallbackSummary(jsonBytes)
	}

	_, err = DB.Exec(`
		INSERT INTO analyses
			(scan_id, provider, overall_risk, risk_level, total_paths, critical_paths, high_risk_paths, summary, json_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, provider, risk, summary.RiskLevel,
		summary.TotalPaths, summary.CriticalPaths, summary.HighRiskPaths,
		summaryText, string(jsonBytes),
	)
	if err != nil {
		return fmt.Errorf("analiz kaydedilemedi: %w", err)
	}
	return nil
}

// GetLatestAnalysis verilen scan için en son analizi döner (yoksa nil, nil).
func GetLatestAnalysis(scanID int64) (*AnalysisInfo, error) {
	row := DB.QueryRow(`
		SELECT id, scan_id, provider, COALESCE(overall_risk,0), COALESCE(risk_level,''),
		       COALESCE(total_paths,0), COALESCE(critical_paths,0), COALESCE(high_risk_paths,0),
		       COALESCE(summary,''), COALESCE(created_at,''), COALESCE(json_data,'')
		FROM analyses WHERE scan_id = ? ORDER BY id DESC LIMIT 1`, scanID)

	var a AnalysisInfo
	err := row.Scan(&a.ID, &a.ScanID, &a.Provider, &a.OverallRisk, &a.RiskLevel,
		&a.TotalPaths, &a.CriticalPaths, &a.HighRiskPaths,
		&a.Summary, &a.CreatedAt, &a.JSONData)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("analiz okunamadı: %w", err)
	}
	return &a, nil
}

// ListAnalyses scan için tüm analizleri listeler (history görünümü için).
func ListAnalyses(scanID int64) ([]AnalysisInfo, error) {
	rows, err := DB.Query(`
		SELECT id, scan_id, provider, COALESCE(overall_risk,0), COALESCE(risk_level,''),
		       COALESCE(total_paths,0), COALESCE(critical_paths,0), COALESCE(high_risk_paths,0),
		       COALESCE(summary,''), COALESCE(created_at,'')
		FROM analyses WHERE scan_id = ? ORDER BY id DESC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("analizler listelenemedi: %w", err)
	}
	defer rows.Close()

	result := make([]AnalysisInfo, 0)
	for rows.Next() {
		var a AnalysisInfo
		if err := rows.Scan(&a.ID, &a.ScanID, &a.Provider, &a.OverallRisk, &a.RiskLevel,
			&a.TotalPaths, &a.CriticalPaths, &a.HighRiskPaths,
			&a.Summary, &a.CreatedAt); err != nil {
			continue
		}
		result = append(result, a)
	}
	return result, nil
}

// buildFallbackSummary json_data'dan kısa bir özet metin üretir.
// AI provider bir "summary" vermemişse burada otomatik metin oluşturulur.
func buildFallbackSummary(jsonBytes []byte) string {
	var parsed struct {
		TotalPaths      int      `json:"total_paths"`
		CriticalPaths   int      `json:"critical_paths"`
		HighRiskPaths   int      `json:"high_risk_paths"`
		Recommendations []string `json:"recommendations"`
		ChainedAttacks  []struct {
			Name string `json:"name"`
		} `json:"chained_attacks"`
	}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		return ""
	}

	var parts []string
	if parsed.TotalPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d saldırı yolu tespit edildi", parsed.TotalPaths))
	}
	if parsed.CriticalPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d kritik", parsed.CriticalPaths))
	}
	if parsed.HighRiskPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d yüksek risk", parsed.HighRiskPaths))
	}
	if len(parsed.ChainedAttacks) > 0 {
		parts = append(parts, fmt.Sprintf("%d zincirleme senaryo", len(parsed.ChainedAttacks)))
	}
	base := strings.Join(parts, ", ")

	if len(parsed.Recommendations) > 0 {
		base += ". İlk öneri: " + parsed.Recommendations[0]
	}
	if base == "" {
		return "Analiz tamamlandı; ciddi bir saldırı yolu tespit edilmedi."
	}
	return base + "."
}
