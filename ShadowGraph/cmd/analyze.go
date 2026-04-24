package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/shadowgraph/core/internal/ai"
	"github.com/shadowgraph/core/internal/ai/providers"
	"github.com/shadowgraph/core/internal/config"
	"github.com/shadowgraph/core/internal/db"
	"github.com/spf13/cobra"
)

var (
	analyzeOutput   string
	analyzeScanID   int64
	analyzeProvider string
	analyzeNoSave   bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "AI saldırı yolu analizi — graf verilerinden saldırı zincirleri tespit eder",
	Long: `Tarama sonuçlarındaki graf verilerini analiz ederek:
  - Saldırı yollarını tespit eder (target → port → service → CVE)
  - Risk skorlaması yapar (0-10)
  - Zincirleme saldırı senaryolarını belirler
  - Önceliklendirmiş remediation önerileri sunar

Sağlayıcılar:
  rule-based  (varsayılan, hızlı, deterministik)
  ollama      (lokal LLM, narrative zenginleştirme; Ollama kurulu olmalı)

Örnekler:
  shadowgraph analyze
  shadowgraph analyze --scan-id 3
  shadowgraph analyze --provider ollama
  shadowgraph analyze --output report.json`,
	Run: func(cmd *cobra.Command, args []string) {
		// scanID çözümle
		resolvedID, err := db.ResolveScanID(analyzeScanID)
		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Scan ID çözümlenemedi: %v\n", err)
			return
		}
		if resolvedID == 0 {
			fmt.Println("[\033[33m!\033[0m] Henüz hiç tarama yapılmamış. Önce 'shadowgraph scan' çalıştırın.")
			return
		}
		fmt.Printf("[\033[36m*\033[0m] AI Attack Path analizi başlatılıyor (scan_id=%d)...\n", resolvedID)

		// 1) Her zaman kural tabanlı baz analizi çalıştır
		surface, err := ai.AnalyzeAttackPaths(db.DB, resolvedID)
		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Analiz hatası: %v\n", err)
			return
		}

		// 2) İstenen sağlayıcı rule-based dışındaysa (ör. ollama) LLM ile zenginleştir
		wantProvider := analyzeProvider
		if wantProvider == "" {
			wantProvider = config.AppConfig.AI.Provider
		}
		providerUsed := "rule-based"
		if wantProvider != "" && wantProvider != "rule-based" {
			providerUsed = tryProviderEnrichment(surface, wantProvider)
		}

		// Konsol çıktısı (rule-based çekirdek sonucu)
		ai.PrintAttackSurface(surface)

		// DB'ye kaydet
		if !analyzeNoSave {
			if err := db.SaveAnalysis(resolvedID, providerUsed, surface); err != nil {
				fmt.Printf("[\033[33m!\033[0m] DB'ye kayıt hatası: %v\n", err)
			} else {
				fmt.Printf("[\033[32m✔\033[0m] Analiz DB'ye kaydedildi (scan_id=%d, provider=%s)\n", resolvedID, providerUsed)
			}
		}

		// JSON çıktı (opsiyonel)
		if analyzeOutput != "" {
			data, _ := json.MarshalIndent(surface, "", "  ")
			if err := os.WriteFile(analyzeOutput, data, 0644); err != nil {
				fmt.Printf("[\033[31m-\033[0m] Dosya yazma hatası: %v\n", err)
				return
			}
			fmt.Printf("[\033[32m✔\033[0m] Analiz raporu kaydedildi: %s\n", analyzeOutput)
		}
	},
}

// tryProviderEnrichment istenen sağlayıcıyı çağırır; başarısızlıkta rule-based'a fallback yapar.
// Rule-based çıktısını provider'a PreAnalysisJSON olarak geçirir ve LLM'in ürettiği
// narrative/recommendations'ı surface'e ekler. Kural tabanlı ana sayısal değerler korunur.
func tryProviderEnrichment(surface *ai.AttackSurface, providerName string) string {
	// surface'ı JSON'a çevir
	surfaceJSON, err := json.Marshal(surface)
	if err != nil {
		fmt.Printf("[\033[33m!\033[0m] Pre-analysis JSON hatası: %v — rule-based'a düşülüyor.\n", err)
		return "rule-based"
	}

	cfg := providers.Config{
		Provider: providerName,
		Ollama: providers.OllamaConfig{
			Host:        config.AppConfig.AI.Ollama.Host,
			Model:       config.AppConfig.AI.Ollama.Model,
			Temperature: config.AppConfig.AI.Ollama.Temperature,
			TimeoutSec:  config.AppConfig.AI.Ollama.TimeoutSec,
		},
	}

	// Health check için kısa timeout
	healthCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, actualName, err := providers.NewProviderWithFallback(healthCtx, providerName, cfg)
	if err != nil {
		// Belirgin uyarı — kullanıcı sessizce rule-based'a düştüğünü fark etsin diye
		// kalın çerçeveli, vurgulu bir hata mesajı yazdır.
		fmt.Println("\n\033[1;33m╔════════════════════════════════════════════════════════════╗\033[0m")
		fmt.Println("\033[1;33m║  UYARI: AI sağlayıcı erişilemez — RULE-BASED'a düşüldü     ║\033[0m")
		fmt.Println("\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m")
		fmt.Printf("\033[33m   Sebep   :\033[0m %v\n", err)
		fmt.Printf("\033[33m   Çözüm   :\033[0m\n")
		fmt.Printf("    1) Ollama servisi çalışıyor mu? → \033[36mollama serve\033[0m\n")
		fmt.Printf("    2) Doğru host'ta mı dinliyor? → \033[36mcurl %s/api/tags\033[0m\n", cfg.Ollama.Host)
		fmt.Printf("    3) Model indirildi mi? → \033[36mollama pull %s\033[0m\n", cfg.Ollama.Model)
		fmt.Printf("    4) Farklı host için: \033[36mexport OLLAMA_HOST=http://<ip>:11434\033[0m\n\n")
	}
	if p.Name() == "rule-based" {
		return actualName
	}

	fmt.Printf("[\033[36m*\033[0m] LLM sağlayıcı (%s) çağrılıyor...\n", p.Name())

	// Analiz için daha uzun timeout
	analyzeCtx, cancel2 := context.WithTimeout(context.Background(), time.Duration(cfg.Ollama.TimeoutSec)*time.Second)
	defer cancel2()

	result, err := p.Analyze(analyzeCtx, providers.AnalysisRequest{
		ScanID:          int64(surface.TotalPaths), // kullanılmıyor
		PreAnalysisJSON: string(surfaceJSON),
	})
	if err != nil {
		fmt.Printf("[\033[33m!\033[0m] LLM çağrısı başarısız: %v — rule-based'a düşülüyor.\n", err)
		return "rule-based"
	}

	// LLM'in eklediği öneri/narrative'i surface'e işle
	if result.Narrative != "" {
		surface.Summary = result.Summary + "\n\n" + result.Narrative
	} else if result.Summary != "" {
		surface.Summary = result.Summary
	}
	if len(result.Recommendations) > 0 {
		surface.Recommendations = result.Recommendations
	}
	// Skor LLM ile harmanlanmışsa uygula (seviyeyi yeniden hesapla)
	if result.OverallRiskScore > 0 {
		surface.OverallRiskScore = result.OverallRiskScore
		surface.RiskLevel = providers.ClassifyRisk(result.OverallRiskScore)
	}

	fmt.Printf("[\033[32m✔\033[0m] LLM zenginleştirmesi uygulandı.\n")
	return actualName
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringVarP(&analyzeOutput, "output", "o", "", "Analiz raporunu JSON olarak kaydet")
	analyzeCmd.Flags().Int64Var(&analyzeScanID, "scan-id", 0, "Analiz edilecek scan ID (varsayılan: en son tarama)")
	analyzeCmd.Flags().StringVar(&analyzeProvider, "provider", "", "AI sağlayıcı: rule-based, ollama (boşsa config'ten okunur)")
	analyzeCmd.Flags().BoolVar(&analyzeNoSave, "no-save", false, "Analizi veritabanına kaydetme")
}
