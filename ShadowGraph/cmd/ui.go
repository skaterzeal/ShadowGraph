package cmd

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/shadowgraph/core/internal/ai"
	"github.com/shadowgraph/core/internal/db"
	"github.com/shadowgraph/core/internal/logger"
	"github.com/spf13/cobra"
)

//go:embed frontend/index.html frontend/app.js frontend/styles.css
var frontendFS embed.FS

var (
	port     int
	uiScanID int64
	uiNoOpen bool
)

// OpenBrowser kullanıcının varsayılan tarayıcısını verilen URL ile açar.
// Paket içinden de çağrılabilir (scan --ui için).
func OpenBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // linux, freebsd, netbsd, openbsd
		cmd = "xdg-open"
		args = []string{url}
	}
	return exec.Command(cmd, args...).Start()
}

// StartUIServer UI sunucusunu başlatır. Hem `ui` komutu hem `scan --ui` için.
// blocking=true ise ListenAndServe'i çağırır; false ise goroutine'de başlatır.
func StartUIServer(listenPort int, scanID int64, openBrowser, blocking bool) error {
	mux := http.NewServeMux()

	// Embed edilmiş frontend dosyaları: sub-FS ile frontend/ prefix'ini kaldır
	sub, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		return fmt.Errorf("frontend embed hatası: %w", err)
	}

	// Root: index.html
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "index.html bulunamadı", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// Static assets: /assets/styles.css, /assets/app.js
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))

	// Graph API
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) {
		reqScanID := scanID
		if q := r.URL.Query().Get("scan_id"); q != "" {
			if parsed, err := strconv.ParseInt(q, 10, 64); err == nil && parsed > 0 {
				reqScanID = parsed
			}
		}
		data, err := db.GetGraphData(reqScanID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(data)
	})

	// Scans API
	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		scans, err := db.GetScansList()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(scans)
	})

	// Analysis API — GET /api/analysis?scan_id=N
	mux.HandleFunc("/api/analysis", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("scan_id")
		if q == "" {
			http.Error(w, "scan_id gerekli", http.StatusBadRequest)
			return
		}
		sid, err := strconv.ParseInt(q, 10, 64)
		if err != nil || sid <= 0 {
			http.Error(w, "geçersiz scan_id", http.StatusBadRequest)
			return
		}
		a, err := db.GetLatestAnalysis(sid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if a == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(a)
	})

	// Analyze POST — POST /api/analyze  body: {"scan_id": N}
	mux.HandleFunc("/api/analyze", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST gerekli", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ScanID int64 `json:"scan_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ScanID <= 0 {
			http.Error(w, "scan_id gerekli", http.StatusBadRequest)
			return
		}
		// Analiz çalıştır (rule-based; ileride provider seçimi buraya gelecek)
		result, err := ai.AnalyzeAttackPaths(db.DB, req.ScanID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// DB'ye kaydet
		if err := db.SaveAnalysis(req.ScanID, "rule-based", result); err != nil {
			logger.Warnf("ui", "analiz DB'ye kaydedilemedi: %v", err)
		}
		// Response: özet bilgileri döndür
		latest, _ := db.GetLatestAnalysis(req.ScanID)
		w.Header().Set("Content-Type", "application/json")
		if latest != nil {
			json.NewEncoder(w).Encode(latest)
		} else {
			// Fallback: direkt result'tan özet çıkar
			json.NewEncoder(w).Encode(map[string]interface{}{
				"scan_id":         req.ScanID,
				"provider":        "rule-based",
				"overall_risk":    result.OverallRiskScore,
				"risk_level":      result.RiskLevel,
				"total_paths":     result.TotalPaths,
				"critical_paths":  result.CriticalPaths,
				"high_risk_paths": result.HighRiskPaths,
			})
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	server := &http.Server{Addr: addr, Handler: mux}

	// Graceful shutdown (yalnızca blocking modda)
	if blocking {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		go func() {
			<-ctx.Done()
			fmt.Println("\n[\033[33m!\033[0m] Kapatiliyor...")
			logger.Infof("ui", "Graceful shutdown basladi")
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutCtx)
		}()
	}

	url := fmt.Sprintf("http://localhost:%d", listenPort)
	fmt.Printf("[\033[36m*\033[0m] Dashboard %s\n", url)

	if openBrowser {
		// Sunucu hazır olana kadar kısa bir gecikme
		go func() {
			time.Sleep(400 * time.Millisecond)
			if err := OpenBrowser(url); err != nil {
				logger.Warnf("ui", "tarayıcı açılamadı: %v", err)
			}
		}()
	}

	if blocking {
		fmt.Println("[\033[33m!\033[0m] CTRL+C ile guvenli kapatma")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("sunucu hatası: %w", err)
		}
		logger.Infof("ui", "Sunucu kapatildi")
		return nil
	}

	// Non-blocking: goroutine'de başlat
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("ui", "sunucu hatası: %v", err)
		}
	}()
	return nil
}

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Interaktif Dashboard panelini baslatir (localhost only)",
	Run: func(cmd *cobra.Command, args []string) {
		resolvedID, _ := db.ResolveScanID(uiScanID)
		if resolvedID > 0 {
			fmt.Printf("[\033[36m*\033[0m] Aktif scan_id: %d (dashboard'dan değiştirilebilir)\n", resolvedID)
		} else {
			fmt.Println("[\033[33m!\033[0m] Henüz hiç tarama yok — dashboard boş gösterecek.")
		}
		openFlag := !uiNoOpen
		if err := StartUIServer(port, uiScanID, openFlag, true); err != nil {
			fmt.Printf("[\033[31m-\033[0m] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(uiCmd)
	uiCmd.Flags().IntVarP(&port, "port", "p", 8080, "Dashboard port numarasi")
	uiCmd.Flags().Int64Var(&uiScanID, "scan-id", 0, "Gösterilecek scan ID (varsayılan: en son tarama)")
	uiCmd.Flags().BoolVar(&uiNoOpen, "no-open", false, "Tarayıcıyı otomatik açma")
}
