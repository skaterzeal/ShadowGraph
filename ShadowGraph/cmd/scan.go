package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shadowgraph/core/internal/config"
	"github.com/shadowgraph/core/internal/db"
	"github.com/shadowgraph/core/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	target      string
	targetFile  string
	profile     string
	customPorts string
	timeoutMs   int
	workers     int
	rateLimit   int
	noNVD       bool
	openUI      bool
	uiPortFlag  int
	forceYes    bool
	maxRetries  int
)

// LargeSubnetThreshold /16 (~65K host) — üstündeki subnet'ler için kullanıcı onayı istenir.
const LargeSubnetThreshold = 65536

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Ağ ve zafiyet keşfini (Recon) başlatır",
	Long: `Tek hedef, CIDR bloğu, virgülle ayrılmış liste veya dosyadan toplu tarama yapar.

Örnekler:
  shadowgraph scan -t 192.168.1.1
  shadowgraph scan -t 192.168.1.0/24
  shadowgraph scan -t "10.0.0.1,10.0.0.2,example.com"
  shadowgraph scan -t 192.168.1.0/24 --profile full --workers 200
  shadowgraph scan --target-file targets.txt --profile stealth`,
	Run: func(cmd *cobra.Command, args []string) {
		// Hedefleri çöz
		var targets []string
		var err error

		if targetFile != "" {
			targets, err = scanner.LoadTargetsFromFile(targetFile)
			if err != nil {
				fmt.Printf("[\033[31m-\033[0m] Hedef dosyası hatası: %v\n", err)
				return
			}
		} else if target != "" {
			targets, err = scanner.ExpandTargets(target)
			if err != nil {
				fmt.Printf("[\033[31m-\033[0m] Hedef parse hatası: %v\n", err)
				return
			}
		} else {
			fmt.Println("[\033[31m-\033[0m] Hedef belirtilmedi. -t veya --target-file kullanın.")
			return
		}

		// Safety net: çok büyük subnet için kullanıcı onayı
		if len(targets) >= LargeSubnetThreshold && config.AppConfig.Safety.ConfirmLargeSubnet && !forceYes {
			fmt.Printf("[\033[33m!\033[0m] UYARI: %d hedef tespit edildi. Büyük subnet taramaları uzun sürebilir ve\n", len(targets))
			fmt.Printf("     hedef ağda IDS/IPS sistemlerini tetikleyebilir. Devam etmek istiyor musunuz? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" && answer != "e" && answer != "evet" {
				fmt.Println("[\033[33m-\033[0m] Tarama iptal edildi.")
				return
			}
		}

		fmt.Printf("[\033[36m+\033[0m] Toplam %d hedef analiz edilecek.\n", len(targets))

		// Profil veya özel port listesi
		var scanProfile scanner.ScanProfile
		if customPorts != "" {
			parsed, err := scanner.ParseCustomPorts(customPorts)
			if err != nil {
				fmt.Printf("[\033[31m-\033[0m] Port parse hatası: %v\n", err)
				return
			}
			scanProfile = scanner.ScanProfile{
				Name:        "custom",
				Ports:       parsed,
				TimeoutMs:   timeoutMs,
				Description: fmt.Sprintf("Özel Port Listesi (%d port)", len(parsed)),
			}
		} else {
			scanProfile = scanner.GetProfile(profile)
			if timeoutMs > 0 {
				scanProfile.TimeoutMs = timeoutMs
			}
		}

		fmt.Printf("[\033[36m*\033[0m] Profil: %s — %s\n", scanProfile.Name, scanProfile.Description)

		// Scan config
		scanCfg := scanner.ScanConfig{
			Profile:    scanProfile,
			Workers:    workers,
			NVDEnabled: !noNVD,
		}
		if rateLimit > 0 {
			scanCfg.RateLimit = time.Duration(rateLimit) * time.Millisecond
		}

		// Yeni scan kaydı oluştur — tüm node/edge'ler bu ID altına yazılacak
		scanTargetLabel := targets[0]
		if len(targets) > 1 {
			// Çok uzun olmasın diye ilk 5 hedefi etikete yaz (underlying slice'ı mutate etme)
			if len(targets) > 5 {
				display := make([]string, 0, 6)
				display = append(display, targets[:5]...)
				display = append(display, fmt.Sprintf("... (+%d)", len(targets)-5))
				scanTargetLabel = strings.Join(display, ",")
			} else {
				scanTargetLabel = strings.Join(targets, ",")
			}
		}

		scanID, err := db.CreateScan(scanTargetLabel, scanProfile.Name)
		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Scan kaydı oluşturulamadı: %v\n", err)
			return
		}
		fmt.Printf("[\033[36m*\033[0m] Scan ID: %d oluşturuldu.\n", scanID)

		// Taramayı başlat
		if len(targets) == 1 {
			scanner.StartReconWithConfig(scanID, targets[0], scanCfg)
		} else {
			scanner.StartMultiRecon(scanID, targets, scanCfg)
		}

		db.FinishScan(scanID)

		fmt.Printf("[\033[32m✔\033[0m] Keşif Tamamlandı. (Scan ID: %d)\n", scanID)
		fmt.Printf("[\033[36m*\033[0m] Sonuçları görmek için: shadowgraph ui --scan-id %d\n", scanID)

		// Otomatik UI açma — kullanıcı --ui ile istemişse bu scan ile dashboard'ı aç
		if openUI {
			fmt.Printf("[\033[36m*\033[0m] Dashboard başlatılıyor (--ui)...\n")
			if err := StartUIServer(uiPortFlag, scanID, true, true); err != nil {
				fmt.Printf("[\033[31m-\033[0m] UI başlatılamadı: %v\n", err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "Hedef IP, Domain, CIDR bloğu veya virgülle ayrılmış liste")
	scanCmd.Flags().StringVar(&targetFile, "target-file", "", "Hedef listesi dosyası (her satır bir hedef)")
	scanCmd.Flags().StringVarP(&profile, "profile", "P", "standard", "Tarama profili: quick, standard, full, stealth")
	scanCmd.Flags().StringVar(&customPorts, "ports", "", "Özel port listesi (Örn: 80,443,8080 veya 1-1000)")
	scanCmd.Flags().IntVar(&timeoutMs, "timeout", 0, "Bağlantı timeout süresi (ms)")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 100, "Eşzamanlı tarama worker sayısı")
	scanCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "Portlar arası bekleme (ms) — IDS atlatma")
	scanCmd.Flags().BoolVar(&noNVD, "no-nvd", false, "NVD CVE sorgusunu devre dışı bırak")
	scanCmd.Flags().BoolVar(&openUI, "ui", false, "Tarama bitince dashboard'ı bu scan ile otomatik aç")
	scanCmd.Flags().IntVar(&uiPortFlag, "ui-port", 8080, "--ui kullanıldığında dashboard port numarası")
	scanCmd.Flags().BoolVarP(&forceYes, "yes", "y", false, "Büyük subnet onayı gibi soruları atla")
	scanCmd.Flags().IntVar(&maxRetries, "max-retries", 2, "Başarısız port/banner/NVD sorguları için yeniden deneme sayısı")
}
