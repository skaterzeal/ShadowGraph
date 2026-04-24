package scanner

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadowgraph/core/internal/db"
)

// ScanResult tek bir hedefin tarama sonuçlarını tutar
type ScanResult struct {
	Target   string
	OpenTCP  int
	OpenUDP  int
	Vulns    int
	RootID   int64
}

// ScanConfig tarama konfigürasyonu
type ScanConfig struct {
	Profile     ScanProfile
	Workers     int           // Eşzamanlı worker sayısı
	RateLimit   time.Duration // Portlar arası minimum bekleme
	NVDEnabled  bool          // NVD CVE sorgusu aktif mi
}

// DefaultScanConfig varsayılan tarama konfigürasyonu
func DefaultScanConfig(profile ScanProfile) ScanConfig {
	return ScanConfig{
		Profile:    profile,
		Workers:    100,
		RateLimit:  0,
		NVDEnabled: true,
	}
}

func resolveTarget(target string) (string, string, string) {
	var ipv4, ipv6, hostname string

	if parsedIP := net.ParseIP(target); parsedIP != nil {
		if parsedIP.To4() != nil {
			ipv4 = target
		} else {
			ipv6 = target
		}
		names, err := net.LookupAddr(target)
		if err == nil && len(names) > 0 {
			hostname = strings.TrimSuffix(names[0], ".")
		}
	} else {
		hostname = target
		ips, err := net.LookupIP(target)
		if err == nil {
			for _, ip := range ips {
				if ip.To4() != nil && ipv4 == "" {
					ipv4 = ip.String()
				} else if ip.To4() == nil && ipv6 == "" {
					ipv6 = ip.String()
				}
			}
		}
	}
	return ipv4, ipv6, hostname
}

func sanitizeBanner(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func grabBanner(target, port string) string {
	if port == "80" || port == "443" || port == "8080" || port == "8443" {
		return ""
	}
	address := net.JoinHostPort(target, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return sanitizeBanner(string(buf[:n]))
	}
	return ""
}

func grabHTTPHeaders(target, port string) string {
	url := fmt.Sprintf("http://%s:%s", target, port)
	if port == "443" || port == "8443" {
		url = fmt.Sprintf("https://%s:%s", target, port)
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	var parts []string
	if server != "" {
		parts = append(parts, "Server: "+server)
	}
	if poweredBy != "" {
		parts = append(parts, "PoweredBy: "+poweredBy)
	}
	return strings.Join(parts, " | ")
}

// portScanResult TCP port tarama sonucu
type portScanResult struct {
	Port        string
	ServiceInfo string
	Open        bool
}

// scanTCPPortsConcurrent goroutine havuzu ile eşzamanlı TCP port taraması
func scanTCPPortsConcurrent(scanID int64, target string, config ScanConfig, rootID int64) (int, int) {
	ports := config.Profile.Ports
	workers := config.Workers
	if workers <= 0 {
		workers = 100
	}
	if workers > len(ports) {
		workers = len(ports)
	}

	timeout := time.Duration(config.Profile.TimeoutMs) * time.Millisecond
	var openCount int32
	var vulnCount int32

	// Port kanalı
	portChan := make(chan string, len(ports))
	resultChan := make(chan portScanResult, len(ports))

	// Worker havuzu
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				// Rate limiting
				if config.RateLimit > 0 {
					time.Sleep(config.RateLimit)
				}
				if config.Profile.DelayMs > 0 {
					time.Sleep(time.Duration(config.Profile.DelayMs) * time.Millisecond)
				}

				address := net.JoinHostPort(target, port)
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err != nil {
					resultChan <- portScanResult{Port: port, Open: false}
					continue
				}
				conn.Close()

				// Banner / Header okuma
				var serviceInfo string
				if port == "80" || port == "443" || port == "8080" || port == "8443" {
					serviceInfo = grabHTTPHeaders(target, port)
				} else {
					serviceInfo = grabBanner(target, port)
				}

				resultChan <- portScanResult{Port: port, Open: true, ServiceInfo: serviceInfo}
			}
		}()
	}

	// Portları kuyruğa at
	go func() {
		for _, p := range ports {
			portChan <- p
		}
		close(portChan)
	}()

	// Sonuç toplama goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Sonuçları işle
	for result := range resultChan {
		if !result.Open {
			continue
		}
		atomic.AddInt32(&openCount, 1)
		fmt.Printf("  [\033[32m+\033[0m] TCP Port %s Açık\n", result.Port)

		portData, _ := json.Marshal(map[string]string{"state": "open", "protocol": "tcp"})
		portID, _ := db.AddNodeWithScan(scanID, "port", fmt.Sprintf("Port %s", result.Port), string(portData))
		db.AddEdgeWithScan(scanID, rootID, portID, "has_port")

		if result.ServiceInfo != "" {
			svc := IdentifyService(result.ServiceInfo)
			svcLabel := svc.DisplayName()
			if svcLabel == "Unknown" {
				svcLabel = "Servis Tespit Edildi"
			}

			// CDN/WAF/Proxy false positive kontrolü
			if shielded, shieldName := IsShieldedService(svc, result.ServiceInfo); shielded {
				shieldData, _ := json.Marshal(map[string]string{
					"banner":       result.ServiceInfo,
					"service":      svc.Name,
					"product":      svc.Product,
					"version":      svc.Version,
					"shield_type":  shieldName,
					"note":         "CDN/WAF arkasında — CVE sorgusu atlandı (false positive önleme)",
				})
				shieldNodeID, _ := db.AddNodeWithScan(scanID, "shield", shieldName, string(shieldData))
				db.AddEdgeWithScan(scanID, portID, shieldNodeID, "shielded_by")
				fmt.Printf("    [\033[1;33m🛡\033[0m] CDN/WAF Tespit: %s — CVE/Exploit sorgusu atlandı (false positive önleme)\n", shieldName)
				continue
			}

			infoData, _ := json.Marshal(map[string]string{
				"banner":  result.ServiceInfo,
				"service": svc.Name,
				"product": svc.Product,
				"version": svc.Version,
			})
			infoNodeID, _ := db.AddNodeWithScan(scanID, "endpoint", svcLabel, string(infoData))
			db.AddEdgeWithScan(scanID, portID, infoNodeID, "runs_service")
			fmt.Printf("    [\033[36mℹ\033[0m] Servis: %s | Banner: %s\n", svcLabel, result.ServiceInfo)

			// Exploit DB kontrolü
			exploits := LookupExploits(svc.Name, svc.Version)
			for _, exp := range exploits {
				expFields := map[string]string{
					"exploit_id":  exp.ID,
					"source":      exp.Source,
					"description": exp.Description,
					"type":        exp.Type,
				}
				// Bağlı CVE'leri (varsa) virgülle birleştirilmiş ve ayrıca
				// numaralandırılmış alanlara yaz — analiz tarafı her ikisini de
				// kullanabilsin.
				if len(exp.CVEs) > 0 {
					expFields["cves"] = strings.Join(exp.CVEs, ",")
					for i, c := range exp.CVEs {
						if i >= 8 {
							break // Aşırı uzamayı engelle
						}
						expFields[fmt.Sprintf("cve_%d", i+1)] = c
					}
				}
				expData, _ := json.Marshal(expFields)
				expNodeID, _ := db.AddNodeWithScan(scanID, "exploit", fmt.Sprintf("%s: %s", exp.Source, exp.ID), string(expData))
				db.AddEdgeWithScan(scanID, infoNodeID, expNodeID, "has_exploit")
				fmt.Printf("    [\033[1;35m⚡\033[0m] Exploit: %s — %s (%s)\n", exp.ID, exp.Description, exp.Source)
			}

			// NVD CVE sorgusu — IdentifyService çıktısından temiz bir Product+Version sorgusu
			// kur. Ham banner ("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-...") NVD'nin anahtar
			// arama motoruyla iyi tokenize olmuyor; "OpenSSH 6.6.1p1" çok daha doğru.
			if config.NVDEnabled {
				nvdQuery := result.ServiceInfo
				if svc.Product != "" && svc.Name != "" && svc.Name != "unknown" {
					if svc.Version != "" {
						nvdQuery = svc.Product + " " + svc.Version
					} else {
						nvdQuery = svc.Product
					}
				}
				cves, apiErr := QueryNVD(nvdQuery)
				if apiErr != nil {
					fmt.Printf("    [\033[31m-\033[0m] NVD API: %v\n", apiErr)
				} else if len(cves) > 0 {
					for _, cve := range cves {
						atomic.AddInt32(&vulnCount, 1)
						cveData, _ := json.Marshal(map[string]string{
							"cve":      cve.ID,
							"severity": cve.Severity,
							"desc":     cve.Description,
						})
						cveID, _ := db.AddNodeWithScan(scanID, "vulnerability", cve.ID, string(cveData))
						db.AddEdgeWithScan(scanID, infoNodeID, cveID, "vulnerable_to")
						fmt.Printf("    [\033[1;31m!\033[0m] CVE: %s (Risk: %s)\n", cve.ID, cve.Severity)
					}
				} else {
					fmt.Printf("    [\033[32m✔\033[0m] Eşleşen CVE bulunamadı.\n")
				}
			}
		}
	}

	return int(openCount), int(vulnCount)
}

// scanUDPPorts bilinen UDP servislerine probe paketi göndererek yanıt dinler
func scanUDPPorts(scanID int64, target string, rootID int64) int {
	fmt.Printf("[\033[36m*\033[0m] UDP Port Taraması Başlatıldı...\n")
	openCount := 0

	for port, payload := range UDPPortsToScan {
		address := net.JoinHostPort(target, port)
		conn, err := net.DialTimeout("udp", address, 3*time.Second)
		if err != nil {
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(payload)
		if err != nil {
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 0 {
			openCount++
			banner := sanitizeBanner(string(buf[:n]))

			svcName := "UDP Service"
			switch port {
			case "53":
				svcName = "DNS"
			case "161":
				svcName = "SNMP"
			case "123":
				svcName = "NTP"
			case "69":
				svcName = "TFTP"
			}

			fmt.Printf("  [\033[32m+\033[0m] UDP Port %s Açık (%s)\n", port, svcName)

			portData, _ := json.Marshal(map[string]string{"state": "open", "protocol": "udp", "service": svcName})
			portID, _ := db.AddNodeWithScan(scanID, "port", fmt.Sprintf("Port %s/UDP", port), string(portData))
			db.AddEdgeWithScan(scanID, rootID, portID, "has_port")

			if banner != "" {
				infoData, _ := json.Marshal(map[string]string{"banner": banner})
				infoNodeID, _ := db.AddNodeWithScan(scanID, "endpoint", svcName+" Servis Tespiti", string(infoData))
				db.AddEdgeWithScan(scanID, portID, infoNodeID, "runs_service")
			}
		}
	}
	return openCount
}

// StartRecon tek hedef için profil tabanlı, TCP+UDP, IPv6 uyumlu tam keşif motoru.
// Bu wrapper kendi scan kaydını oluşturur (geriye dönük uyumluluk için).
func StartRecon(target string, profile ScanProfile) *ScanResult {
	config := DefaultScanConfig(profile)
	scanID, err := db.CreateScan(target, profile.Name)
	if err != nil {
		fmt.Printf("[\033[31m-\033[0m] Scan kaydı oluşturulamadı: %v\n", err)
		return &ScanResult{Target: target}
	}
	result := StartReconWithConfig(scanID, target, config)
	db.FinishScan(scanID)
	return result
}

// StartReconWithConfig gelişmiş konfigürasyonla tarama başlatır.
// scanID > 0 olmalıdır; çağıran taraf scan kaydını db.CreateScan ile oluşturmalıdır.
func StartReconWithConfig(scanID int64, target string, config ScanConfig) *ScanResult {
	fmt.Printf("\n[\033[36m*\033[0m] %s için Recon Modülü Başlatıldı (scan_id=%d).\n", target, scanID)

	result := &ScanResult{Target: target}

	// DNS Çözümleme
	ipv4, ipv6, hostname := resolveTarget(target)
	if ipv4 == "" && ipv6 == "" && hostname == "" {
		fmt.Printf("[\033[33m!\033[0m] Ağ Çözümlemesi Hata: %s adresine ulaşılamıyor.\n", target)
		return result
	}
	fmt.Printf("[\033[36m*\033[0m] DNS Çözümleme: IPv4=[%s], IPv6=[%s], Hostname=[%s]\n", ipv4, ipv6, hostname)

	// OS Fingerprinting
	scanTarget := target
	if ipv4 != "" {
		scanTarget = ipv4
	}
	osByTTL := GetOSFromTTL(scanTarget)
	fmt.Printf("[\033[36m*\033[0m] OS Fingerprint (TTL): %s\n", osByTTL)

	// Hedef node verisi
	targetMap := map[string]interface{}{}
	if ipv4 != "" {
		targetMap["ip_address"] = ipv4
	}
	if ipv6 != "" {
		targetMap["ipv6_address"] = ipv6
	}
	if hostname != "" {
		targetMap["hostname"] = hostname
	}
	if osByTTL != "" && !strings.Contains(osByTTL, "Bilinemiyor") {
		targetMap["os_version"] = osByTTL
	}
	if len(targetMap) == 0 {
		targetMap["target"] = target
	}

	targetData, _ := json.Marshal(targetMap)

	displayLabel := target
	if hostname != "" && ipv4 != "" {
		displayLabel = fmt.Sprintf("%s\n[%s]", hostname, ipv4)
	} else if ipv4 != "" {
		displayLabel = ipv4
	}

	rootID, err := db.AddNodeWithScan(scanID, "target", displayLabel, string(targetData))
	if err != nil {
		fmt.Printf("[\033[31m-\033[0m] Hata: Veritabanına hedef işlenemedi: %v\n", err)
		return result
	}
	result.RootID = rootID

	// TCP Port Taraması (Eşzamanlı)
	fmt.Printf("[\033[36m*\033[0m] TCP Taraması Başlatıldı (%d port, %d worker, timeout %dms)...\n",
		len(config.Profile.Ports), config.Workers, config.Profile.TimeoutMs)

	openTCP, vulns := scanTCPPortsConcurrent(scanID, scanTarget, config, rootID)

	// UDP Taraması
	openUDP := scanUDPPorts(scanID, scanTarget, rootID)

	result.OpenTCP = openTCP
	result.OpenUDP = openUDP
	result.Vulns = vulns

	totalOpen := openTCP + openUDP
	if totalOpen > 0 {
		fmt.Printf("\n[\033[32m✔\033[0m] %s: Toplam %d açık port (TCP: %d, UDP: %d), %d zafiyet tespit edildi.\n",
			target, totalOpen, openTCP, openUDP, vulns)
	} else {
		fmt.Printf("[\033[31m-\033[0m] %s üzerinde açık port bulunamadı.\n", target)
	}

	return result
}

// StartMultiRecon birden fazla hedefi aynı scan_id altında sırayla tarar.
// scanID > 0 olmalıdır; çağıran taraf scan kaydını db.CreateScan ile oluşturmalıdır.
func StartMultiRecon(scanID int64, targets []string, config ScanConfig) []*ScanResult {
	fmt.Printf("[\033[36m*\033[0m] Çoklu hedef taraması (scan_id=%d): %d hedef\n", scanID, len(targets))
	fmt.Println("[\033[36m═══════════════════════════════════════════════════\033[0m]")

	var results []*ScanResult
	for i, t := range targets {
		fmt.Printf("\n[\033[36m*\033[0m] [%d/%d] Hedef: %s\n", i+1, len(targets), t)
		result := StartReconWithConfig(scanID, t, config)
		results = append(results, result)
	}

	// Özet
	totalPorts := 0
	totalVulns := 0
	for _, r := range results {
		totalPorts += r.OpenTCP + r.OpenUDP
		totalVulns += r.Vulns
	}

	fmt.Println("\n[\033[36m═══════════════════════════════════════════════════\033[0m]")
	fmt.Printf("[\033[32m✔\033[0m] Çoklu Tarama Tamamlandı: %d hedef, %d açık port, %d zafiyet\n",
		len(targets), totalPorts, totalVulns)

	return results
}
