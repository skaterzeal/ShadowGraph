package ai

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// AttackPath tek bir saldırı yolunu temsil eder (target → port → service → CVE zinciri)
type AttackPath struct {
	Steps      []PathStep `json:"steps"`
	RiskScore  float64    `json:"risk_score"`
	Complexity string     `json:"complexity"` // LOW, MEDIUM, HIGH
	Impact     string     `json:"impact"`     // CRITICAL, HIGH, MEDIUM, LOW
	Summary    string     `json:"summary"`
}

// PathStep saldırı yolundaki tek bir adım
type PathStep struct {
	NodeID   int64             `json:"node_id"`
	NodeType string            `json:"node_type"`
	Label    string            `json:"label"`
	Data     map[string]string `json:"data"`
	Action   string            `json:"action"` // İnsan-okunur aksiyon açıklaması
}

// AttackSurface genel saldırı yüzeyi analizi
type AttackSurface struct {
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

// ChainedAttack birden fazla zafiyetin birleştirilmesiyle oluşan saldırı senaryosu
type ChainedAttack struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CVEs        []string `json:"cves"`
	RiskScore   float64  `json:"risk_score"`
	Scenario    string   `json:"scenario"`
}

// graphNode iç graf temsili
type graphNode struct {
	ID       int64
	Type     string
	Label    string
	Data     map[string]string
	Children []int64
	Parents  []int64
}

// AnalyzeAttackPaths veritabanındaki graf verilerini analiz ederek saldırı yollarını hesaplar.
// scanID <= 0 ise en son scan kullanılır.
func AnalyzeAttackPaths(database *sql.DB, scanID int64) (*AttackSurface, error) {
	nodes, edges, err := loadGraph(database, scanID)
	if err != nil {
		return nil, fmt.Errorf("graf yüklenemedi: %w", err)
	}

	if len(nodes) == 0 {
		return &AttackSurface{
			Recommendations: []string{"Henüz tarama yapılmamış. 'shadowgraph scan -t <hedef>' komutuyla başlayın."},
		}, nil
	}

	// Adjacency list oluştur
	nodeMap := make(map[int64]*graphNode)
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}
	for _, e := range edges {
		if parent, ok := nodeMap[e.From]; ok {
			parent.Children = append(parent.Children, e.To)
		}
		if child, ok := nodeMap[e.To]; ok {
			child.Parents = append(child.Parents, e.From)
		}
	}

	// Tüm saldırı yollarını bul (target → ... → vulnerability)
	var allPaths []AttackPath
	for _, n := range nodes {
		if n.Type == "target" {
			paths := findPathsToVulns(nodeMap, n.ID, []int64{}, []PathStep{})
			allPaths = append(allPaths, paths...)
		}
	}

	// Risk skorlarını hesapla
	for i := range allPaths {
		calculatePathRisk(&allPaths[i])
	}

	// Skora göre sırala (yüksekten düşüğe)
	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].RiskScore > allPaths[j].RiskScore
	})

	// Zincirleme saldırı senaryoları tespit et
	chainedAttacks := detectChainedAttacks(allPaths, nodeMap)

	// Genel analiz
	surface := &AttackSurface{
		TotalPaths:     len(allPaths),
		ChainedAttacks: chainedAttacks,
	}

	for _, p := range allPaths {
		if p.RiskScore >= 9.0 {
			surface.CriticalPaths++
		} else if p.RiskScore >= 7.0 {
			surface.HighRiskPaths++
		}
	}

	// En riskli 10 yolu raporla
	limit := 10
	if len(allPaths) < limit {
		limit = len(allPaths)
	}
	surface.TopPaths = allPaths[:limit]

	// Genel risk skoru — en kötü-yol + ortalama karması, böylece tek bir
	// kritik yol toplamı yükseltirken yüzlerce düşük-risk path toplu skoru aşağı çekmez.
	if len(allPaths) > 0 {
		var totalRisk float64
		var maxRisk float64
		for _, p := range allPaths {
			totalRisk += p.RiskScore
			if p.RiskScore > maxRisk {
				maxRisk = p.RiskScore
			}
		}
		avgRisk := totalRisk / float64(len(allPaths))
		// 0.7 × en kötü yol + 0.3 × ortalama — maksimum 10.0
		surface.OverallRiskScore = math.Min(10.0, 0.7*maxRisk+0.3*avgRisk)
	}

	// Zincirleme saldırı risk skorunu overall score'a dahil et.
	// Eğer chained attack risk'i overall'dan yüksekse, ağırlıklı harmanlama yap.
	if len(chainedAttacks) > 0 {
		maxChainRisk := 0.0
		for _, ch := range chainedAttacks {
			if ch.RiskScore > maxChainRisk {
				maxChainRisk = ch.RiskScore
			}
		}
		if maxChainRisk > surface.OverallRiskScore {
			// Zincirleme senaryo riski yüksekse: %60 chain + %40 mevcut path skoru
			surface.OverallRiskScore = math.Min(10.0, 0.6*maxChainRisk+0.4*surface.OverallRiskScore)
		}
	}

	surface.RiskLevel = classifyRisk(surface.OverallRiskScore)
	surface.Recommendations = generateRecommendations(allPaths, nodeMap, surface.RiskLevel)
	surface.Summary = buildSurfaceSummary(surface)

	return surface, nil
}

// buildSurfaceSummary, AttackSurface'ın kısa bir metin özetini üretir.
// Bu özet DB'ye ve UI'a sunulur.
func buildSurfaceSummary(s *AttackSurface) string {
	if s == nil || s.TotalPaths == 0 {
		return "Grafikte analiz edilecek saldırı yolu bulunamadı. (Tarama eksik ya da ciddi zafiyet tespit edilmedi.)"
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("%.1f/10 genel risk (%s)", s.OverallRiskScore, s.RiskLevel))
	parts = append(parts, fmt.Sprintf("%d toplam yol", s.TotalPaths))
	if s.CriticalPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d kritik", s.CriticalPaths))
	}
	if s.HighRiskPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d yüksek", s.HighRiskPaths))
	}
	if len(s.ChainedAttacks) > 0 {
		parts = append(parts, fmt.Sprintf("%d zincirleme senaryo", len(s.ChainedAttacks)))
	}
	base := strings.Join(parts, " · ")
	if len(s.Recommendations) > 0 {
		base += ". Birincil öneri: " + s.Recommendations[0]
	}
	return base
}

// findPathsToVulns DFS ile target'tan saldırı yüzeylerine giden tüm yolları bulur.
// Yol tamamlanma kriteri: bir "vulnerability" (CVE eşleşmiş zafiyet) VEYA bir
// "exploit" (bilinen public exploit) düğümüne ulaşmak. Exploit varlığı CVE
// eşleşmesi olmasa bile bir saldırı yüzeyi kanıtıdır (silahlandırılmış
// zafiyetin halihazırda yayınlandığını gösterir).
func findPathsToVulns(nodeMap map[int64]*graphNode, currentID int64, visited []int64, currentPath []PathStep) []AttackPath {
	node, ok := nodeMap[currentID]
	if !ok {
		return nil
	}

	// Döngü kontrolü
	for _, v := range visited {
		if v == currentID {
			return nil
		}
	}

	visited = append(visited, currentID)

	step := PathStep{
		NodeID:   node.ID,
		NodeType: node.Type,
		Label:    node.Label,
		Data:     node.Data,
		Action:   describeAction(node),
	}
	currentPath = append(currentPath, step)

	var paths []AttackPath

	// Saldırı yüzeyine ulaştıysak yol tamamlandı (vulnerability VEYA exploit).
	// Bir hedefte yalnızca exploit varsa (CVE eşleşmemiş) bile bu kritik bir
	// saldırı yüzeyi kanıtıdır ve raporlanmalıdır.
	if (node.Type == "vulnerability" || node.Type == "exploit") && len(currentPath) > 1 {
		pathCopy := make([]PathStep, len(currentPath))
		copy(pathCopy, currentPath)
		paths = append(paths, AttackPath{
			Steps:   pathCopy,
			Summary: buildPathSummary(pathCopy),
		})
	}

	// Çocukları explore et
	for _, childID := range node.Children {
		childPaths := findPathsToVulns(nodeMap, childID, visited, currentPath)
		paths = append(paths, childPaths...)
	}

	return paths
}

// calculatePathRisk yol için risk skoru hesaplar
func calculatePathRisk(path *AttackPath) {
	baseScore := 0.0
	complexity := "LOW"
	maxSeverity := "LOW"

	for _, step := range path.Steps {
		switch step.NodeType {
		case "vulnerability":
			sev := strings.ToUpper(step.Data["severity"])
			cvss := parseCVSS(step.Data["cvss"])
			switch {
			case strings.Contains(sev, "CRITICAL") || cvss >= 9.0:
				baseScore += 10.0
				maxSeverity = "CRITICAL"
			case strings.Contains(sev, "HIGH") || cvss >= 7.0:
				baseScore += 7.5
				if maxSeverity != "CRITICAL" {
					maxSeverity = "HIGH"
				}
			case strings.Contains(sev, "MEDIUM") || cvss >= 4.0:
				baseScore += 5.0
				if maxSeverity != "CRITICAL" && maxSeverity != "HIGH" {
					maxSeverity = "MEDIUM"
				}
			case sev == "" || sev == "N/A" || sev == "UNKNOWN":
				// Severity bilinmiyorsa MEDIUM varsay (güvenli tarafta kal)
				baseScore += 5.0
				if maxSeverity != "CRITICAL" && maxSeverity != "HIGH" {
					maxSeverity = "MEDIUM"
				}
			default:
				baseScore += 2.5
			}
		case "exploit":
			// Yayınlanmış public exploit'in varlığı, eşleşmiş bir CVE olmasa bile
			// ciddi bir risk göstergesidir (saldırgan silahlandırılmış kod elinde).
			// Tipe göre derecelendir; "remote" RCE en yüksek skoru alır.
			expType := strings.ToLower(step.Data["type"])
			source := strings.ToLower(step.Data["source"])
			score := 7.0 // varsayılan: bilinen exploit varlığı = HIGH
			switch expType {
			case "remote":
				score = 8.5
			case "webapps":
				score = 7.5
			case "local":
				score = 5.5
			case "dos":
				score = 4.5
			}
			// Metasploit modülü = düşük teknik bariyer (script kiddie seviyesinde
			// kullanılabilir) — riski biraz daha yükselt.
			if strings.Contains(source, "metasploit") {
				score += 0.5
			}
			baseScore += score
			if score >= 8.5 {
				if maxSeverity != "CRITICAL" {
					maxSeverity = "HIGH"
				}
			} else if score >= 7.0 {
				if maxSeverity != "CRITICAL" && maxSeverity != "HIGH" {
					maxSeverity = "HIGH"
				}
			} else if maxSeverity != "CRITICAL" && maxSeverity != "HIGH" {
				maxSeverity = "MEDIUM"
			}
		case "port":
			// Kritik portlar ek risk
			label := step.Label
			if strings.Contains(label, "22") || strings.Contains(label, "3389") {
				baseScore += 1.5 // Remote access portları
			}
			if strings.Contains(label, "445") || strings.Contains(label, "139") {
				baseScore += 2.0 // SMB portları (lateral movement)
			}
			if strings.Contains(label, "3306") || strings.Contains(label, "5432") || strings.Contains(label, "27017") {
				baseScore += 1.5 // Veritabanı portları
			}
		case "endpoint":
			svc := strings.ToLower(step.Data["service"])
			// Eski/bilinen zafiyetli servisler
			if strings.Contains(svc, "ftp") || strings.Contains(svc, "telnet") {
				baseScore += 2.0
				complexity = "LOW"
			}
		}
	}

	// Yol uzunluğu karmaşıklığı etkiler
	stepCount := len(path.Steps)
	if stepCount > 4 {
		complexity = "HIGH"
	} else if stepCount > 2 {
		complexity = "MEDIUM"
	}

	// Normalize (0-10)
	path.RiskScore = math.Min(10.0, baseScore)
	path.Complexity = complexity
	path.Impact = maxSeverity
}

// detectChainedAttacks birden fazla CVE veya public exploit kombinasyonunu içeren
// saldırı senaryolarını tespit eder. Exploit varlığı CVE eşleşmesinden bağımsız
// olarak değerlendirilir — silahlandırılmış public exploit elindeki bir saldırgan
// için CVE eşleşmesi olup olmaması fark etmez.
func detectChainedAttacks(paths []AttackPath, _ map[int64]*graphNode) []ChainedAttack {
	var chains []ChainedAttack

	// Aynı target'a ait CVE/exploit'leri grupla
	targetVulns := make(map[string][]string) // target label → CVE/Exploit IDs
	targetExploits := make(map[string][]string) // target label → exploit ID + açıklama
	targetPorts := make(map[string]map[string]bool)

	for _, p := range paths {
		targetLabel := ""
		var cves []string
		var exploits []string
		ports := make(map[string]bool)

		for _, step := range p.Steps {
			if step.NodeType == "target" {
				targetLabel = step.Label
			}
			if step.NodeType == "port" {
				ports[step.Label] = true
			}
			if step.NodeType == "vulnerability" {
				cveID := step.Data["cve"]
				if cveID != "" {
					cves = append(cves, cveID)
				}
			}
			if step.NodeType == "exploit" {
				expID := step.Data["exploit_id"]
				if expID != "" {
					exploits = append(exploits, expID)
				}
				// Exploit'e bağlı CVE'ler "cves" alanından (virgülle ayrılmış)
				// ve "cve_N" indeksli alanlardan toplanır — rapor üretiminde
				// tek bir CVE listesi sunulur.
				if cveList := step.Data["cves"]; cveList != "" {
					for _, c := range strings.Split(cveList, ",") {
						c = strings.TrimSpace(c)
						if strings.HasPrefix(strings.ToUpper(c), "CVE-") {
							cves = append(cves, c)
						}
					}
				}
				for k, v := range step.Data {
					if strings.HasPrefix(k, "cve_") && strings.HasPrefix(strings.ToUpper(v), "CVE-") {
						cves = append(cves, v)
					}
				}
			}
		}

		if targetLabel != "" {
			targetVulns[targetLabel] = append(targetVulns[targetLabel], cves...)
			targetExploits[targetLabel] = append(targetExploits[targetLabel], exploits...)
			if targetPorts[targetLabel] == nil {
				targetPorts[targetLabel] = make(map[string]bool)
			}
			for k, v := range ports {
				targetPorts[targetLabel][k] = v
			}
		}
	}

	for target, cves := range targetVulns {
		uniqueCVEs := uniqueStrings(cves)
		uniqueExploits := uniqueStrings(targetExploits[target])
		ports := targetPorts[target]

		// Senaryo: Remote Access + Vulnerability = Remote Code Execution
		hasRemoteAccess := ports["Port 22"] || ports["Port 3389"] || ports["Port 23"]
		hasWebVuln := false
		hasDBExposed := ports["Port 3306"] || ports["Port 5432"] || ports["Port 27017"] || ports["Port 6379"]
		hasExploit := len(uniqueExploits) > 0

		for _, cve := range uniqueCVEs {
			if strings.Contains(strings.ToLower(cve), "cve") {
				hasWebVuln = true
				break
			}
		}

		// SENARYO 1: Public exploit + uzaktan erişim portu = Hazır RCE saldırısı
		// Bu en kritik durum: silahlandırılmış kod + saldırı yüzeyi açık.
		if hasRemoteAccess && hasExploit {
			chains = append(chains, ChainedAttack{
				Name:        "Hazır Public Exploit + Açık Uzak Erişim",
				Description: fmt.Sprintf("%s üzerinde uzaktan erişim portu açık ve eşleşen public exploit yayınlanmış (%d adet)", target, len(uniqueExploits)),
				CVEs:        append(uniqueExploits, uniqueCVEs...),
				RiskScore:   9.5,
				Scenario:    "Saldırgan zaten yayınlanmış exploit kodunu (Metasploit/ExploitDB) doğrudan kullanarak başlangıç erişimi sağlayabilir. Exploit'in halka açık olması istismar bariyerini script-kiddie seviyesine indirir.",
			})
		}

		// SENARYO 2: Public exploit + veritabanı portu = Hazır veri sızıntısı
		if hasDBExposed && hasExploit {
			chains = append(chains, ChainedAttack{
				Name:        "Hazır Exploit + Açık Veritabanı",
				Description: fmt.Sprintf("%s üzerinde açık veritabanı portu ve eşleşen public exploit tespit edildi", target),
				CVEs:        append(uniqueExploits, uniqueCVEs...),
				RiskScore:   9.0,
				Scenario:    "Saldırgan public exploit'i kullanarak veritabanı servisine doğrudan erişim sağlayabilir; sonrasında toplu veri sızıntısı veya kalıcılık (persistence) mümkündür.",
			})
		}

		if hasRemoteAccess && hasWebVuln && len(uniqueCVEs) >= 2 {
			chains = append(chains, ChainedAttack{
				Name:        "Remote Code Execution Zinciri",
				Description: fmt.Sprintf("%s üzerinde uzaktan erişim portu + bilinen zafiyet kombinasyonu tespit edildi", target),
				CVEs:        uniqueCVEs,
				RiskScore:   9.5,
				Scenario:    "Saldırgan web zafiyetini kullanarak initial access sağlar, ardından uzak erişim portundan lateral movement yapar.",
			})
		}

		if hasDBExposed && len(uniqueCVEs) > 0 {
			chains = append(chains, ChainedAttack{
				Name:        "Veri Sızıntısı Riski",
				Description: fmt.Sprintf("%s üzerinde açık veritabanı portu + zafiyet tespit edildi", target),
				CVEs:        uniqueCVEs,
				RiskScore:   8.5,
				Scenario:    "Açık veritabanı portu üzerinden doğrudan veri erişimi veya zafiyet exploit'i ile veri sızıntısı mümkün.",
			})
		}

		if len(uniqueCVEs) >= 3 {
			chains = append(chains, ChainedAttack{
				Name:        "Çoklu Zafiyet Escalation",
				Description: fmt.Sprintf("%s üzerinde %d farklı zafiyet tespit edildi — zincirleme exploit riski yüksek", target, len(uniqueCVEs)),
				CVEs:        uniqueCVEs,
				RiskScore:   9.0,
				Scenario:    "Birden fazla zafiyet birleştirilerek privilege escalation ve tam sistem kontrolü elde edilebilir.",
			})
		}

		// SENARYO 3: 2+ public exploit aynı hedefte = Kompozit istismar
		if len(uniqueExploits) >= 2 {
			chains = append(chains, ChainedAttack{
				Name:        "Çoklu Public Exploit Eşleşmesi",
				Description: fmt.Sprintf("%s üzerinde %d farklı public exploit eşleşti — birden fazla istismar yolu mevcut", target, len(uniqueExploits)),
				CVEs:        uniqueExploits,
				RiskScore:   8.8,
				Scenario:    "Saldırgan exploit'lerden birinin defansif ürünler tarafından engellendiği durumda diğerine geçebilir. Tek bir patch yetmez — hepsi yamalanmalı veya etkilenen servisler kapatılmalıdır.",
			})
		}
	}

	sort.Slice(chains, func(i, j int) bool {
		return chains[i].RiskScore > chains[j].RiskScore
	})
	return chains
}

// generateRecommendations analiz sonuçlarına göre öneriler üretir.
// riskLevel, overall scoring sonrası belirlenen seviyedir ve "öneri yok" durumunda
// çelişkili metin (ör. Risk=CRITICAL ama "ciddi yol yok") yazmamak için kullanılır.
func generateRecommendations(paths []AttackPath, _ map[int64]*graphNode, riskLevel string) []string {
	var recs []string
	seen := make(map[string]bool)

	criticalCVEs := 0
	publicExploits := 0
	exposedDBs := false
	remoteAccessOpen := false
	oldServices := false

	for _, p := range paths {
		for _, step := range p.Steps {
			if step.NodeType == "vulnerability" {
				sev := strings.ToUpper(step.Data["severity"])
				if strings.Contains(sev, "CRITICAL") {
					criticalCVEs++
					cve := step.Data["cve"]
					if cve != "" && !seen["patch_"+cve] {
						seen["patch_"+cve] = true
						recs = append(recs, fmt.Sprintf("ACİL: %s zafiyetini derhal yamalayın (Severity: CRITICAL)", cve))
					}
				}
			}
			if step.NodeType == "exploit" {
				publicExploits++
				expID := step.Data["exploit_id"]
				desc := step.Data["description"]
				if expID != "" && !seen["exp_"+expID] {
					seen["exp_"+expID] = true
					recs = append(recs, fmt.Sprintf("ACİL: %s için public exploit yayınlanmış (%s) — etkilenen servisi yamalayın veya devre dışı bırakın", expID, desc))
				}
			}
			if step.NodeType == "port" {
				label := step.Label
				if strings.Contains(label, "3306") || strings.Contains(label, "5432") || strings.Contains(label, "27017") || strings.Contains(label, "6379") {
					exposedDBs = true
				}
				if strings.Contains(label, "22") || strings.Contains(label, "3389") || strings.Contains(label, "23") {
					remoteAccessOpen = true
				}
				if strings.Contains(label, "21") || strings.Contains(label, "23") {
					oldServices = true
				}
			}
			if step.NodeType == "endpoint" {
				svc := strings.ToLower(step.Data["service"])
				if svc == "ftp" || svc == "vsftpd" || svc == "telnet" {
					oldServices = true
				}
			}
		}
	}

	if exposedDBs && !seen["db"] {
		seen["db"] = true
		recs = append(recs, "Veritabanı portlarını (3306, 5432, 27017, 6379) dış erişime kapatın veya firewall kuralı ekleyin.")
	}
	if remoteAccessOpen && !seen["remote"] {
		seen["remote"] = true
		recs = append(recs, "Uzak erişim portlarını (22, 3389) IP kısıtlaması veya VPN arkasına alın.")
	}
	if oldServices && !seen["legacy"] {
		seen["legacy"] = true
		recs = append(recs, "Eski protokolleri (FTP, Telnet) devre dışı bırakıp SFTP/SSH ile değiştirin.")
	}
	if criticalCVEs > 0 && !seen["patch_general"] {
		seen["patch_general"] = true
		recs = append(recs, fmt.Sprintf("Toplam %d CRITICAL zafiyet tespit edildi — acil yama planı oluşturun.", criticalCVEs))
	}
	if publicExploits > 0 && !seen["exploit_general"] {
		seen["exploit_general"] = true
		recs = append(recs, fmt.Sprintf("Toplam %d public exploit eşleşti — bu servisler aktif istismar tehdidi altındadır; SOC/IDS imzalarını güncelleyin ve etkilenen sürümleri ivedilikle yükseltin.", publicExploits))
	}

	// Fallback: spesifik öneri oluşmadıysa genel mesaj — ancak risk seviyesine göre
	// çelişki oluşturmayacak şekilde seçilir.
	if len(recs) == 0 {
		switch strings.ToUpper(riskLevel) {
		case "CRITICAL", "HIGH":
			recs = append(recs, "Spesifik CVE eşlemesi yapılamadı ancak yüksek riskli saldırı yolları mevcut — tespit edilen zafiyetleri ve açık portları gözden geçirip önceliklendirin.")
		case "MEDIUM":
			recs = append(recs, "Orta seviye saldırı yolları tespit edildi — açık servisleri gözden geçirin ve gereksiz olanları kapatın.")
		default:
			recs = append(recs, "Düşük seviye saldırı yolları tespit edildi. Servis versiyonlarını güncel tutun ve düzenli taramaya devam edin.")
		}
	}

	return recs
}

func describeAction(node *graphNode) string {
	switch node.Type {
	case "target":
		return "Hedef keşfedildi"
	case "port":
		return fmt.Sprintf("%s açık — bağlantı noktası tespit edildi", node.Label)
	case "endpoint":
		svc := node.Data["service"]
		ver := node.Data["version"]
		if svc != "" && ver != "" {
			return fmt.Sprintf("%s %s servisi çalışıyor", svc, ver)
		}
		return "Servis tespit edildi"
	case "vulnerability":
		return fmt.Sprintf("Zafiyet: %s (Severity: %s)", node.Data["cve"], node.Data["severity"])
	case "exploit":
		expID := node.Data["exploit_id"]
		src := node.Data["source"]
		desc := node.Data["description"]
		if expID == "" {
			expID = node.Label
		}
		if desc != "" {
			return fmt.Sprintf("Public Exploit: %s [%s] — %s", expID, src, desc)
		}
		return fmt.Sprintf("Public Exploit: %s [%s]", expID, src)
	}
	return ""
}

func buildPathSummary(steps []PathStep) string {
	var parts []string
	for _, s := range steps {
		switch s.NodeType {
		case "target":
			parts = append(parts, s.Label)
		case "port":
			parts = append(parts, s.Label)
		case "endpoint":
			svc := s.Data["service"]
			ver := s.Data["version"]
			if svc != "" && ver != "" {
				parts = append(parts, svc+" "+ver)
			} else if svc != "" {
				parts = append(parts, svc)
			} else {
				parts = append(parts, s.Label)
			}
		case "vulnerability":
			parts = append(parts, s.Data["cve"])
		case "exploit":
			id := s.Data["exploit_id"]
			if id == "" {
				id = s.Label
			}
			parts = append(parts, "Exploit:"+id)
		}
	}
	return strings.Join(parts, " → ")
}

func classifyRisk(score float64) string {
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

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if v != "" && !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// parseCVSS sayısal CVSS skoru çıkarmaya çalışır; başarısızsa 0 döner.
func parseCVSS(s string) float64 {
	if s == "" {
		return 0
	}
	var v float64
	fmt.Sscanf(s, "%f", &v)
	return v
}

type edgeRow struct {
	From int64
	To   int64
}

func loadGraph(database *sql.DB, scanID int64) ([]graphNode, []edgeRow, error) {
	// scanID <= 0 ise en son scan'ı kullan
	resolvedID := scanID
	if resolvedID <= 0 {
		var maxID int64
		err := database.QueryRow("SELECT COALESCE(MAX(id), 0) FROM scans").Scan(&maxID)
		if err != nil {
			return nil, nil, fmt.Errorf("son scan_id okunamadı: %w", err)
		}
		resolvedID = maxID
	}

	// Hiç scan yoksa boş graf döndür
	if resolvedID == 0 {
		return nil, nil, nil
	}

	rows, err := database.Query(`
		SELECT id, type, label, COALESCE(data, '{}')
		FROM nodes WHERE scan_id = ?`, resolvedID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var nodes []graphNode
	for rows.Next() {
		var n graphNode
		var dataStr string
		if err := rows.Scan(&n.ID, &n.Type, &n.Label, &dataStr); err != nil {
			continue
		}
		n.Data = make(map[string]string)
		json.Unmarshal([]byte(dataStr), &n.Data)
		nodes = append(nodes, n)
	}

	edgeRows, err := database.Query(`
		SELECT from_node, to_node
		FROM edges WHERE scan_id = ?`, resolvedID)
	if err != nil {
		return nil, nil, err
	}
	defer edgeRows.Close()

	var edges []edgeRow
	for edgeRows.Next() {
		var e edgeRow
		if err := edgeRows.Scan(&e.From, &e.To); err != nil {
			continue
		}
		edges = append(edges, e)
	}

	return nodes, edges, nil
}

// PrintAttackSurface analiz sonuçlarını konsola yazdırır
func PrintAttackSurface(surface *AttackSurface) {
	fmt.Println("\n\033[1;36m══════════════════════════════════════════════════════════════\033[0m")
	fmt.Println("\033[1;36m          SHADOWGRAPH — AI ATTACK PATH ANALİZİ\033[0m")
	fmt.Println("\033[1;36m══════════════════════════════════════════════════════════════\033[0m")

	// Genel risk
	riskColor := "\033[32m" // green
	switch surface.RiskLevel {
	case "CRITICAL":
		riskColor = "\033[1;31m"
	case "HIGH":
		riskColor = "\033[31m"
	case "MEDIUM":
		riskColor = "\033[33m"
	}
	fmt.Printf("\n  Genel Risk Skoru: %s%.1f/10 (%s)\033[0m\n", riskColor, surface.OverallRiskScore, surface.RiskLevel)
	fmt.Printf("  Toplam Saldırı Yolu: %d | Kritik: %d | Yüksek: %d\n",
		surface.TotalPaths, surface.CriticalPaths, surface.HighRiskPaths)

	// Zincirleme saldırılar
	if len(surface.ChainedAttacks) > 0 {
		fmt.Println("\n\033[1;31m  ⚠ ZİNCİRLEME SALDIRI SENARYOLARI:\033[0m")
		for i, chain := range surface.ChainedAttacks {
			fmt.Printf("  \033[31m%d.\033[0m %s (Risk: %.1f)\n", i+1, chain.Name, chain.RiskScore)
			fmt.Printf("     %s\n", chain.Description)
			fmt.Printf("     \033[33mSenaryo:\033[0m %s\n", chain.Scenario)
			fmt.Printf("     CVEs: %s\n", strings.Join(chain.CVEs, ", "))
		}
	}

	// En riskli yollar
	if len(surface.TopPaths) > 0 {
		fmt.Println("\n\033[1;36m  EN RİSKLİ SALDIRI YOLLARI:\033[0m")
		for i, p := range surface.TopPaths {
			rColor := "\033[32m"
			if p.RiskScore >= 9 {
				rColor = "\033[1;31m"
			} else if p.RiskScore >= 7 {
				rColor = "\033[31m"
			} else if p.RiskScore >= 4 {
				rColor = "\033[33m"
			}
			fmt.Printf("  %s#%d\033[0m [Risk: %s%.1f\033[0m] %s\n", rColor, i+1, rColor, p.RiskScore, p.Summary)
			fmt.Printf("       Karmaşıklık: %s | Etki: %s\n", p.Complexity, p.Impact)
		}
	}

	// Öneriler
	if len(surface.Recommendations) > 0 {
		fmt.Println("\n\033[1;32m  ÖNERİLER:\033[0m")
		for i, r := range surface.Recommendations {
			fmt.Printf("  \033[32m%d.\033[0m %s\n", i+1, r)
		}
	}

	fmt.Println("\n\033[1;36m══════════════════════════════════════════════════════════════\033[0m")
}
