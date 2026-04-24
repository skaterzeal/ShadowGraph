package importer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/shadowgraph/core/internal/db"
)

// NmapRun Nmap XML çıktısının kök yapısı
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Scanner string     `xml:"scanner,attr"`
	Args    string     `xml:"args,attr"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost tek bir host
type NmapHost struct {
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Hostnames NmapHostnames `xml:"hostnames"`
	Ports     NmapPorts     `xml:"ports"`
	OS        NmapOS        `xml:"os"`
}

type NmapStatus struct {
	State string `xml:"state,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapHostnames struct {
	Hostnames []NmapHostname `xml:"hostname"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
	Scripts  []NmapScript `xml:"script"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extra   string `xml:"extrainfo,attr"`
	Tunnel  string `xml:"tunnel,attr"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapOS struct {
	OSMatches []NmapOSMatch `xml:"osmatch"`
}

type NmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// MasscanRun Masscan JSON çıktısı
type MasscanEntry struct {
	IP        string          `json:"ip"`
	Timestamp string          `json:"timestamp"`
	Ports     []MasscanPort   `json:"ports"`
}

type MasscanPort struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Status   string `json:"status"`
	Service  MasscanService `json:"service,omitempty"`
}

type MasscanService struct {
	Name   string `json:"name"`
	Banner string `json:"banner"`
}

// ImportResult import işleminin sonucu
type ImportResult struct {
	Source     string
	Hosts      int
	Ports      int
	Services   int
	Vulns      int
}

// ImportNmapXML Nmap XML dosyasını parse ederek ShadowGraph veritabanına yazar
func ImportNmapXML(filePath string) (*ImportResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("dosya okunamadı: %v", err)
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, fmt.Errorf("XML parse hatası: %v", err)
	}

	// Kaynak tespiti
	source := "nmap"
	if strings.Contains(nmapRun.Scanner, "masscan") {
		source = "masscan"
	}

	result := &ImportResult{Source: source}

	// Yeni scan kaydı
	scanID, _ := db.CreateScan("import:"+filePath, source)

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}

		result.Hosts++

		// IP ve hostname çıkar
		var ipv4, ipv6, hostname string
		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4":
				ipv4 = addr.Addr
			case "ipv6":
				ipv6 = addr.Addr
			}
		}
		if len(host.Hostnames.Hostnames) > 0 {
			hostname = host.Hostnames.Hostnames[0].Name
		}

		// OS tespiti
		osName := ""
		if len(host.OS.OSMatches) > 0 {
			osName = host.OS.OSMatches[0].Name
		}

		// Target node oluştur
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
		if osName != "" {
			targetMap["os_version"] = osName
		}
		targetMap["import_source"] = source

		targetData, _ := json.Marshal(targetMap)

		displayLabel := ipv4
		if hostname != "" {
			displayLabel = fmt.Sprintf("%s\n[%s]", hostname, ipv4)
		}
		if displayLabel == "" {
			displayLabel = ipv6
		}

		rootID, err := db.AddNodeWithScan(scanID, "target", displayLabel, string(targetData))
		if err != nil {
			continue
		}

		// Portları işle
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			result.Ports++

			portData, _ := json.Marshal(map[string]string{
				"state":    port.State.State,
				"protocol": port.Protocol,
				"service":  port.Service.Name,
			})

			portLabel := fmt.Sprintf("Port %s", port.PortID)
			if port.Protocol == "udp" {
				portLabel = fmt.Sprintf("Port %s/UDP", port.PortID)
			}

			portID, _ := db.AddNodeWithScan(scanID, "port", portLabel, string(portData))
			db.AddEdgeWithScan(scanID, rootID, portID, "has_port")

			// Servis bilgisi
			if port.Service.Product != "" || port.Service.Name != "" {
				result.Services++

				svcLabel := port.Service.Product
				if port.Service.Version != "" {
					svcLabel += " " + port.Service.Version
				}
				if svcLabel == "" {
					svcLabel = port.Service.Name
				}

				svcData, _ := json.Marshal(map[string]string{
					"service": port.Service.Name,
					"product": port.Service.Product,
					"version": port.Service.Version,
					"extra":   port.Service.Extra,
					"banner":  fmt.Sprintf("%s %s", port.Service.Product, port.Service.Version),
				})

				svcID, _ := db.AddNodeWithScan(scanID, "endpoint", svcLabel, string(svcData))
				db.AddEdgeWithScan(scanID, portID, svcID, "runs_service")

				// NSE script çıktılarından CVE çıkar
				for _, script := range port.Scripts {
					if strings.Contains(script.ID, "vuln") || strings.Contains(script.ID, "cve") {
						result.Vulns++

						vulnData, _ := json.Marshal(map[string]string{
							"cve":      script.ID,
							"severity": "HIGH",
							"desc":     script.Output,
							"source":   "nmap-nse",
						})

						vulnID, _ := db.AddNodeWithScan(scanID, "vulnerability", script.ID, string(vulnData))
						db.AddEdgeWithScan(scanID, svcID, vulnID, "vulnerable_to")
					}
				}
			}
		}
	}

	db.FinishScan(scanID)
	return result, nil
}

// ImportMasscanJSON Masscan JSON çıktısını parse ederek veritabanına yazar
func ImportMasscanJSON(filePath string) (*ImportResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("dosya okunamadı: %v", err)
	}

	// Masscan JSON formatı: satır satır JSON veya JSON array
	var entries []MasscanEntry

	// Önce array olarak dene
	if err := json.Unmarshal(data, &entries); err != nil {
		// Satır satır JSON (NDJSON) formatı
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line == "[" || line == "]" || strings.HasPrefix(line, "{finished") {
				continue
			}
			line = strings.TrimSuffix(line, ",")
			var entry MasscanEntry
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
				entries = append(entries, entry)
			}
		}
	}

	result := &ImportResult{Source: "masscan"}
	scanID, _ := db.CreateScan("import:"+filePath, "masscan")

	// IP bazlı gruplama
	hostPorts := make(map[string][]MasscanPort)
	for _, entry := range entries {
		hostPorts[entry.IP] = append(hostPorts[entry.IP], entry.Ports...)
	}

	for ip, ports := range hostPorts {
		result.Hosts++

		targetData, _ := json.Marshal(map[string]interface{}{
			"ip_address":    ip,
			"import_source": "masscan",
		})
		rootID, _ := db.AddNodeWithScan(scanID, "target", ip, string(targetData))

		for _, port := range ports {
			if port.Status != "open" {
				continue
			}
			result.Ports++

			portData, _ := json.Marshal(map[string]string{
				"state":    port.Status,
				"protocol": port.Proto,
			})
			portLabel := fmt.Sprintf("Port %d", port.Port)
			if port.Proto == "udp" {
				portLabel = fmt.Sprintf("Port %d/UDP", port.Port)
			}

			portID, _ := db.AddNodeWithScan(scanID, "port", portLabel, string(portData))
			db.AddEdgeWithScan(scanID, rootID, portID, "has_port")

			if port.Service.Name != "" {
				result.Services++
				svcData, _ := json.Marshal(map[string]string{
					"service": port.Service.Name,
					"banner":  port.Service.Banner,
				})
				svcID, _ := db.AddNodeWithScan(scanID, "endpoint", port.Service.Name, string(svcData))
				db.AddEdgeWithScan(scanID, portID, svcID, "runs_service")
			}
		}
	}

	db.FinishScan(scanID)
	return result, nil
}

// DetectAndImport dosya uzantısına göre uygun import fonksiyonunu seçer
func DetectAndImport(filePath string) (*ImportResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(data))

	// XML kontrolü
	if strings.HasPrefix(content, "<?xml") || strings.HasPrefix(content, "<nmaprun") {
		return ImportNmapXML(filePath)
	}

	// JSON kontrolü (Masscan)
	if strings.HasPrefix(content, "[") || strings.HasPrefix(content, "{") {
		return ImportMasscanJSON(filePath)
	}

	return nil, fmt.Errorf("tanınmayan dosya formatı: XML (Nmap) veya JSON (Masscan) bekleniyor")
}
