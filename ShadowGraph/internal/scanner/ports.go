package scanner

import (
	"fmt"
	"strconv"
	"strings"
)

// ScanProfile tarama profilinin ayarlarını tanımlar
type ScanProfile struct {
	Name        string
	Ports       []string
	TimeoutMs   int
	DelayMs     int // Port arası bekleme (IDS atlatma için)
	Description string
}

// Top 10 — En yaygın açık portlar (Nmap istatistiklerine göre)
var top10Ports = []string{
	"80", "443", "22", "21", "25", "3306", "3389", "8080", "110", "143",
}

// Top 100 — Kurumsal ağlarda en çok rastlanan portlar
var top100Ports = []string{
	"7", "9", "13", "21", "22", "23", "25", "26", "37", "53",
	"79", "80", "81", "88", "106", "110", "111", "113", "119", "135",
	"139", "143", "144", "179", "199", "389", "427", "443", "444", "445",
	"465", "513", "514", "515", "543", "544", "548", "554", "587", "631",
	"646", "873", "990", "993", "995", "1025", "1026", "1027", "1028", "1029",
	"1110", "1433", "1720", "1723", "1755", "1900", "2000", "2001", "2049", "2121",
	"2717", "3000", "3128", "3306", "3389", "3986", "4899", "5000", "5009", "5051",
	"5060", "5101", "5190", "5357", "5432", "5631", "5666", "5800", "5900", "6000",
	"6001", "6646", "7070", "8000", "8008", "8009", "8080", "8081", "8443", "8888",
	"9100", "9200", "9999", "10000", "32768", "49152", "49153", "49154", "49155", "49156",
}

// GetProfile profil adına göre tarama konfigürasyonu döndürür
func GetProfile(name string) ScanProfile {
	switch strings.ToLower(name) {
	case "quick":
		return ScanProfile{
			Name:        "quick",
			Ports:       top10Ports,
			TimeoutMs:   1000,
			DelayMs:     0,
			Description: "Hızlı Tarama (Top 10 Port, 1s timeout)",
		}
	case "full":
		return ScanProfile{
			Name:        "full",
			Ports:       generateFullPorts(),
			TimeoutMs:   3000,
			DelayMs:     0,
			Description: "Tam Tarama (1-65535 arası tüm portlar)",
		}
	case "stealth":
		return ScanProfile{
			Name:        "stealth",
			Ports:       top100Ports,
			TimeoutMs:   5000,
			DelayMs:     500,
			Description: "Gizli Tarama (Yavaş, IDS/IPS atlatma modeli)",
		}
	default: // standard
		return ScanProfile{
			Name:        "standard",
			Ports:       top100Ports,
			TimeoutMs:   3000,
			DelayMs:     0,
			Description: "Standart Tarama (Top 100 Port, 3s timeout)",
		}
	}
}

// ParseCustomPorts kullanıcının --ports flag'i ile verdiği virgülle ayrılmış port listesini parse eder
func ParseCustomPorts(portsStr string) ([]string, error) {
	if portsStr == "" {
		return nil, nil
	}

	parts := strings.Split(portsStr, ",")
	var ports []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			// Port aralığı (Örn: 80-100)
			rangeParts := strings.SplitN(p, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("geçersiz port aralığı: %s", p)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, strconv.Itoa(i))
			}
		} else {
			portNum, err := strconv.Atoi(p)
			if err != nil || portNum < 1 || portNum > 65535 {
				return nil, fmt.Errorf("geçersiz port numarası: %s", p)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func generateFullPorts() []string {
	ports := make([]string, 65535)
	for i := 1; i <= 65535; i++ {
		ports[i-1] = strconv.Itoa(i)
	}
	return ports
}

// UDPPortsToScan UDP taraması için hedef portlar ve payload'lar
var UDPPortsToScan = map[string][]byte{
	"53":  {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x10, 0x00, 0x03}, // DNS version.bind query
	"161": {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x71, 0xb4, 0xd6, 0x30, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}, // SNMP sysDescr
	"123": {0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}, // NTP monlist
	"69":  {0x00, 0x01, 0x2f, 0x00, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00},                                                                                                         // TFTP read request
}
