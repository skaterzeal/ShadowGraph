package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// ExpandTargets hedef stringini analiz eder: tek IP, hostname, CIDR bloğu veya virgülle ayrılmış listeyi destekler
func ExpandTargets(input string) ([]string, error) {
	var allTargets []string

	// Virgülle ayrılmış hedefler
	parts := strings.Split(input, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// CIDR bloğu kontrolü
		if strings.Contains(p, "/") {
			ips, err := expandCIDR(p)
			if err != nil {
				return nil, fmt.Errorf("CIDR parse hatası (%s): %v", p, err)
			}
			allTargets = append(allTargets, ips...)
		} else {
			allTargets = append(allTargets, p)
		}
	}

	if len(allTargets) == 0 {
		return nil, fmt.Errorf("geçerli hedef bulunamadı")
	}

	return uniqueTargets(allTargets), nil
}

// expandCIDR bir CIDR bloğundaki tüm kullanılabilir IP adreslerini döner
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Mask boyutunu kontrol et — /16'dan büyük bloklar çok fazla IP üretir
	ones, bits := ipNet.Mask.Size()
	if bits-ones > 16 {
		return nil, fmt.Errorf("CIDR bloğu çok geniş (/%d): maksimum /16 destekleniyor", ones)
	}

	var ips []string
	for currentIP := cloneIP(ip.Mask(ipNet.Mask)); ipNet.Contains(currentIP); incrementIP(currentIP) {
		// Network ve broadcast adreslerini atla (/31 ve /32 hariç)
		if ones < 31 {
			if isNetworkAddr(currentIP, ipNet) || isBroadcastAddr(currentIP, ipNet) {
				continue
			}
		}
		ips = append(ips, currentIP.String())
	}

	return ips, nil
}

// LoadTargetsFromFile dosyadan hedef listesi okur (her satır bir hedef)
func LoadTargetsFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("hedef dosyası okunamadı: %v", err)
	}

	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		expanded, err := ExpandTargets(line)
		if err != nil {
			return nil, err
		}
		targets = append(targets, expanded...)
	}

	return uniqueTargets(targets), nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func isNetworkAddr(ip net.IP, network *net.IPNet) bool {
	networkAddr := network.IP.Mask(network.Mask)
	return ip.Equal(networkAddr)
}

func isBroadcastAddr(ip net.IP, network *net.IPNet) bool {
	if len(ip) == net.IPv6len && ip.To4() == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	mask := network.Mask
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}

	networkInt := binary.BigEndian.Uint32(network.IP.To4())
	maskInt := binary.BigEndian.Uint32(mask)
	broadcastInt := networkInt | ^maskInt

	ipInt := binary.BigEndian.Uint32(ip4)
	return ipInt == broadcastInt
}

func uniqueTargets(targets []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, t := range targets {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}
	return unique
}
