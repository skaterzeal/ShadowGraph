package scanner

import (
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"net"
)

// GetOSFromTTL ICMP Kernel analizine dayanarak hedefin işletim sistemini tespit eder
// ICMP başarısız olursa TCP handshake'ten TTL okumayı dener (fallback)
func GetOSFromTTL(target string) string {
	ttl := getICMPTTL(target)
	if ttl > 0 {
		return classifyTTL(ttl)
	}

	// Fallback: TCP üzerinden TTL okuma (ICMP bloklandığında)
	ttl = getTCPTTL(target)
	if ttl > 0 {
		return classifyTTL(ttl) + " (TCP Fallback)"
	}

	return "Bilinemiyor (Ping & TCP Bloklu)"
}

func getICMPTTL(target string) int {
	var out []byte
	var err error

	isIPv6 := strings.Contains(target, ":")

	if runtime.GOOS == "windows" {
		if isIPv6 {
			out, err = exec.Command("ping", "-6", "-n", "1", "-w", "2000", target).CombinedOutput()
		} else {
			out, err = exec.Command("ping", "-n", "1", "-w", "2000", target).CombinedOutput()
		}
	} else {
		if isIPv6 {
			out, err = exec.Command("ping6", "-c", "1", "-W", "2", target).CombinedOutput()
		} else {
			out, err = exec.Command("ping", "-c", "1", "-W", "2", target).CombinedOutput()
		}
	}

	if err != nil {
		return 0
	}

	re := regexp.MustCompile(`[Tt][Tt][Ll]=(\d+)`)
	matches := re.FindSubmatch(out)
	if len(matches) < 2 {
		return 0
	}

	ttlVal, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		return 0
	}
	return ttlVal
}

// getTCPTTL açık bir porta TCP bağlantısı kurarak SYN-ACK'ten TTL okumaya çalışır
func getTCPTTL(target string) int {
	commonPorts := []string{"80", "443", "22", "21", "8080"}

	for _, port := range commonPorts {
		address := net.JoinHostPort(target, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// TCP bağlantısı kurulabildi — OS bilgisini traceroute benzeri bir yöntemle oku
		if runtime.GOOS == "windows" {
			out, err := exec.Command("powershell", "-Command",
				"(Test-NetConnection -ComputerName "+target+" -Port "+port+" -InformationLevel Detailed).PingReplyDetails.Options.Ttl").CombinedOutput()
			if err == nil {
				cleaned := strings.TrimSpace(string(out))
				ttl, err := strconv.Atoi(cleaned)
				if err == nil && ttl > 0 {
					return ttl
				}
			}
		}

		// Linux fallback: hping3 veya traceroute denemesi
		if runtime.GOOS != "windows" {
			out, err := exec.Command("bash", "-c",
				"nmap -sT -p "+port+" --ttl 0 "+target+" 2>/dev/null | grep -oP 'ttl\\s+(\\d+)' | head -1 | grep -oP '\\d+'").CombinedOutput()
			if err == nil {
				cleaned := strings.TrimSpace(string(out))
				ttl, err := strconv.Atoi(cleaned)
				if err == nil && ttl > 0 {
					return ttl
				}
			}
		}

		// Bağlantı kurulabildiğine göre en azından canlı bir host var
		return 0
	}
	return 0
}

// classifyTTL TTL değerine göre OS ailesi döndürür
func classifyTTL(ttlVal int) string {
	if ttlVal > 0 && ttlVal <= 64 {
		return "Linux / Unix-like / MacOS"
	} else if ttlVal > 64 && ttlVal <= 128 {
		return "Windows Ailesi"
	} else if ttlVal > 128 && ttlVal <= 255 {
		return "Ağ Cihazı (Router/Switch/IoT) / Solaris"
	}
	return "Bilinemiyor"
}
