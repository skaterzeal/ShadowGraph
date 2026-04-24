package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Plugin YAML tabanlı script tanımı
type Plugin struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Author      string   `yaml:"author"`
	Version     string   `yaml:"version"`
	Category    string   `yaml:"category"` // recon, vuln, exploit, aux, report
	Triggers    []string `yaml:"triggers"` // Hangi portlar/servisler için çalışır
	Commands    []Step   `yaml:"commands"` // Çalıştırılacak komutlar
	Timeout     int      `yaml:"timeout"`  // Saniye cinsinden zaman aşımı
}

// Step tek bir komut adımı
type Step struct {
	Name    string `yaml:"name"`
	Run     string `yaml:"run"`     // Shell komutu
	Args    string `yaml:"args"`    // Ek parametreler ({target}, {port}, {service} placeholder)
	OnFail  string `yaml:"on_fail"` // "continue" veya "abort"
}

// PluginResult script çalıştırma sonucu
type PluginResult struct {
	PluginName string
	Success    bool
	Output     string
	Duration   time.Duration
	Error      string
}

// PluginManager script'leri yönetir
type PluginManager struct {
	PluginsDir string
	Plugins    []Plugin
}

// NewPluginManager yeni plugin yöneticisi oluşturur
func NewPluginManager(pluginsDir string) *PluginManager {
	return &PluginManager{
		PluginsDir: pluginsDir,
	}
}

// LoadPlugins dizindeki tüm YAML plugin tanımlarını yükler
func (pm *PluginManager) LoadPlugins() error {
	if _, err := os.Stat(pm.PluginsDir); os.IsNotExist(err) {
		return nil // Plugin dizini yoksa sorun değil
	}

	entries, err := os.ReadDir(pm.PluginsDir)
	if err != nil {
		return fmt.Errorf("plugin dizini okunamadı: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}

		pluginPath := filepath.Join(pm.PluginsDir, entry.Name())
		data, err := os.ReadFile(pluginPath)
		if err != nil {
			fmt.Printf("[\033[33m!\033[0m] Plugin okunamadı: %s — %v\n", entry.Name(), err)
			continue
		}

		var p Plugin
		if err := yaml.Unmarshal(data, &p); err != nil {
			fmt.Printf("[\033[33m!\033[0m] Plugin parse hatası: %s — %v\n", entry.Name(), err)
			continue
		}

		pm.Plugins = append(pm.Plugins, p)
	}

	return nil
}

// GetMatchingPlugins belirli bir servis/port için uygun plugin'leri döner
func (pm *PluginManager) GetMatchingPlugins(service, port string) []Plugin {
	var matches []Plugin
	for _, p := range pm.Plugins {
		for _, trigger := range p.Triggers {
			trigger = strings.ToLower(trigger)
			if trigger == "*" ||
				trigger == strings.ToLower(service) ||
				trigger == strings.ToLower(port) ||
				strings.Contains(strings.ToLower(service), trigger) {
				matches = append(matches, p)
				break
			}
		}
	}
	return matches
}

// RunPlugin tek bir plugin'i çalıştırır
func (pm *PluginManager) RunPlugin(p Plugin, target, port, service string) *PluginResult {
	result := &PluginResult{PluginName: p.Name}
	start := time.Now()

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 // Varsayılan 30 saniye
	}

	var output strings.Builder

	for _, step := range p.Commands {
		// Placeholder'ları değiştir
		cmd := expandPlaceholders(step.Run+" "+step.Args, target, port, service)
		cmd = strings.TrimSpace(cmd)

		fmt.Printf("    [\033[36m⚙\033[0m] Plugin '%s' → %s: %s\n", p.Name, step.Name, cmd)

		// Komutu çalıştır
		ctx_cmd := exec.Command("sh", "-c", cmd)
		ctx_cmd.Env = append(os.Environ(),
			"SG_TARGET="+target,
			"SG_PORT="+port,
			"SG_SERVICE="+service,
		)

		out, err := ctx_cmd.CombinedOutput()
		output.Write(out)

		if err != nil {
			if step.OnFail == "continue" {
				output.WriteString(fmt.Sprintf("\n[WARN] %s başarısız, devam ediliyor: %v\n", step.Name, err))
				continue
			}
			result.Duration = time.Since(start)
			result.Error = fmt.Sprintf("Adım '%s' başarısız: %v", step.Name, err)
			result.Output = output.String()
			return result
		}
	}

	result.Success = true
	result.Output = output.String()
	result.Duration = time.Since(start)
	return result
}

// RunMatchingPlugins hedef için eşleşen tüm plugin'leri çalıştırır
func (pm *PluginManager) RunMatchingPlugins(target, port, service string) []*PluginResult {
	matching := pm.GetMatchingPlugins(service, port)
	if len(matching) == 0 {
		return nil
	}

	fmt.Printf("  [\033[35m⚙\033[0m] %d plugin eşleşti (port: %s, servis: %s)\n", len(matching), port, service)

	var results []*PluginResult
	for _, p := range matching {
		result := pm.RunPlugin(p, target, port, service)
		results = append(results, result)
	}
	return results
}

// ListPlugins yüklü plugin'leri listeler
func (pm *PluginManager) ListPlugins() {
	if len(pm.Plugins) == 0 {
		fmt.Println("[\033[33m!\033[0m] Yüklü plugin bulunamadı.")
		fmt.Printf("    Plugin dizini: %s\n", pm.PluginsDir)
		fmt.Println("    Örnek plugin oluşturmak için: shadowgraph plugin --init")
		return
	}

	fmt.Printf("\n  %-25s %-12s %-45s %s\n", "İSİM", "KATEGORİ", "AÇIKLAMA", "TETİKLEYİCİLER")
	fmt.Println("  " + strings.Repeat("─", 110))
	for _, p := range pm.Plugins {
		triggers := strings.Join(p.Triggers, ", ")
		fmt.Printf("  %-25s %-12s %-45s %s\n", p.Name, p.Category, p.Description, triggers)
	}
	fmt.Println()
}

// InitSamplePlugin örnek bir plugin dosyası oluşturur
func InitSamplePlugin(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	sample := `# ShadowGraph Plugin Örneği
name: http-headers-check
description: HTTP güvenlik header'larını kontrol eder
author: ShadowGraph Community
version: "1.0"
category: recon
triggers:
  - http
  - nginx
  - apache
  - "80"
  - "443"
  - "8080"
timeout: 15
commands:
  - name: "Security Headers Check"
    run: "curl -sI -o /dev/null -w '%{http_code}' --max-time 5 http://{target}:{port}"
    on_fail: continue
  - name: "HSTS Header"
    run: "curl -sI --max-time 5 http://{target}:{port} | grep -i strict-transport"
    on_fail: continue
  - name: "X-Frame-Options"
    run: "curl -sI --max-time 5 http://{target}:{port} | grep -i x-frame-options"
    on_fail: continue
  - name: "Content-Security-Policy"
    run: "curl -sI --max-time 5 http://{target}:{port} | grep -i content-security-policy"
    on_fail: continue
`
	path := filepath.Join(dir, "http-headers-check.yaml")
	if err := os.WriteFile(path, []byte(sample), 0644); err != nil {
		return err
	}

	fmt.Printf("[\033[32m✔\033[0m] Örnek plugin oluşturuldu: %s\n", path)
	return nil
}

func expandPlaceholders(cmd, target, port, service string) string {
	r := strings.NewReplacer(
		"{target}", target,
		"{port}", port,
		"{service}", service,
		"$SG_TARGET", target,
		"$SG_PORT", port,
		"$SG_SERVICE", service,
	)
	return r.Replace(cmd)
}
