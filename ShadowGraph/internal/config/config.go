package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config uygulama genelinde kullanılan yapılandırma
type Config struct {
	NVDAPIKey      string `yaml:"nvd_api_key"`
	DefaultProfile string `yaml:"default_profile"`
	Proxy          struct {
		HTTP  string `yaml:"http"`
		HTTPS string `yaml:"https"`
	} `yaml:"proxy"`
	UI struct {
		Port int `yaml:"port"`
	} `yaml:"ui"`
	Scan struct {
		Workers   int `yaml:"workers"`
		RateLimit int `yaml:"rate_limit_ms"`
	} `yaml:"scan"`
	Plugins struct {
		Dir     string `yaml:"dir"`
		Enabled bool   `yaml:"enabled"`
	} `yaml:"plugins"`
	Logging struct {
		Level   string `yaml:"level"`
		File    string `yaml:"file"`
		JSON    bool   `yaml:"json"`
		MaxSize int    `yaml:"max_size_mb"`
	} `yaml:"logging"`
	AI struct {
		Provider string `yaml:"provider"` // "rule-based", "ollama"
		Ollama   struct {
			Host        string  `yaml:"host"`
			Model       string  `yaml:"model"`
			Temperature float64 `yaml:"temperature"`
			TimeoutSec  int     `yaml:"timeout_sec"`
		} `yaml:"ollama"`
	} `yaml:"ai"`
	Safety struct {
		MaxRetries         int  `yaml:"max_retries"`
		ConfirmLargeSubnet bool `yaml:"confirm_large_subnet"` // /16 ve üstü için onay iste
	} `yaml:"safety"`
}

var AppConfig Config

// LoadConfig YAML config dosyasını okur, ortam değişkenleriyle override eder
func LoadConfig() error {
	// Varsayılan değerler
	AppConfig.UI.Port = 8080
	AppConfig.DefaultProfile = "standard"
	AppConfig.Logging.Level = "INFO"
	AppConfig.Logging.MaxSize = 10
	AppConfig.Scan.Workers = 100
	AppConfig.Plugins.Dir = "plugins"
	AppConfig.Plugins.Enabled = true
	AppConfig.AI.Provider = "rule-based"
	AppConfig.AI.Ollama.Host = "http://127.0.0.1:11434"
	AppConfig.AI.Ollama.Model = "llama3.1:8b"
	AppConfig.AI.Ollama.Temperature = 0.2
	AppConfig.AI.Ollama.TimeoutSec = 120
	AppConfig.Safety.MaxRetries = 2
	AppConfig.Safety.ConfirmLargeSubnet = true

	// Config dosyası aranacak konumlar
	paths := []string{
		"config.yaml",
		filepath.Join(homeDir(), ".shadowgraph", "config.yaml"),
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			if err := yaml.Unmarshal(data, &AppConfig); err != nil {
				return fmt.Errorf("config parse hatası (%s): %v", p, err)
			}
			fmt.Printf("[\033[36m*\033[0m] Config yüklendi: %s\n", p)
			break
		}
	}

	// Ortam değişkenleri override
	if v := os.Getenv("SHADOWGRAPH_NVD_KEY"); v != "" {
		AppConfig.NVDAPIKey = v
	}
	if v := os.Getenv("SHADOWGRAPH_PROXY"); v != "" {
		AppConfig.Proxy.HTTP = v
		AppConfig.Proxy.HTTPS = v
	}
	if v := os.Getenv("OLLAMA_HOST"); v != "" {
		AppConfig.AI.Ollama.Host = v
	}
	if v := os.Getenv("SHADOWGRAPH_AI_PROVIDER"); v != "" {
		AppConfig.AI.Provider = v
	}

	return nil
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}
