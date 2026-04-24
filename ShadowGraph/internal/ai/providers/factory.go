package providers

import (
	"context"
	"fmt"
	"strings"
)

// NewProvider yapılandırmaya göre Provider döner.
// Bilinmeyen sağlayıcılar için rule-based'a düşer.
func NewProvider(name string, cfg Config) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "rule-based", "rules", "default":
		return NewRuleBased(), nil
	case "ollama":
		return NewOllama(cfg.Ollama), nil
	default:
		return nil, fmt.Errorf("bilinmeyen AI provider: %q (desteklenen: rule-based, ollama)", name)
	}
}

// NewProviderWithFallback istenen provider'ı dener; healthy değilse veya oluşturulamazsa
// rule-based'a fallback yapar. Caller'a hangisinin kullanıldığını döner.
func NewProviderWithFallback(ctx context.Context, name string, cfg Config) (Provider, string, error) {
	p, err := NewProvider(name, cfg)
	if err != nil {
		// Bilinmeyen provider adı: rule-based
		return NewRuleBased(), "rule-based", nil
	}
	if err := p.Healthy(ctx); err != nil {
		// Ollama ulaşılamıyor: rule-based'a düş
		return NewRuleBased(), "rule-based", fmt.Errorf("%s erişilemez, rule-based'a fallback: %w", p.Name(), err)
	}
	return p, p.Name(), nil
}
