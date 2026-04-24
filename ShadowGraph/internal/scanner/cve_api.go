package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shadowgraph/core/internal/config"
)

type CVEResult struct {
	ID          string
	Description string
	Severity    string
}

// NVD rate limit (https://nvd.nist.gov/developers/start-here):
//   - API anahtarı yok: 5 istek / 30 saniye → güvenli aralık ~6.5s
//   - API anahtarı var: 50 istek / 30 saniye → güvenli aralık ~0.6s
// Küresel bir limiter, paralel taramalarda da limite uyum sağlar.
var (
	nvdLimiter    = newNVDLimiter()
	nvdClient     = &http.Client{Timeout: 20 * time.Second}
	nvdMaxRetries = 3
)

type tokenLimiter struct {
	mu       sync.Mutex
	nextOK   time.Time
	interval time.Duration
}

func newNVDLimiter() *tokenLimiter {
	return &tokenLimiter{interval: nvdInterval()}
}

// nvdInterval yapılandırmaya (API key varlığı) göre minimum istekler arası bekleme süresi döner.
func nvdInterval() time.Duration {
	if strings.TrimSpace(config.AppConfig.NVDAPIKey) != "" {
		return 700 * time.Millisecond // ~50 req / 30s; kenar payıyla
	}
	return 6500 * time.Millisecond // ~5 req / 30s; kenar payıyla
}

// Wait bir sonraki isteğe kadar bekler ve rezervasyon zamanını ileriye kaydırır.
func (l *tokenLimiter) Wait() {
	l.mu.Lock()
	// Interval'i runtime'da config değişmişse güncelle
	l.interval = nvdInterval()
	now := time.Now()
	if now.Before(l.nextOK) {
		wait := l.nextOK.Sub(now)
		l.mu.Unlock()
		time.Sleep(wait)
		l.mu.Lock()
		now = time.Now()
	}
	l.nextOK = now.Add(l.interval)
	l.mu.Unlock()
}

// QueryNVD NIST'in canlı REST JSON API'sini kullanarak tespit edilen servis yazılımlarının açıklarını arar.
// Özellikler:
//   - Config'te NVD_API_KEY varsa Authorization header olarak gönderir.
//   - Küresel rate limiter ile NVD'nin "istek sayısı / 30 sn" limitine uyar.
//   - 429/503 dönerse exponential backoff ile yeniden dener (en fazla nvdMaxRetries).
func QueryNVD(keyword string) ([]CVEResult, error) {
	cleanKeyword := strings.ReplaceAll(keyword, "Server:", "")
	cleanKeyword = strings.ReplaceAll(cleanKeyword, "PoweredBy:", "")
	cleanKeyword = strings.Split(cleanKeyword, " | ")[0]
	cleanKeyword = strings.ReplaceAll(strings.TrimSpace(cleanKeyword), "/", " ")

	if len(cleanKeyword) < 3 {
		return nil, fmt.Errorf("servis imzası (banner) sorgu atılamayacak kadar kısa")
	}

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=3",
		url.QueryEscape(cleanKeyword))

	fmt.Printf("    [\033[33m~\033[0m] NIST NVD sorgulanıyor: '%s'\n", cleanKeyword)

	var lastErr error
	backoff := 5 * time.Second
	for attempt := 1; attempt <= nvdMaxRetries; attempt++ {
		// Küresel rate limiter: tüm QueryNVD çağrıları aynı kuyruğu paylaşır
		nvdLimiter.Wait()

		req, err := http.NewRequest(http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, err
		}
		if k := strings.TrimSpace(config.AppConfig.NVDAPIKey); k != "" {
			req.Header.Set("apiKey", k)
		}
		req.Header.Set("User-Agent", "ShadowGraph/0.2")

		resp, err := nvdClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			return parseNVDResponse(body)
		case http.StatusNotFound:
			resp.Body.Close()
			return nil, fmt.Errorf("sorgulanan yazılım datası geçersiz (HTTP 404)")
		case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
			// Rate limited — backoff + retry
			resp.Body.Close()
			lastErr = fmt.Errorf("NVD rate limit (%d) — denemem=%d/%d", resp.StatusCode, attempt, nvdMaxRetries)
			if attempt < nvdMaxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return nil, lastErr
		default:
			resp.Body.Close()
			return nil, fmt.Errorf("NVD beklenmeyen HTTP %d", resp.StatusCode)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("NVD sorgusu %d denemenin sonunda başarısız oldu", nvdMaxRetries)
	}
	return nil, lastErr
}

func parseNVDResponse(body []byte) ([]CVEResult, error) {
	type NISTResponse struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV30 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	var apiData NISTResponse
	if err := json.Unmarshal(body, &apiData); err != nil {
		return nil, err
	}

	var results []CVEResult
	for _, v := range apiData.Vulnerabilities {
		c := v.CVE
		desc := "Tehdit Tanımı Eksik"
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		sev := "Risk Bilinmiyor"
		if len(c.Metrics.CvssMetricV31) > 0 {
			sev = c.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(c.Metrics.CvssMetricV30) > 0 {
			sev = c.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
		}

		results = append(results, CVEResult{
			ID:          c.ID,
			Description: desc,
			Severity:    sev,
		})
	}

	return results, nil
}
