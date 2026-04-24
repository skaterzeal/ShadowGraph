package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shadowgraph/core/internal/db"
)

// ExportHTML profesyonel HTML rapor oluşturur (executive summary, risk matrisi, exploit, remediation, AI, SVG).
// scanID <= 0 ise en son scan kullanılır.
func ExportHTML(outputPath string, scanID int64) error {
	resolvedID, err := db.ResolveScanID(scanID)
	if err != nil {
		return fmt.Errorf("scan id çözümlenemedi: %w", err)
	}

	graphData, err := db.GetGraphData(resolvedID)
	if err != nil {
		return fmt.Errorf("veritabanı okuma hatası: %w", err)
	}

	var graph db.GraphJSON
	if err := json.Unmarshal(graphData, &graph); err != nil {
		return err
	}

	// İstatistikleri hesapla
	var targets, ports, vulns, endpoints, exploits, shields []db.NodeData
	for _, n := range graph.Nodes {
		switch n.Group {
		case "target":
			targets = append(targets, n)
		case "port":
			ports = append(ports, n)
		case "vulnerability":
			vulns = append(vulns, n)
		case "endpoint":
			endpoints = append(endpoints, n)
		case "exploit":
			exploits = append(exploits, n)
		case "shield":
			shields = append(shields, n)
		}
	}

	// Severity dağılımı
	critical, high, medium, low, unknown := 0, 0, 0, 0, 0
	type vulnDetail struct {
		CVE, Severity, Desc, CVSS, Vector string
	}
	var vulnDetails []vulnDetail
	for _, v := range vulns {
		pd := map[string]string{}
		json.Unmarshal([]byte(v.Data), &pd)
		sev := strings.ToUpper(pd["severity"])
		switch {
		case strings.Contains(sev, "CRITICAL"):
			critical++
		case strings.Contains(sev, "HIGH"):
			high++
		case strings.Contains(sev, "MEDIUM"):
			medium++
		case strings.Contains(sev, "LOW"):
			low++
		default:
			unknown++
		}
		vulnDetails = append(vulnDetails, vulnDetail{
			CVE:      pd["cve"],
			Severity: pd["severity"],
			Desc:     pd["desc"],
			CVSS:     pd["cvss"],
			Vector:   pd["vector"],
		})
	}

	// Zafiyet önceliğe göre sırala (CRITICAL → HIGH → MEDIUM → LOW)
	sevWeight := func(s string) int {
		s = strings.ToUpper(s)
		switch {
		case strings.Contains(s, "CRITICAL"):
			return 4
		case strings.Contains(s, "HIGH"):
			return 3
		case strings.Contains(s, "MEDIUM"):
			return 2
		case strings.Contains(s, "LOW"):
			return 1
		default:
			return 0
		}
	}
	sort.SliceStable(vulnDetails, func(i, j int) bool {
		return sevWeight(vulnDetails[i].Severity) > sevWeight(vulnDetails[j].Severity)
	})

	// Exploit detayları
	type exploitDetail struct {
		ID, Source, Desc, Type string
	}
	var exploitDetails []exploitDetail
	for _, e := range exploits {
		pd := map[string]string{}
		json.Unmarshal([]byte(e.Data), &pd)
		exploitDetails = append(exploitDetails, exploitDetail{
			ID:     pd["exploit_id"],
			Source: pd["source"],
			Desc:   pd["description"],
			Type:   pd["type"],
		})
	}

	// AI analiz (varsa)
	var aiSection string
	if resolvedID > 0 {
		if latest, err := db.GetLatestAnalysis(resolvedID); err == nil && latest != nil {
			aiSection = renderAISection(latest)
		}
	}

	// SVG Network Snapshot
	svgSnapshot := renderSVGSnapshot(graph)

	// Scan metadata
	scanMeta := ""
	if resolvedID > 0 {
		row := db.DB.QueryRow(`SELECT target, COALESCE(profile,''), COALESCE(started_at,''), COALESCE(finished_at,'')
			FROM scans WHERE id = ?`, resolvedID)
		var target, profile, started, finished string
		if err := row.Scan(&target, &profile, &started, &finished); err == nil {
			scanMeta = fmt.Sprintf(`<div class="meta"><b>Scan #%d</b> · Hedef: %s · Profil: %s · Başlangıç: %s · Bitiş: %s</div>`,
				resolvedID, htmlEscape(target), htmlEscape(profile), htmlEscape(started), htmlEscape(finished))
		}
	}

	// HTML template
	html := `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>ShadowGraph Security Report - Scan #` + fmt.Sprintf("%d", resolvedID) + `</title>
<style>
body{font-family:'Segoe UI',sans-serif;margin:40px;color:#1e293b;background:#f8fafc;}
h1{color:#0f172a;border-bottom:3px solid #0ea5e9;padding-bottom:10px;}
h2{color:#334155;margin-top:30px;border-bottom:1px solid #e2e8f0;padding-bottom:6px;}
.header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #e2e8f0;padding-bottom:20px;margin-bottom:30px;}
.logo{font-size:28px;font-weight:800;color:#0f172a;}
.logo span{color:#0ea5e9;}
.date{color:#64748b;font-size:14px;}
.meta{color:#475569;font-size:13px;background:#eff6ff;border-left:3px solid #0ea5e9;padding:8px 14px;margin:10px 0 20px;border-radius:3px;}
.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin:20px 0;}
.summary6{display:grid;grid-template-columns:repeat(6,1fr);gap:15px;margin:20px 0;}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1);}
.card .num{font-size:36px;font-weight:700;}
.card .label{color:#64748b;font-size:13px;margin-top:5px;}
.card.crit .num{color:#dc2626;}
.card.high .num{color:#ea580c;}
.card.med .num{color:#d97706;}
.card.safe .num{color:#16a34a;}
.card.purple .num{color:#9333ea;}
table{width:100%;border-collapse:collapse;margin:15px 0;}
th{background:#0f172a;color:#fff;padding:10px;text-align:left;font-size:13px;}
td{padding:10px;border-bottom:1px solid #e2e8f0;font-size:13px;vertical-align:top;}
tr:hover td{background:#f1f5f9;}
.sev-critical{color:#dc2626;font-weight:700;}
.sev-high{color:#ea580c;font-weight:700;}
.sev-medium{color:#d97706;font-weight:600;}
.sev-low{color:#16a34a;}
.exp-badge{background:#f3e8ff;color:#9333ea;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;}
.risk-badge{display:inline-block;padding:4px 10px;border-radius:4px;font-weight:700;font-size:13px;}
.risk-badge.critical{background:#fee2e2;color:#dc2626;border:1px solid #dc2626;}
.risk-badge.high{background:#ffedd5;color:#ea580c;border:1px solid #ea580c;}
.risk-badge.medium{background:#fef3c7;color:#d97706;border:1px solid #d97706;}
.risk-badge.low{background:#dcfce7;color:#16a34a;border:1px solid #16a34a;}
.ai-box{background:#fff;border:1px solid #e2e8f0;border-left:4px solid #6366f1;border-radius:6px;padding:18px;margin:15px 0;}
.ai-box .ai-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.ai-box h3{margin:0;font-size:18px;color:#4338ca;}
.ai-box .ai-summary{color:#334155;line-height:1.5;margin:8px 0;}
.ai-box .ai-meta{color:#64748b;font-size:12px;}
.recs{margin:10px 0;padding-left:20px;}
.recs li{margin:5px 0;}
.svg-wrap{background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:10px;margin:15px 0;text-align:center;overflow:auto;}
.svg-wrap svg{max-width:100%;height:auto;}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:12px;text-align:center;}
.cvss{font-family:monospace;font-size:11px;color:#64748b;background:#f1f5f9;padding:2px 6px;border-radius:3px;}
@media print{
  body{margin:10px;background:#fff;}
  .header{page-break-after:avoid;}
  h2{page-break-after:avoid;}
  table{page-break-inside:auto;}
  tr{page-break-inside:avoid;page-break-after:auto;}
  .ai-box,.svg-wrap{page-break-inside:avoid;}
  .footer{position:fixed;bottom:0;width:100%;}
}
</style>
</head>
<body>
<div class="header">
<div class="logo"><span>Shadow</span>Graph Security Report</div>
<div class="date">` + time.Now().Format("02.01.2006 15:04 MST") + `</div>
</div>
` + scanMeta + `
<h2>Executive Summary</h2>
<div class="summary6">
<div class="card"><div class="num">` + fmt.Sprintf("%d", len(targets)) + `</div><div class="label">Taranan Hedef</div></div>
<div class="card safe"><div class="num">` + fmt.Sprintf("%d", len(ports)) + `</div><div class="label">Açık Port</div></div>
<div class="card"><div class="num">` + fmt.Sprintf("%d", len(endpoints)) + `</div><div class="label">Tespit Edilen Servis</div></div>
<div class="card crit"><div class="num">` + fmt.Sprintf("%d", len(vulns)) + `</div><div class="label">Zafiyet (CVE)</div></div>
<div class="card purple"><div class="num">` + fmt.Sprintf("%d", len(exploits)) + `</div><div class="label">Bilinen Exploit</div></div>
<div class="card high"><div class="num">` + fmt.Sprintf("%d", critical) + `</div><div class="label">Kritik Zafiyet</div></div>
</div>

<h2>Risk Matrisi</h2>
<div class="summary">
<div class="card crit"><div class="num">` + fmt.Sprintf("%d", critical) + `</div><div class="label">CRITICAL</div></div>
<div class="card high"><div class="num">` + fmt.Sprintf("%d", high) + `</div><div class="label">HIGH</div></div>
<div class="card med"><div class="num">` + fmt.Sprintf("%d", medium) + `</div><div class="label">MEDIUM</div></div>
</div>
` + aiSection + `
<h2>Ağ Topolojisi (Snapshot)</h2>
<div class="svg-wrap">` + svgSnapshot + `</div>

<h2>Hedef Bilgileri</h2>
<table><tr><th>Hostname</th><th>IP Address</th><th>OS</th></tr>`

	for _, t := range targets {
		pd := map[string]string{}
		json.Unmarshal([]byte(t.Data), &pd)
		html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
			htmlEscape(pd["hostname"]), htmlEscape(pd["ip_address"]), htmlEscape(pd["os_version"]))
	}

	html += `</table>

<h2>Zafiyet Detayları &amp; Remediation</h2>
<table><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Description</th><th>Remediation</th></tr>`

	for _, v := range vulnDetails {
		sevClass := "sev-low"
		remediation := "Yazılımı en son sürüme güncelleyin."
		sev := strings.ToUpper(v.Severity)
		if strings.Contains(sev, "CRITICAL") {
			sevClass = "sev-critical"
			remediation = "ACİL: Derhal yamalayın veya servisi devre dışı bırakın!"
		} else if strings.Contains(sev, "HIGH") {
			sevClass = "sev-high"
			remediation = "ÖNCELİKLİ: 7 gün içinde yamalayın."
		} else if strings.Contains(sev, "MEDIUM") {
			sevClass = "sev-medium"
			remediation = "PLANLI: 30 gün içinde yamalayın."
		}

		desc := v.Desc
		if len(desc) > 240 {
			desc = desc[:240] + "..."
		}
		cvssCell := ""
		if v.CVSS != "" {
			cvssCell = `<span class="cvss">` + htmlEscape(v.CVSS) + `</span>`
		}
		html += fmt.Sprintf("<tr><td><b>%s</b></td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			htmlEscape(v.CVE), sevClass, htmlEscape(v.Severity), cvssCell, htmlEscape(desc), remediation)
	}

	html += `</table>`

	// Exploit tablosu
	if len(exploitDetails) > 0 {
		html += `
<h2>Bilinen Exploit'ler</h2>
<table><tr><th>Exploit ID</th><th>Kaynak</th><th>Tür</th><th>Açıklama</th></tr>`

		for _, e := range exploitDetails {
			html += fmt.Sprintf("<tr><td><b>%s</b></td><td><span class=\"exp-badge\">%s</span></td><td>%s</td><td>%s</td></tr>",
				htmlEscape(e.ID), htmlEscape(e.Source), htmlEscape(e.Type), htmlEscape(e.Desc))
		}
		html += `</table>`
	}

	// CDN/WAF Shield tablosu
	if len(shields) > 0 {
		html += `
<h2>CDN/WAF Korumalı Servisler (False Positive Önleme)</h2>
<p style="color:#64748b;font-size:13px;">Aşağıdaki servisler CDN, WAF veya reverse proxy arkasında tespit edilmiştir.
Bu servislerin banner bilgileri gerçek uygulamayı yansıtmadığından CVE sorgusu atlanmıştır.</p>
<table><tr><th>Servis</th><th>Tür</th><th>Not</th></tr>`

		for _, s := range shields {
			pd := map[string]string{}
			json.Unmarshal([]byte(s.Data), &pd)
			html += fmt.Sprintf("<tr><td><b>%s</b></td><td><span style=\"background:#fef3c7;color:#d97706;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;\">%s</span></td><td>%s</td></tr>",
				htmlEscape(s.Label), htmlEscape(pd["shield_type"]), htmlEscape(pd["note"]))
		}
		html += `</table>`
	}

	html += `
<div class="footer">Generated by ShadowGraph v0.2.0 | Open Source | ` + time.Now().Format("2006") + `</div>
</body></html>`

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("dosya oluşturulamadı: %w", err)
	}
	defer file.Close()
	file.WriteString(html)

	fmt.Printf("[\033[32m✔\033[0m] HTML rapor oluşturuldu: %s\n", outputPath)
	return nil
}

// renderAISection DB'deki analysesten rapora HTML bloğu üretir.
func renderAISection(a *db.AnalysisInfo) string {
	if a == nil {
		return ""
	}
	lvlClass := "medium"
	switch strings.ToUpper(a.RiskLevel) {
	case "CRITICAL":
		lvlClass = "critical"
	case "HIGH":
		lvlClass = "high"
	case "LOW":
		lvlClass = "low"
	}

	// Recommendations'ı json_data'dan oku
	var parsed struct {
		Recommendations []string `json:"recommendations"`
		ChainedAttacks  []struct {
			Name        string  `json:"name"`
			Description string  `json:"description"`
			RiskScore   float64 `json:"risk_score"`
			Scenario    string  `json:"scenario"`
		} `json:"chained_attacks"`
	}
	_ = json.Unmarshal([]byte(a.JSONData), &parsed)

	var recs string
	if len(parsed.Recommendations) > 0 {
		recs = "<h3 style=\"margin:12px 0 4px;font-size:14px;color:#0f172a;\">Öneriler</h3><ul class=\"recs\">"
		for _, r := range parsed.Recommendations {
			recs += "<li>" + htmlEscape(r) + "</li>"
		}
		recs += "</ul>"
	}

	var chains string
	if len(parsed.ChainedAttacks) > 0 {
		chains = "<h3 style=\"margin:12px 0 4px;font-size:14px;color:#0f172a;\">Zincirleme Saldırı Senaryoları</h3><ul class=\"recs\">"
		for _, c := range parsed.ChainedAttacks {
			chains += fmt.Sprintf("<li><b>%s</b> (Risk: %.1f)<br/><span style=\"color:#64748b;font-size:12px;\">%s</span><br/><i style=\"font-size:12px;color:#475569;\">%s</i></li>",
				htmlEscape(c.Name), c.RiskScore, htmlEscape(c.Description), htmlEscape(c.Scenario))
		}
		chains += "</ul>"
	}

	return fmt.Sprintf(`<h2>AI Attack Path Analysis</h2>
<div class="ai-box">
  <div class="ai-head">
    <h3>%s</h3>
    <span class="risk-badge %s">%s · %.1f / 10</span>
  </div>
  <div class="ai-meta">Provider: %s · Analiz: %s · Toplam path: %d · Kritik: %d · Yüksek: %d</div>
  <div class="ai-summary">%s</div>
  %s
  %s
</div>`,
		"Saldırı Yüzeyi Analizi",
		lvlClass,
		htmlEscape(a.RiskLevel),
		a.OverallRisk,
		htmlEscape(a.Provider),
		htmlEscape(a.CreatedAt),
		a.TotalPaths, a.CriticalPaths, a.HighRiskPaths,
		htmlEscape(a.Summary),
		recs, chains,
	)
}

// renderSVGSnapshot grafikten basit bir SVG görsel üretir.
// Force-directed yerine radyal bir layout: target'lar merkez, port/endpoint/vuln çevrede.
func renderSVGSnapshot(graph db.GraphJSON) string {
	if len(graph.Nodes) == 0 {
		return `<span style="color:#64748b">Bu scan için gösterilecek graf verisi yok.</span>`
	}

	const W, H = 900, 500
	cx, cy := float64(W/2), float64(H/2)

	// Grup bazında renk
	colors := map[string]string{
		"target":        "#0ea5e9",
		"port":          "#10b981",
		"endpoint":      "#f59e0b",
		"vulnerability": "#ef4444",
		"exploit":       "#a855f7",
		"shield":        "#eab308",
	}

	// Target düğümlerini merkezde yay üzerinde yerleştir
	var targets []db.NodeData
	for _, n := range graph.Nodes {
		if n.Group == "target" {
			targets = append(targets, n)
		}
	}

	// Node pozisyonlarını hesapla
	pos := make(map[int64][2]float64)

	// 1. Target'ları merkezde dağıt
	if len(targets) == 1 {
		pos[targets[0].ID] = [2]float64{cx, cy}
	} else {
		for i, t := range targets {
			angle := 2 * math.Pi * float64(i) / float64(len(targets))
			r := 80.0
			pos[t.ID] = [2]float64{cx + r*math.Cos(angle), cy + r*math.Sin(angle)}
		}
	}

	// 2. Port/endpoint/vuln/exploit/shield — her target çocuklarını kendi etrafına yerleştir
	// Basit: BFS tarzı; parent bulunmayanları sayfa kenarına yay
	// Önce adjacency (from → to)
	children := make(map[int64][]int64)
	for _, e := range graph.Edges {
		children[e.From] = append(children[e.From], e.To)
	}

	placed := make(map[int64]bool)
	for _, t := range targets {
		placed[t.ID] = true
	}

	// BFS katmanları
	layer := 1
	current := make([]int64, 0, len(targets))
	for _, t := range targets {
		current = append(current, t.ID)
	}
	for len(current) > 0 && layer < 5 {
		next := []int64{}
		for _, pid := range current {
			kids := children[pid]
			if len(kids) == 0 {
				continue
			}
			ppos, ok := pos[pid]
			if !ok {
				continue
			}
			r := 60.0 + 40.0*float64(layer)
			for i, k := range kids {
				if placed[k] {
					continue
				}
				angle := 2 * math.Pi * float64(i) / float64(len(kids))
				// Layer'a göre ofset açısı
				angle += float64(layer) * 0.3
				x := ppos[0] + r*math.Cos(angle)
				y := ppos[1] + r*math.Sin(angle)
				// Canvas içinde kalsın
				if x < 10 {
					x = 10
				}
				if x > float64(W-10) {
					x = float64(W - 10)
				}
				if y < 10 {
					y = 10
				}
				if y > float64(H-10) {
					y = float64(H - 10)
				}
				pos[k] = [2]float64{x, y}
				placed[k] = true
				next = append(next, k)
			}
		}
		current = next
		layer++
	}

	// Yerleştirilmeyen düğümleri dışta rastgele sıraya
	var unplaced []db.NodeData
	for _, n := range graph.Nodes {
		if !placed[n.ID] {
			unplaced = append(unplaced, n)
		}
	}
	for i, n := range unplaced {
		angle := 2 * math.Pi * float64(i) / float64(len(unplaced)+1)
		r := 230.0
		pos[n.ID] = [2]float64{cx + r*math.Cos(angle), cy + r*math.Sin(angle)}
	}

	// SVG oluştur
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" style="background:#f8fafc;border-radius:6px;">`, W, H))

	// Edges
	for _, e := range graph.Edges {
		fromPos, ok1 := pos[e.From]
		toPos, ok2 := pos[e.To]
		if !ok1 || !ok2 {
			continue
		}
		sb.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#cbd5e1" stroke-width="1"/>`,
			fromPos[0], fromPos[1], toPos[0], toPos[1]))
	}

	// Nodes
	for _, n := range graph.Nodes {
		p, ok := pos[n.ID]
		if !ok {
			continue
		}
		col, ok := colors[n.Group]
		if !ok {
			col = "#64748b"
		}
		r := 8.0
		if n.Group == "target" {
			r = 14.0
		} else if n.Group == "vulnerability" {
			r = 10.0
		}
		sb.WriteString(fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" stroke="#ffffff" stroke-width="1.5"/>`,
			p[0], p[1], r, col))

		// Target'lara label
		if n.Group == "target" {
			label := n.Label
			if strings.Contains(label, "\n") {
				label = strings.SplitN(label, "\n", 2)[0]
			}
			if len(label) > 30 {
				label = label[:30] + "..."
			}
			sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" font-family="Segoe UI, sans-serif" font-size="11" fill="#0f172a" text-anchor="middle">%s</text>`,
				p[0], p[1]+r+12, htmlEscape(label)))
		}
	}

	// Legend
	legendY := H - 20
	legendX := 20.0
	groups := []struct {
		Name, Label string
	}{
		{"target", "Hedef"},
		{"port", "Port"},
		{"endpoint", "Servis"},
		{"vulnerability", "CVE"},
		{"exploit", "Exploit"},
		{"shield", "CDN/WAF"},
	}
	for _, g := range groups {
		sb.WriteString(fmt.Sprintf(`<circle cx="%.1f" cy="%d" r="5" fill="%s"/>`, legendX, legendY, colors[g.Name]))
		sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%d" font-family="Segoe UI" font-size="11" fill="#475569">%s</text>`, legendX+10, legendY+4, g.Label))
		legendX += 80
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}

// htmlEscape basit HTML escape
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
