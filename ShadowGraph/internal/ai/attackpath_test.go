package ai

import "testing"

func TestClassifyRisk_Boundaries(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, "LOW"},
		{3.99, "LOW"},
		{4, "MEDIUM"},
		{6.99, "MEDIUM"},
		{7, "HIGH"},
		{8.99, "HIGH"},
		{9, "CRITICAL"},
		{10, "CRITICAL"},
	}
	for _, tc := range tests {
		if got := classifyRisk(tc.score); got != tc.want {
			t.Errorf("classifyRisk(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestCalculatePathRisk_CriticalVuln(t *testing.T) {
	p := &AttackPath{
		Steps: []PathStep{
			{NodeType: "target", Label: "10.0.0.1"},
			{NodeType: "port", Label: "Port 22"},
			{NodeType: "vulnerability", Data: map[string]string{"severity": "CRITICAL"}},
		},
	}
	calculatePathRisk(p)
	if p.Impact != "CRITICAL" {
		t.Errorf("impact: %s", p.Impact)
	}
	if p.RiskScore <= 9 {
		t.Errorf("kritik zafiyette skor 9+ bekleniyordu: %f", p.RiskScore)
	}
}

func TestCalculatePathRisk_LowVuln(t *testing.T) {
	p := &AttackPath{
		Steps: []PathStep{
			{NodeType: "target", Label: "10.0.0.1"},
			{NodeType: "vulnerability", Data: map[string]string{"severity": "LOW"}},
		},
	}
	calculatePathRisk(p)
	if p.Impact != "LOW" {
		t.Errorf("impact: %s", p.Impact)
	}
	if p.RiskScore > 5 {
		t.Errorf("low vuln için düşük skor bekleniyordu: %f", p.RiskScore)
	}
}

func TestUniqueStrings(t *testing.T) {
	in := []string{"a", "", "a", "b", "c", "b"}
	got := uniqueStrings(in)
	if len(got) != 3 {
		t.Errorf("len: %d, want 3, got=%v", len(got), got)
	}
}

func TestBuildSurfaceSummary_EmptyPaths(t *testing.T) {
	s := &AttackSurface{TotalPaths: 0}
	summary := buildSurfaceSummary(s)
	if summary == "" {
		t.Error("boş surface için özet üretilmedi")
	}
}

func TestBuildSurfaceSummary_Content(t *testing.T) {
	s := &AttackSurface{
		TotalPaths:       5,
		CriticalPaths:    1,
		HighRiskPaths:    2,
		OverallRiskScore: 8.3,
		RiskLevel:        "HIGH",
		Recommendations:  []string{"Patch CVE-X"},
	}
	summary := buildSurfaceSummary(s)
	if summary == "" {
		t.Error("özet üretilmedi")
	}
	if !contains(summary, "HIGH") {
		t.Errorf("özet risk seviyesi içermiyor: %q", summary)
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && indexOf(s, substr) >= 0)
}
func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Exploit düğümünün de saldırı yüzeyi sayıldığını ve risk skoruna katkıda
// bulunduğunu doğrular. CVE eşleşmemiş ama public exploit yayınlanmış
// servisler (örn. OpenSSH 6.6.1p1 + EDB-45939) için sıfır risk skoru
// dönmemeli.
func TestCalculatePathRisk_RemoteExploit(t *testing.T) {
	p := &AttackPath{
		Steps: []PathStep{
			{NodeType: "target", Label: "scanme.nmap.org"},
			{NodeType: "port", Label: "Port 22"},
			{NodeType: "endpoint", Label: "OpenSSH 6.6.1p1", Data: map[string]string{"service": "openssh", "version": "6.6.1p1"}},
			{NodeType: "exploit", Label: "ExploitDB: EDB-45939", Data: map[string]string{
				"exploit_id":  "EDB-45939",
				"source":      "ExploitDB",
				"description": "OpenSSH Username Enumeration",
				"type":        "remote",
				"cves":        "CVE-2018-15473",
			}},
		},
	}
	calculatePathRisk(p)
	if p.RiskScore <= 0 {
		t.Errorf("public exploit içeren yolun risk skoru pozitif olmalı: %f", p.RiskScore)
	}
	if p.RiskScore < 7 {
		t.Errorf("remote exploit + Port 22 için en az HIGH (>=7) bekleniyordu: %f", p.RiskScore)
	}
	if p.Impact != "HIGH" && p.Impact != "CRITICAL" {
		t.Errorf("impact en az HIGH olmalı: %q", p.Impact)
	}
}

// findPathsToVulns'in exploit düğümünde de yolu tamamladığını doğrular.
// scanme.nmap.org senaryosunda CVE eşleşmemesine rağmen exploit yolundan
// dolayı en az bir saldırı yolu üretilmeli.
func TestFindPathsToVulns_TerminatesOnExploit(t *testing.T) {
	nodes := map[int64]*graphNode{
		1: {ID: 1, Type: "target", Label: "10.0.0.1", Children: []int64{2}},
		2: {ID: 2, Type: "port", Label: "Port 22", Children: []int64{3}},
		3: {ID: 3, Type: "endpoint", Label: "OpenSSH 6.6.1p1", Data: map[string]string{
			"service": "openssh", "version": "6.6.1p1",
		}, Children: []int64{4}},
		4: {ID: 4, Type: "exploit", Label: "ExploitDB: EDB-45939", Data: map[string]string{
			"exploit_id":  "EDB-45939",
			"source":      "ExploitDB",
			"description": "OpenSSH Username Enumeration",
			"type":        "remote",
		}},
	}
	paths := findPathsToVulns(nodes, 1, []int64{}, []PathStep{})
	if len(paths) == 0 {
		t.Fatal("exploit ile sonlanan yol üretilmedi — tespit boşluğu hâlâ var")
	}
	if len(paths[0].Steps) != 4 {
		t.Errorf("yol uzunluğu 4 olmalı (target→port→endpoint→exploit), gerçek=%d", len(paths[0].Steps))
	}
	last := paths[0].Steps[len(paths[0].Steps)-1]
	if last.NodeType != "exploit" {
		t.Errorf("son adım exploit olmalı: %q", last.NodeType)
	}
}

// detectChainedAttacks'in exploit + uzak erişim portu kombinasyonunu yakaladığını
// doğrular.
func TestDetectChainedAttacks_ExploitWithRemoteAccess(t *testing.T) {
	paths := []AttackPath{{
		Steps: []PathStep{
			{NodeType: "target", Label: "10.0.0.1"},
			{NodeType: "port", Label: "Port 22"},
			{NodeType: "endpoint", Data: map[string]string{"service": "openssh"}},
			{NodeType: "exploit", Data: map[string]string{
				"exploit_id": "EDB-45939",
				"type":       "remote",
				"source":     "ExploitDB",
			}},
		},
	}}
	chains := detectChainedAttacks(paths, nil)
	if len(chains) == 0 {
		t.Fatal("exploit + Port 22 zincirleme senaryo olarak yakalanmadı")
	}
	found := false
	for _, c := range chains {
		if contains(c.Name, "Public Exploit") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'Public Exploit' senaryosu bekleniyordu, gelen=%v", chains)
	}
}
