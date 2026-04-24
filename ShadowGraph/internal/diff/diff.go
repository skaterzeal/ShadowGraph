package diff

import (
	"database/sql"
	"fmt"
)

// DiffResult iki tarama arasındaki farkları tutar
type DiffResult struct {
	NewPorts      []string
	ClosedPorts   []string
	NewVulns      []string
	ResolvedVulns []string
	NewServices   []string
}

// CompareScansByID iki tarama ID'sini karşılaştırarak farkları döner
func CompareScansByID(db *sql.DB, scanA, scanB int64) (*DiffResult, error) {
	result := &DiffResult{}

	// Scan A'daki portlar
	portsA, err := getNodeLabelsByScan(db, scanA, "port")
	if err != nil {
		return nil, fmt.Errorf("scan %d okunamadı: %v", scanA, err)
	}
	// Scan B'deki portlar
	portsB, err := getNodeLabelsByScan(db, scanB, "port")
	if err != nil {
		return nil, fmt.Errorf("scan %d okunamadı: %v", scanB, err)
	}

	// Scan A'daki zafiyetler
	vulnsA, err := getNodeLabelsByScan(db, scanA, "vulnerability")
	if err != nil {
		return nil, err
	}
	vulnsB, err := getNodeLabelsByScan(db, scanB, "vulnerability")
	if err != nil {
		return nil, err
	}

	// Servisler
	svcsA, err := getNodeLabelsByScan(db, scanA, "endpoint")
	if err != nil {
		return nil, err
	}
	svcsB, err := getNodeLabelsByScan(db, scanB, "endpoint")
	if err != nil {
		return nil, err
	}

	// Fark hesaplama
	result.NewPorts = setDiff(portsB, portsA)
	result.ClosedPorts = setDiff(portsA, portsB)
	result.NewVulns = setDiff(vulnsB, vulnsA)
	result.ResolvedVulns = setDiff(vulnsA, vulnsB)
	result.NewServices = setDiff(svcsB, svcsA)

	return result, nil
}

// PrintDiff sonuçları konsola yazdırır
func PrintDiff(r *DiffResult) {
	fmt.Println("\n══════════════════════════════════════════")
	fmt.Println("         TARAMA KARŞILAŞTIRMA (DIFF)")
	fmt.Println("══════════════════════════════════════════")

	if len(r.NewPorts) > 0 {
		fmt.Println("\n[\033[32m+\033[0m] Yeni Açılan Portlar:")
		for _, p := range r.NewPorts {
			fmt.Printf("    [\033[32m+\033[0m] %s\n", p)
		}
	}
	if len(r.ClosedPorts) > 0 {
		fmt.Println("\n[\033[31m-\033[0m] Kapanan Portlar:")
		for _, p := range r.ClosedPorts {
			fmt.Printf("    [\033[31m-\033[0m] %s\n", p)
		}
	}
	if len(r.NewVulns) > 0 {
		fmt.Println("\n[\033[1;31m!\033[0m] Yeni Tespit Edilen Zafiyetler:")
		for _, v := range r.NewVulns {
			fmt.Printf("    [\033[1;31m!\033[0m] %s\n", v)
		}
	}
	if len(r.ResolvedVulns) > 0 {
		fmt.Println("\n[\033[32m✔\033[0m] Düzeltilen Zafiyetler:")
		for _, v := range r.ResolvedVulns {
			fmt.Printf("    [\033[32m✔\033[0m] %s\n", v)
		}
	}
	if len(r.NewServices) > 0 {
		fmt.Println("\n[\033[36mℹ\033[0m] Yeni Tespit Edilen Servisler:")
		for _, s := range r.NewServices {
			fmt.Printf("    [\033[36mℹ\033[0m] %s\n", s)
		}
	}

	if len(r.NewPorts) == 0 && len(r.ClosedPorts) == 0 && len(r.NewVulns) == 0 && len(r.ResolvedVulns) == 0 {
		fmt.Println("\n[\033[32m✔\033[0m] İki tarama arasında fark bulunamadı.")
	}
}

func getNodeLabelsByScan(db *sql.DB, scanID int64, nodeType string) ([]string, error) {
	rows, err := db.Query("SELECT label FROM nodes WHERE scan_id = ? AND type = ?", scanID, nodeType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var labels []string
	for rows.Next() {
		var l string
		rows.Scan(&l)
		labels = append(labels, l)
	}
	return labels, nil
}

// setDiff A'da olup B'de olmayanları döner
func setDiff(a, b []string) []string {
	bSet := make(map[string]bool)
	for _, v := range b {
		bSet[v] = true
	}
	var diff []string
	for _, v := range a {
		if !bSet[v] {
			diff = append(diff, v)
		}
	}
	return diff
}
