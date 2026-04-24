package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/shadowgraph/core/internal/db"
)

// ReportEntry dışa aktarılacak düz tablo satırı
type ReportEntry struct {
	DeviceName string `json:"device_name"`
	IPAddress  string `json:"ip_address"`
	OS         string `json:"os"`
	Port       string `json:"port"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	Banner     string `json:"banner"`
	CVEID      string `json:"cve_id"`
	Severity   string `json:"severity"`
	CVEDesc    string `json:"cve_description"`
}

// ExportJSON SQLite graph verisini yapılandırılmış JSON dosyasına yazar.
// scanID <= 0 ise en son scan kullanılır.
func ExportJSON(outputPath string, scanID int64) error {
	data, err := db.GetGraphData(scanID)
	if err != nil {
		return fmt.Errorf("veritabanı okuma hatası: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("dosya oluşturulamadı: %v", err)
	}
	defer file.Close()

	// JSON'u güzel formatlı (indented) yaz
	var raw json.RawMessage = data
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}

	_, err = file.Write(pretty)
	if err != nil {
		return err
	}

	fmt.Printf("[\033[32m✔\033[0m] JSON rapor oluşturuldu: %s\n", outputPath)
	return nil
}

// ExportCSV SQLite graph verisini düz tablo CSV dosyasına yazar.
// scanID <= 0 ise en son scan kullanılır.
func ExportCSV(outputPath string, scanID int64) error {
	graphData, err := db.GetGraphData(scanID)
	if err != nil {
		return fmt.Errorf("veritabanı okuma hatası: %w", err)
	}

	var graph db.GraphJSON
	if err := json.Unmarshal(graphData, &graph); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("dosya oluşturulamadı: %v", err)
	}
	defer file.Close()

	// UTF-8 BOM (Excel Türkçe karakter desteği)
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Type", "Label", "Group", "Data"})

	for _, node := range graph.Nodes {
		writer.Write([]string{
			node.Group,
			node.Label,
			node.Group,
			node.Data,
		})
	}

	fmt.Printf("[\033[32m✔\033[0m] CSV rapor oluşturuldu: %s (%d kayıt)\n", outputPath, len(graph.Nodes))
	return nil
}
