package db

import (
	"encoding/json"
	"fmt"
	"log"
)

type NodeData struct {
	ID    int64  `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"`
	Data  string `json:"data"`
}

type EdgeData struct {
	From  int64  `json:"from"`
	To    int64  `json:"to"`
	Label string `json:"label"`
}

type GraphJSON struct {
	Nodes []NodeData `json:"nodes"`
	Edges []EdgeData `json:"edges"`
}

// ScanInfo UI için scan metadata taşır
type ScanInfo struct {
	ID         int64  `json:"id"`
	Target     string `json:"target"`
	Profile    string `json:"profile"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// ResolveScanID scanID <= 0 ise son tamamlanmış scan ID'sini döner.
// Scan yoksa 0 ve hata yerine 0 dönülür (boş grafikle çalışılabilsin).
func ResolveScanID(scanID int64) (int64, error) {
	if scanID > 0 {
		return scanID, nil
	}
	var maxID int64
	err := DB.QueryRow("SELECT COALESCE(MAX(id), 0) FROM scans").Scan(&maxID)
	if err != nil {
		return 0, fmt.Errorf("son scan_id okunamadı: %w", err)
	}
	return maxID, nil
}

// GetScansList tüm scan kayıtlarını JSON olarak döner (UI dropdown için)
func GetScansList() ([]ScanInfo, error) {
	rows, err := DB.Query(`
		SELECT id, target, COALESCE(profile,''), COALESCE(started_at,''), COALESCE(finished_at,'')
		FROM scans ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("scanler listelenemedi: %w", err)
	}
	defer rows.Close()

	scans := make([]ScanInfo, 0)
	for rows.Next() {
		var s ScanInfo
		if err := rows.Scan(&s.ID, &s.Target, &s.Profile, &s.StartedAt, &s.FinishedAt); err != nil {
			log.Println("Scan okuma hatası:", err)
			continue
		}
		scans = append(scans, s)
	}
	return scans, nil
}

// GetGraphData UI paneli için SQLite verisini JSON formatına dönüştürür.
// scanID <= 0 ise en son scan'ın verisi döner. scanID = 0 scan yoksa boş graf döner.
func GetGraphData(scanID int64) ([]byte, error) {
	resolvedID, err := ResolveScanID(scanID)
	if err != nil {
		return nil, err
	}

	var graph GraphJSON
	graph.Nodes = make([]NodeData, 0)
	graph.Edges = make([]EdgeData, 0)

	// Hiç scan yoksa boş graf döndür (UI boş render etsin)
	if resolvedID == 0 {
		return json.Marshal(graph)
	}

	// Düğümleri çek (sadece bu scan'a ait)
	rows, err := DB.Query(`
		SELECT id, type, label, COALESCE(data, '{}')
		FROM nodes
		WHERE scan_id = ?`, resolvedID)
	if err != nil {
		return nil, fmt.Errorf("node okuma: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var n NodeData
		if err := rows.Scan(&n.ID, &n.Group, &n.Label, &n.Data); err != nil {
			log.Println("Node okuma hatası:", err)
			continue
		}
		graph.Nodes = append(graph.Nodes, n)
	}

	// Bağlantıları (Edges) çek (sadece bu scan'a ait)
	edgeRows, err := DB.Query(`
		SELECT from_node, to_node, label
		FROM edges
		WHERE scan_id = ?`, resolvedID)
	if err != nil {
		return nil, fmt.Errorf("edge okuma: %w", err)
	}
	defer edgeRows.Close()

	for edgeRows.Next() {
		var e EdgeData
		if err := edgeRows.Scan(&e.From, &e.To, &e.Label); err != nil {
			log.Println("Edge okuma hatası:", err)
			continue
		}
		graph.Edges = append(graph.Edges, e)
	}

	return json.Marshal(graph)
}
