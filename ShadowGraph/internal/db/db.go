package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// InitDB veritabanı bağlantısını ve Graph schemasını ayağa kaldırır
func InitDB() error {
	dbPath := filepath.Join(".", "shadowgraph.db")

	var err error
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("sqlite acilamadi: %w", err)
	}

	// Önce eski DB dosyalarında eksik kolonları ekle (v1 migration'dan önce çalışır)
	backfillLegacyScanID(DB)

	// Sonra versiyonlu migration'ları uygula
	if err := runMigrations(DB); err != nil {
		return fmt.Errorf("migration hatası: %w", err)
	}

	return nil
}

// CreateScan yeni bir tarama kaydı oluşturur ve ID'sini döner
func CreateScan(target, profile string) (int64, error) {
	result, err := DB.Exec("INSERT INTO scans (target, profile) VALUES (?, ?)", target, profile)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// FinishScan tarama bitiş zamanını günceller
func FinishScan(scanID int64) {
	DB.Exec("UPDATE scans SET finished_at = ? WHERE id = ?", time.Now().Format("2006-01-02 15:04:05"), scanID)
}

// ListScans tüm taramaları listeler
func ListScans() {
	rows, err := DB.Query("SELECT id, target, profile, started_at, coalesce(finished_at,'devam ediyor') FROM scans ORDER BY id DESC LIMIT 20")
	if err != nil {
		fmt.Printf("[\033[31m-\033[0m] Tarama listesi okunamadı: %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("\n  ID  | Hedef                  | Profil    | Başlangıç           | Bitiş")
	fmt.Println("  ----|------------------------|-----------|---------------------|--------------------")
	for rows.Next() {
		var id int64
		var target, profile, started, finished string
		rows.Scan(&id, &target, &profile, &started, &finished)
		fmt.Printf("  %-4d| %-23s| %-10s| %-20s| %s\n", id, target, profile, started, finished)
	}
	fmt.Println()
}

// AddNode Graf yapısına yeni bir düğüm ekler (scan_id destekli)
func AddNode(nodeType, label, data string) (int64, error) {
	result, err := DB.Exec("INSERT INTO nodes (type, label, data) VALUES (?, ?, ?)", nodeType, label, data)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// AddNodeWithScan scan_id ile düğüm ekler
func AddNodeWithScan(scanID int64, nodeType, label, data string) (int64, error) {
	result, err := DB.Exec("INSERT INTO nodes (scan_id, type, label, data) VALUES (?, ?, ?, ?)", scanID, nodeType, label, data)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// AddEdge İki düğüm arasında ilişki kurar
func AddEdge(fromNode, toNode int64, label string) (int64, error) {
	result, err := DB.Exec("INSERT INTO edges (from_node, to_node, label) VALUES (?, ?, ?)", fromNode, toNode, label)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// AddEdgeWithScan scan_id ile edge ekler
func AddEdgeWithScan(scanID, fromNode, toNode int64, label string) (int64, error) {
	result, err := DB.Exec("INSERT INTO edges (scan_id, from_node, to_node, label) VALUES (?, ?, ?, ?)", scanID, fromNode, toNode, label)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}
