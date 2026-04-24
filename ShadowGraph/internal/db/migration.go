package db

import (
	"database/sql"
	"fmt"
	"sort"
)

// Migration tek bir schema değişikliğini temsil eder
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// migrations geçmişe dönük sıralı migration'lar.
// Yeni migration eklerken: sıradaki version numarasını kullan, hiçbir zaman geçmiştekileri değiştirme.
var migrations = []Migration{
	{
		Version:     1,
		Description: "initial schema (scans, nodes, edges)",
		SQL: `
CREATE TABLE IF NOT EXISTS scans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target TEXT NOT NULL,
	profile TEXT,
	started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	finished_at DATETIME
);

CREATE TABLE IF NOT EXISTS nodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER DEFAULT 0,
	type TEXT NOT NULL,
	label TEXT NOT NULL,
	data TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS edges (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER DEFAULT 0,
	from_node INTEGER,
	to_node INTEGER,
	label TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(scan_id) REFERENCES scans(id),
	FOREIGN KEY(from_node) REFERENCES nodes(id),
	FOREIGN KEY(to_node) REFERENCES nodes(id)
);
`,
	},
	{
		Version:     2,
		Description: "scan_id indexes (performance for WHERE scan_id = ?)",
		SQL: `
CREATE INDEX IF NOT EXISTS idx_nodes_scan_id ON nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan_id ON edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
`,
	},
	{
		Version:     3,
		Description: "analyses table (AI attack path results)",
		SQL: `
CREATE TABLE IF NOT EXISTS analyses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	provider TEXT NOT NULL,
	overall_risk REAL,
	risk_level TEXT,
	total_paths INTEGER,
	critical_paths INTEGER,
	high_risk_paths INTEGER,
	summary TEXT,
	json_data TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_analyses_scan_id ON analyses(scan_id);
`,
	},
}

// runMigrations mevcut schema_version'ı kontrol eder ve pending migration'ları sırayla uygular.
// Hatanın ortasında kalmamak için her migration kendi transaction'ında çalışır.
func runMigrations(database *sql.DB) error {
	// schema_version tablosunu garanti et
	_, err := database.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			description TEXT,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return fmt.Errorf("schema_version tablosu oluşturulamadı: %w", err)
	}

	// Mevcut en yüksek version'ı bul
	var current int
	err = database.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("mevcut schema version okunamadı: %w", err)
	}

	// Migration'ları sıraya göre uygula
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	for _, m := range migrations {
		if m.Version <= current {
			continue
		}

		tx, err := database.Begin()
		if err != nil {
			return fmt.Errorf("migration %d: transaction başlatılamadı: %w", m.Version, err)
		}

		if _, err := tx.Exec(m.SQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d (%s) başarısız: %w", m.Version, m.Description, err)
		}
		if _, err := tx.Exec("INSERT INTO schema_version (version, description) VALUES (?, ?)", m.Version, m.Description); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: schema_version güncellenemedi: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %d: commit hatası: %w", m.Version, err)
		}

		fmt.Printf("[\033[36m*\033[0m] DB migration uygulandı: v%d — %s\n", m.Version, m.Description)
	}

	return nil
}

// backfillLegacyScanID eski DB dosyalarında scan_id kolonu yoksa ekler.
// runMigrations'tan önce çağrılmalı (v1 migration yeni DB için; eski DB'ler için uyumluluk).
func backfillLegacyScanID(database *sql.DB) {
	// Eski DB'lerde (v1 migration'sız kurulmuş) scan_id kolonu yoksa ekle.
	// sqlite ALTER TABLE ... ADD COLUMN idempotent değil, o yüzden PRAGMA ile kontrol.
	hasColumn := func(table, col string) bool {
		rows, err := database.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
		if err != nil {
			return true // güvenli taraf: dene ama hata verse de devam et
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt sql.NullString
			rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk)
			if name == col {
				return true
			}
		}
		return false
	}

	if !hasColumn("nodes", "scan_id") {
		database.Exec("ALTER TABLE nodes ADD COLUMN scan_id INTEGER DEFAULT 0")
	}
	if !hasColumn("edges", "scan_id") {
		database.Exec("ALTER TABLE edges ADD COLUMN scan_id INTEGER DEFAULT 0")
	}
}
