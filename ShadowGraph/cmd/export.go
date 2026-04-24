package cmd

import (
	"fmt"

	"github.com/shadowgraph/core/internal/db"
	"github.com/shadowgraph/core/internal/report"
	"github.com/spf13/cobra"
)

var (
	exportFormat string
	exportOutput string
	exportScanID int64
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Tarama sonuçlarını JSON, CSV veya HTML olarak dışa aktarır",
	Run: func(cmd *cobra.Command, args []string) {
		if exportOutput == "" {
			switch exportFormat {
			case "csv":
				exportOutput = "shadowgraph_report.csv"
			case "html":
				exportOutput = "shadowgraph_report.html"
			default:
				exportOutput = "shadowgraph_report.json"
			}
		}

		// scanID çözümle (kullanıcıya doğru ID'yi göster)
		resolvedID, err := db.ResolveScanID(exportScanID)
		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Scan ID çözümlenemedi: %v\n", err)
			return
		}
		if resolvedID == 0 {
			fmt.Println("[\033[33m!\033[0m] Henüz hiç tarama yapılmamış. Önce 'shadowgraph scan' çalıştırın.")
			return
		}

		fmt.Printf("[\033[36m*\033[0m] Rapor oluşturuluyor: format=%s, scan_id=%d, dosya=%s\n", exportFormat, resolvedID, exportOutput)

		switch exportFormat {
		case "csv":
			err = report.ExportCSV(exportOutput, resolvedID)
		case "json":
			err = report.ExportJSON(exportOutput, resolvedID)
		case "html":
			err = report.ExportHTML(exportOutput, resolvedID)
		case "scans":
			db.ListScans()
			return
		default:
			fmt.Printf("[\033[31m-\033[0m] Desteklenmeyen format: %s (json, csv, html veya scans)\n", exportFormat)
			return
		}

		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Export hatası: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Çıktı formatı: json, csv, html veya scans")
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Çıktı dosya yolu")
	exportCmd.Flags().Int64Var(&exportScanID, "scan-id", 0, "Hangi scan ID raporlansın (varsayılan: en son)")
}
