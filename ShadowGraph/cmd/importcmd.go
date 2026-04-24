package cmd

import (
	"fmt"

	"github.com/shadowgraph/core/internal/importer"
	"github.com/spf13/cobra"
)

var importFile string

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Nmap XML veya Masscan JSON çıktılarını içe aktarır",
	Long: `Harici tarama araçlarının çıktılarını ShadowGraph veritabanına aktarır.

Desteklenen formatlar:
  - Nmap XML   (nmap -oX output.xml)
  - Masscan JSON (masscan --output-format json)

Örnekler:
  shadowgraph import -f nmap_scan.xml
  shadowgraph import -f masscan_output.json`,
	Run: func(cmd *cobra.Command, args []string) {
		if importFile == "" {
			fmt.Println("[\033[31m-\033[0m] Dosya belirtilmedi. -f flag kullanın.")
			return
		}

		fmt.Printf("[\033[36m*\033[0m] İçe aktarılıyor: %s\n", importFile)

		result, err := importer.DetectAndImport(importFile)
		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Import hatası: %v\n", err)
			return
		}

		fmt.Println("\n[\033[32m✔\033[0m] İçe aktarma tamamlandı:")
		fmt.Printf("    Kaynak:     %s\n", result.Source)
		fmt.Printf("    Host:       %d\n", result.Hosts)
		fmt.Printf("    Port:       %d\n", result.Ports)
		fmt.Printf("    Servis:     %d\n", result.Services)
		fmt.Printf("    Zafiyet:    %d\n", result.Vulns)
		fmt.Println("\n[\033[36m*\033[0m] Dashboard'da görmek için: shadowgraph ui")
	},
}

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.Flags().StringVarP(&importFile, "file", "f", "", "İçe aktarılacak dosya yolu (XML veya JSON)")
	importCmd.MarkFlagRequired("file")
}
