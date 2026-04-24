package cmd

import (
	"github.com/shadowgraph/core/internal/db"
	"github.com/spf13/cobra"
)

// scansCmd geçmiş tüm scan kayıtlarını listeler (UI ve analyze için --scan-id seçmeye yardımcı)
var scansCmd = &cobra.Command{
	Use:   "scans",
	Short: "Geçmiş taramaları listeler (ID, hedef, profil, başlangıç/bitiş)",
	Long: `Veritabanındaki tüm scan kayıtlarını en yeniden en eskiye doğru listeler.
Bu ID'leri 'ui --scan-id N', 'analyze --scan-id N' veya 'export --scan-id N' ile kullanabilirsiniz.`,
	Run: func(cmd *cobra.Command, args []string) {
		db.ListScans()
	},
}

func init() {
	rootCmd.AddCommand(scansCmd)
}
