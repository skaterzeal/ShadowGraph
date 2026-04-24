package cmd

import (
	"fmt"

	"github.com/shadowgraph/core/internal/db"
	"github.com/shadowgraph/core/internal/diff"
	"github.com/spf13/cobra"
)

var (
	scanA int64
	scanB int64
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "İki taramayı karşılaştırarak değişiklikleri raporlar (Enterprise)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[\033[36m*\033[0m] Tarama #%d ile #%d karşılaştırılıyor...\n", scanA, scanB)

		result, err := diff.CompareScansByID(db.DB, scanA, scanB)
		if err != nil {
			fmt.Printf("[\033[31m-\033[0m] Diff hatası: %v\n", err)
			return
		}

		diff.PrintDiff(result)
	},
}

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().Int64Var(&scanA, "scan-a", 0, "Eski tarama ID'si")
	diffCmd.Flags().Int64Var(&scanB, "scan-b", 0, "Yeni tarama ID'si")
	diffCmd.MarkFlagRequired("scan-a")
	diffCmd.MarkFlagRequired("scan-b")
}
