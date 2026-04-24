package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const banner = `
` + "\033[36m" + `   _____ __               __               ______                 __
  / ___// /_  ____ _____/ /___ _      __/ ____/________ _____  / /_
  \__ \/ __ \/ __ ` + "`" + `/ __  / __ \ | /| / / / __/ ___/ __ ` + "`" + `/ __ \/ __ \
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ / /_/ / /  / /_/ / /_/ / / / /
/____/_/ /_/\__,_/\__,_/\____/|__/|__/\____/_/   \__,_/ .___/_/ /_/
                                                     /_/            ` + "\033[0m" + `
` + "\033[1;31m" + `       v0.2.0 — AI-Driven Attack Path & Vulnerability Chaining Engine` + "\033[0m" + `
` + "\033[36m" + `       Open Source | github.com/shadowgraph` + "\033[0m" + `
====================================================================
`

var rootCmd = &cobra.Command{
	Use:   "shadowgraph",
	Short: "ShadowGraph — AI-Driven Attack Path & Chaining Engine",
	Long: banner + `
ShadowGraph hedeflerdeki zafiyetleri tespit eder, saldırı yollarını
graf üzerinde zincirler ve AI tabanlı risk analizi yapar.

Komutlar:
  scan      Ağ taraması (tek IP, CIDR, çoklu hedef)
  import    Nmap XML / Masscan JSON içe aktarma
  analyze   AI saldırı yolu analizi
  ui        İnteraktif web dashboard
  export    JSON / CSV / HTML rapor
  diff      İki tarama karşılaştırması
  plugin    Script/plugin yönetimi`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(banner)
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
