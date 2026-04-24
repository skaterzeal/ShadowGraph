package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/shadowgraph/core/internal/plugin"
	"github.com/spf13/cobra"
)

var (
	pluginInit bool
	pluginDir  string
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "YAML tabanlı plugin/script yönetimi",
	Long: `ShadowGraph plugin sistemi — YAML formatında özel tarama scriptleri.

Örnekler:
  shadowgraph plugin                    # Yüklü plugin'leri listele
  shadowgraph plugin --init             # Örnek plugin oluştur
  shadowgraph plugin --dir ./plugins    # Özel dizinden yükle`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := pluginDir
		if dir == "" {
			dir = filepath.Join(".", "plugins")
		}

		if pluginInit {
			if err := plugin.InitSamplePlugin(dir); err != nil {
				fmt.Printf("[\033[31m-\033[0m] Plugin oluşturma hatası: %v\n", err)
				return
			}
			return
		}

		pm := plugin.NewPluginManager(dir)
		if err := pm.LoadPlugins(); err != nil {
			fmt.Printf("[\033[31m-\033[0m] Plugin yükleme hatası: %v\n", err)
			return
		}

		pm.ListPlugins()
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.Flags().BoolVar(&pluginInit, "init", false, "Örnek plugin dosyası oluştur")
	pluginCmd.Flags().StringVar(&pluginDir, "dir", "", "Plugin dizini (varsayılan: ./plugins)")
}
