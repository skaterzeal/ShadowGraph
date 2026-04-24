package main

import (
	"fmt"
	"os"

	"github.com/shadowgraph/core/cmd"
	"github.com/shadowgraph/core/internal/config"
	"github.com/shadowgraph/core/internal/db"
	"github.com/shadowgraph/core/internal/logger"
)

func main() {
	// Config yükle
	if err := config.LoadConfig(); err != nil {
		fmt.Printf("[\033[33m!\033[0m] Config uyarısı: %v\n", err)
	}

	// Logger başlat
	logFile := config.AppConfig.Logging.File
	if logFile == "" {
		logFile = "shadowgraph.log"
	}
	logger.Init(
		config.AppConfig.Logging.Level,
		logFile,
		config.AppConfig.Logging.JSON,
		config.AppConfig.Logging.MaxSize,
	)

	// DB başlat
	if err := db.InitDB(); err != nil {
		fmt.Printf("[\033[31m-\033[0m] Kritik Hata: Veritabanı başlatılamadı: %v\n", err)
		os.Exit(1)
	}

	logger.Infof("main", "ShadowGraph başlatıldı")
	cmd.Execute()
}
