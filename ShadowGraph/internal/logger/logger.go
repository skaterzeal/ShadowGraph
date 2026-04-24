package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level log seviyeleri
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames = map[Level]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

// Logger yapılandırılmış log sistemi
type Logger struct {
	mu       sync.Mutex
	level    Level
	writers  []io.Writer
	jsonMode bool
	file     *os.File
	maxBytes int64
	filePath string
}

// LogEntry SIEM-uyumlu JSON log satırı
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Module    string `json:"module,omitempty"`
}

var defaultLogger *Logger

// Init global logger'ı başlatır
func Init(level string, filePath string, jsonMode bool, maxSizeMB int) error {
	l := &Logger{
		level:    parseLevel(level),
		jsonMode: jsonMode,
		maxBytes: int64(maxSizeMB) * 1024 * 1024,
		filePath: filePath,
	}

	// Stdout her zaman yazılır
	l.writers = append(l.writers, os.Stdout)

	// Dosyaya da yaz
	if filePath != "" {
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("log dizini oluşturulamadı: %v", err)
		}
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("log dosyası açılamadı: %v", err)
		}
		l.file = f
		l.writers = append(l.writers, f)
	}

	defaultLogger = l
	return nil
}

func parseLevel(s string) Level {
	switch s {
	case "DEBUG":
		return DEBUG
	case "WARN":
		return WARN
	case "ERROR":
		return ERROR
	case "FATAL":
		return FATAL
	default:
		return INFO
	}
}

func (l *Logger) log(lvl Level, module, msg string) {
	if lvl < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Log rotation kontrolü
	if l.file != nil && l.maxBytes > 0 {
		if info, err := l.file.Stat(); err == nil && info.Size() > l.maxBytes {
			l.file.Close()
			rotated := l.filePath + "." + time.Now().Format("20060102-150405")
			os.Rename(l.filePath, rotated)
			f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err == nil {
				l.file = f
				l.writers[len(l.writers)-1] = f
			}
		}
	}

	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")

	if l.jsonMode {
		entry := LogEntry{Timestamp: ts, Level: levelNames[lvl], Message: msg, Module: module}
		data, _ := json.Marshal(entry)
		line := string(data) + "\n"
		for _, w := range l.writers {
			w.Write([]byte(line))
		}
	} else {
		line := fmt.Sprintf("[%s] [%s] [%s] %s\n", ts, levelNames[lvl], module, msg)
		for _, w := range l.writers {
			w.Write([]byte(line))
		}
	}
}

// Paket-seviyesi fonksiyonlar
func Debugf(module, format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(DEBUG, module, fmt.Sprintf(format, args...))
	}
}
func Infof(module, format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(INFO, module, fmt.Sprintf(format, args...))
	}
}
func Warnf(module, format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(WARN, module, fmt.Sprintf(format, args...))
	}
}
func Errorf(module, format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(ERROR, module, fmt.Sprintf(format, args...))
	}
}
func Fatalf(module, format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(FATAL, module, fmt.Sprintf(format, args...))
		os.Exit(1)
	}
}
