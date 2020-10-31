package log

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// entry structure for logging
type entry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Address   string `json:"address"`
	Message   string `json:"message"`
}

// Levels for iota
type Levels int

const (
	l_panic Levels = iota
	fatal
	info
	debug
)

var (
	levelStr []string = []string{
		"panic",
		"fatal",
		"info",
		"debug",
	}
)

var level = info

// Println logs a structured line
// log.Println(log.Info, message, remoteAddress)
func Println(entryLevel Levels, message string, address string) {
	var l *entry = new(entry)
	l.Timestamp = time.Now().Format(time.RFC1123)
	l.Message = message
	l.Address = address
	l.Level = levelStr[level]
	content, err := json.Marshal(l)
	if err != nil {
		// we shouldn't skip errors
		return
	}
	if level >= entryLevel {
		fmt.Println(string(content))
	}
}

// Info logs at info level
func Info(message string, address string) {
	Println(info, message, address)
}

// Debug logs at debug level
func Debug(message string, address string) {
	Println(debug, message, address)
}

// Info logs at info level
func Fatal(message string, address string) {
	Println(fatal, message, address)
	os.Exit(1)
}

// Info logs at info level
func Panic(message string, address string) {
	Println(l_panic, message, address)
	panic(message)
}
