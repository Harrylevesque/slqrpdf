package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Logger is a custom logger type
type Logger struct {
	file   *os.File
	logger *log.Logger
}

// NewLogger creates a new logger instance
func NewLogger(filePath string) (*Logger, error) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := log.New(file, "", log.LstdFlags)

	return &Logger{
		file:   file,
		logger: logger,
	}, nil
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.logger.SetPrefix("INFO: ")
	l.logger.Println(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.logger.SetPrefix("WARN: ")
	l.logger.Println(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.logger.SetPrefix("ERROR: ")
	l.logger.Println(msg)
}

// Close closes the log file
func (l *Logger) Close() {
	l.file.Close()
}

// RotateLog rotates the log file daily
func (l *Logger) RotateLog() {
	for {
		now := time.Now()
		next := now.Add(24 * time.Hour)

		// Wait until the next rotation time
		time.Sleep(next.Sub(now))

		// Close the current log file
		l.Close()

		// Reopen the log file
		file, err := os.OpenFile(l.file.Name(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("failed to rotate log file: %v\n", err)
			return
		}

		l.file = file
		l.logger.SetOutput(file)
	}
}
