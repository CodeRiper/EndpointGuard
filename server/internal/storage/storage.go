package storage

import (
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogEntry represents an in-memory broadcast log entry.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Level     string `json:"level"`
}

// FileInfo holds summary information about a file in storage.
type FileInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

// StorageStats contains storage utilization and disk metrics.
type StorageStats struct {
	StorageDir     string     `json:"storage_dir"`
	TotalSizeBytes int64      `json:"total_size_bytes"`
	FreeDiskBytes  uint64     `json:"free_disk_bytes"`
	TotalDiskBytes uint64     `json:"total_disk_bytes"`
	LogFiles       []FileInfo `json:"log_files"`
}

// Manager orchestrates file persistence, log streaming, and storage metrics.
type Manager struct {
	storageDir     string
	mu             sync.RWMutex
	serverLogFile  *os.File
	auditLogFile   *os.File
	telemLogFile   *os.File
	ringBuffer     []string
	ringCapacity   int
	subscribers    map[chan string]struct{}
	subscribersMu  sync.RWMutex
}

var globalManager *Manager

// Global returns the active global storage manager if initialized.
func Global() *Manager {
	return globalManager
}

// New initializes the storage directory structure and opens log streams.
func New(dir string) (*Manager, error) {
	if dir == "" {
		dir = filepath.Join(".", "storage")
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}

	logsDir := filepath.Join(absDir, "logs")
	auditDir := filepath.Join(absDir, "audit")
	telemDir := filepath.Join(absDir, "telemetry")
	dataDir := filepath.Join(absDir, "data")

	for _, d := range []string{logsDir, auditDir, telemDir, dataDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("create storage subfolder %s: %w", d, err)
		}
	}

	serverLogPath := filepath.Join(logsDir, "server.log")
	serverFile, err := os.OpenFile(serverLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open server.log: %w", err)
	}

	auditLogPath := filepath.Join(auditDir, "audit.log")
	auditFile, err := os.OpenFile(auditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open audit.log: %w", err)
	}

	telemLogPath := filepath.Join(telemDir, "telemetry.log")
	telemFile, err := os.OpenFile(telemLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open telemetry.log: %w", err)
	}

	mgr := &Manager{
		storageDir:    absDir,
		serverLogFile: serverFile,
		auditLogFile:  auditFile,
		telemLogFile:  telemFile,
		ringCapacity:  1000,
		ringBuffer:    make([]string, 0, 1000),
		subscribers:   make(map[chan string]struct{}),
	}

	// Tee standard logger output to both stdout and storage/logs/server.log + ring buffer
	writer := &logHookWriter{
		primary: os.Stdout,
		file:    serverFile,
		mgr:     mgr,
	}
	stdlog.SetOutput(writer)

	globalManager = mgr
	return mgr, nil
}

// StorageDir returns the configured root storage directory path.
func (m *Manager) StorageDir() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storageDir
}

// LogAudit writes a structured audit log entry to storage/audit/audit.log.
func (m *Manager) LogAudit(username, action, target, details string) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"username":  username,
		"action":    action,
		"target":    target,
		"details":   details,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.auditLogFile != nil {
		_, _ = m.auditLogFile.Write(append(data, '\n'))
	}
}

// LogTelemetry persists an agent telemetry event line into storage/telemetry/telemetry.log.
func (m *Manager) LogTelemetry(agentID, eventType, rawJSON string) {
	line := fmt.Sprintf("[%s] agent=%s type=%s %s\n",
		time.Now().UTC().Format(time.RFC3339), agentID, eventType, rawJSON)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.telemLogFile != nil {
		_, _ = m.telemLogFile.WriteString(line)
	}
}

// RecordLogEntry adds a log line to the ring buffer and notifies subscribers.
func (m *Manager) RecordLogEntry(line string) {
	m.mu.Lock()
	if len(m.ringBuffer) >= m.ringCapacity {
		m.ringBuffer = m.ringBuffer[1:]
	}
	m.ringBuffer = append(m.ringBuffer, line)
	m.mu.Unlock()

	// Broadcast to active SSE subscribers
	m.subscribersMu.RLock()
	defer m.subscribersMu.RUnlock()
	for ch := range m.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
}

// Subscribe returns a channel that receives live log lines.
func (m *Manager) Subscribe() chan string {
	ch := make(chan string, 100)
	m.subscribersMu.Lock()
	m.subscribers[ch] = struct{}{}
	m.subscribersMu.Unlock()
	return ch
}

// Unsubscribe removes a log streaming channel.
func (m *Manager) Unsubscribe(ch chan string) {
	m.subscribersMu.Lock()
	delete(m.subscribers, ch)
	m.subscribersMu.Unlock()
	close(ch)
}

// RecentLogs returns up to limit of the most recent log lines.
func (m *Manager) RecentLogs(limit int) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.ringBuffer) {
		limit = len(m.ringBuffer)
	}
	start := len(m.ringBuffer) - limit
	out := make([]string, limit)
	copy(out, m.ringBuffer[start:])
	return out
}

// GetStats calculates disk metrics and lists files in the storage directory.
func (m *Manager) GetStats() (StorageStats, error) {
	m.mu.RLock()
	dir := m.storageDir
	m.mu.RUnlock()

	var totalSize int64
	var files []FileInfo

	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			totalSize += info.Size()
			rel, _ := filepath.Rel(dir, p)
			files = append(files, FileInfo{
				Name:      rel,
				Path:      p,
				SizeBytes: info.Size(),
				ModTime:   info.ModTime(),
			})
		}
		return nil
	})

	freeBytes, totalBytes, _ := getDiskSpace(dir)

	return StorageStats{
		StorageDir:     dir,
		TotalSizeBytes: totalSize,
		FreeDiskBytes:  freeBytes,
		TotalDiskBytes: totalBytes,
		LogFiles:       files,
	}, nil
}

// CleanOldLogs deletes log files older than retentionDays (if retentionDays > 0).
func (m *Manager) CleanOldLogs(retentionDays int) int {
	if retentionDays <= 0 {
		return 0
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	deleted := 0

	m.mu.RLock()
	dir := m.storageDir
	m.mu.RUnlock()

	for _, sub := range []string{"logs", "audit", "telemetry"} {
		subDir := filepath.Join(dir, sub)
		entries, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			// Do not delete currently active main log files
			if e.Name() == "server.log" || e.Name() == "audit.log" || e.Name() == "telemetry.log" {
				continue
			}
			if info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(subDir, e.Name()))
				deleted++
			}
		}
	}
	return deleted
}

// ReadLogFileSlice reads the last nLines lines of the specified log file in storage.
func (m *Manager) ReadLogFileSlice(relativePath string, maxLines int) ([]string, error) {
	m.mu.RLock()
	dir := m.storageDir
	m.mu.RUnlock()

	fullPath := filepath.Join(dir, relativePath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	lines := splitLines(string(content))
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// logHookWriter intercepts stdlog.Printf output.
type logHookWriter struct {
	primary io.Writer
	file    io.Writer
	mgr     *Manager
}

func (w *logHookWriter) Write(p []byte) (n int, err error) {
	n, err = w.primary.Write(p)
	if w.file != nil {
		_, _ = w.file.Write(p)
	}
	if w.mgr != nil {
		line := string(p)
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		w.mgr.RecordLogEntry(line)
	}
	return n, err
}
