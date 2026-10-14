package ingest

import (
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/yourorg/endpointguard/server/internal/pb"
	"github.com/yourorg/endpointguard/server/internal/store"
)

// flatten converts one TelemetryEvent (its payload is a oneof) into
// the flat row shape ClickHouse stores. Everything not promoted to
// its own column still survives in RawJSON.
func flatten(agentID string, ev *pb.TelemetryEvent) store.FlatEvent {
	row := store.FlatEvent{
		EventID:   ev.EventId,
		AgentID:   agentID,
		Hostname:  ev.Hostname,
		EventType: ev.EventType.String(),
		EventTime: time.UnixMilli(ev.TimestampUnixMs).UTC(),
	}

	switch p := ev.Payload.(type) {
	case *pb.TelemetryEvent_Process:
		row.ProcessID = p.Process.ProcessId
		row.ParentPID = p.Process.ParentProcessId
		row.ImagePath = p.Process.ImageFilePath
		row.CommandLine = p.Process.CommandLine
		row.UserName = p.Process.UserName
	case *pb.TelemetryEvent_Window:
		row.ProcessID = p.Window.ProcessId
		row.ImagePath = p.Window.ProcessImage
		row.WindowTitle = SanitizeWindowTitle(p.Window.WindowTitle, p.Window.ProcessImage)
		if p.Window.IsIdle {
			row.IsIdle = 1
		}
	case *pb.TelemetryEvent_Metric:
		row.CPUPct = float32(p.Metric.CpuUsagePercent)
		row.MemUsedBytes = p.Metric.MemoryUsedBytes
		row.BatteryPct = p.Metric.BatteryPercent
	case *pb.TelemetryEvent_ClipboardDlp:
		row.DLPCategory = p.ClipboardDlp.MatchCategory
	}

	if raw, err := protojson.Marshal(ev); err == nil {
		row.RawJSON = string(raw)
	}

	return row
}

// SanitizeWindowTitle redacts sensitive user conversations and private chat text,
// ensuring only application, workspace, and domain identity are preserved.
func SanitizeWindowTitle(raw, image string) string {
	lower := strings.ToLower(raw)
	imgLower := strings.ToLower(image)

	prefix := ""
	clean := raw
	if strings.HasPrefix(lower, "[incognito]") {
		prefix = "[INCOGNITO] "
		clean = strings.TrimSpace(strings.TrimPrefix(raw, "[INCOGNITO]"))
	} else if strings.HasPrefix(lower, "[inprivate]") {
		prefix = "[INPRIVATE] "
		clean = strings.TrimSpace(strings.TrimPrefix(raw, "[INPRIVATE]"))
	}

	// 1. Chat & Messaging Privacy: Preserve active channel / chat partner while stripping brand suffix
	if strings.Contains(imgLower, "teams") || strings.Contains(lower, "teams") {
		t := clean
		for _, s := range []string{" | Microsoft Teams", " - Microsoft Teams", " - Teams"} {
			if idx := strings.LastIndex(t, s); idx != -1 {
				t = t[:idx]
			}
		}
		tTrim := strings.TrimSpace(t)
		if tTrim != "" && !strings.EqualFold(tTrim, "microsoft teams") {
			return prefix + "Microsoft Teams · " + tTrim
		}
		return prefix + "Microsoft Teams (Workspace)"
	}
	if strings.Contains(imgLower, "slack") || strings.Contains(lower, "slack") {
		t := clean
		for _, s := range []string{" | Slack", " - Slack"} {
			if idx := strings.LastIndex(t, s); idx != -1 {
				t = t[:idx]
			}
		}
		tTrim := strings.TrimSpace(t)
		if tTrim != "" && !strings.EqualFold(tTrim, "slack") {
			return prefix + "Slack · " + tTrim
		}
		return prefix + "Slack (Workspace)"
	}
	if strings.Contains(imgLower, "whatsapp") || strings.Contains(lower, "whatsapp") {
		t := clean
		for _, s := range []string{" - WhatsApp", " | WhatsApp"} {
			if idx := strings.LastIndex(t, s); idx != -1 {
				t = t[:idx]
			}
		}
		tTrim := strings.TrimSpace(t)
		if tTrim != "" && !strings.EqualFold(tTrim, "whatsapp") {
			return prefix + "WhatsApp · " + tTrim
		}
		return prefix + "WhatsApp (Direct Message)"
	}
	if strings.Contains(imgLower, "telegram") || strings.Contains(lower, "telegram") {
		t := clean
		for _, s := range []string{" - Telegram", " | Telegram"} {
			if idx := strings.LastIndex(t, s); idx != -1 {
				t = t[:idx]
			}
		}
		tTrim := strings.TrimSpace(t)
		if tTrim != "" && !strings.EqualFold(tTrim, "telegram") {
			return prefix + "Telegram · " + tTrim
		}
		return prefix + "Telegram (Messenger)"
	}
	if strings.Contains(imgLower, "discord") || strings.Contains(lower, "discord") {
		t := clean
		for _, s := range []string{" - Discord", " | Discord"} {
			if idx := strings.LastIndex(t, s); idx != -1 {
				t = t[:idx]
			}
		}
		tTrim := strings.TrimSpace(t)
		if tTrim != "" && !strings.EqualFold(tTrim, "discord") {
			return prefix + "Discord · " + tTrim
		}
		return prefix + "Discord (Chat)"
	}

	// 2. Browser Workspace Sanitization
	isBrowser := strings.Contains(imgLower, "chrome") ||
		strings.Contains(imgLower, "msedge") ||
		strings.Contains(imgLower, "firefox") ||
		strings.Contains(imgLower, "brave") ||
		strings.Contains(imgLower, "zen") ||
		strings.Contains(imgLower, "opera") ||
		strings.Contains(imgLower, "arc")

	if isBrowser {
		titlePart := clean
		suffixes := []string{
			" - Google Chrome",
			" - Microsoft Edge",
			" - Mozilla Firefox",
			" - Brave",
			" - Zen Browser",
			" - Opera",
			" - Arc",
			" and 1 more page",
			" and 2 more pages",
			" and 3 more pages",
			" and 4 more pages",
		}
		for _, s := range suffixes {
			if idx := strings.LastIndex(titlePart, s); idx != -1 {
				titlePart = titlePart[:idx]
			}
		}

		trimmedTitle := strings.TrimSpace(titlePart)
		if len(trimmedTitle) > 180 {
			return prefix + trimmedTitle[:180]
		}
		return prefix + trimmedTitle
	}

	// 3. IDEs / Editors: keep workspace name and editor
	if strings.Contains(imgLower, "code") || strings.Contains(imgLower, "antigravity") || strings.Contains(lower, "visual studio") {
		return prefix + clean
	}

	return raw
}

