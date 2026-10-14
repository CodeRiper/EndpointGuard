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

	// 1. Chat & Messaging Privacy: Redact private message text
	if strings.Contains(imgLower, "slack") || strings.Contains(lower, "slack") {
		if idx := strings.Index(clean, "#"); idx != -1 {
			ch := clean[idx:]
			if pipe := strings.Index(ch, "|"); pipe != -1 {
				ch = ch[:pipe]
			}
			return prefix + "Slack (" + strings.TrimSpace(ch) + ")"
		}
		return prefix + "Slack (Workspace)"
	}
	if strings.Contains(imgLower, "teams") || strings.Contains(lower, "teams") {
		return prefix + "Microsoft Teams (Workspace / Chat)"
	}
	if strings.Contains(imgLower, "whatsapp") || strings.Contains(lower, "whatsapp") {
		return prefix + "WhatsApp (Direct Message)"
	}
	if strings.Contains(imgLower, "telegram") || strings.Contains(lower, "telegram") {
		return prefix + "Telegram (Direct Message / Channel)"
	}
	if strings.Contains(imgLower, "discord") || strings.Contains(lower, "discord") {
		if idx := strings.Index(clean, "#"); idx != -1 {
			ch := clean[idx:]
			if dash := strings.Index(ch, " - "); dash != -1 {
				ch = ch[:dash]
			}
			return prefix + "Discord (" + strings.TrimSpace(ch) + ")"
		}
		return prefix + "Discord (Chat)"
	}
	if strings.Contains(lower, "chatgpt") || strings.Contains(lower, "chat.openai.com") {
		return prefix + "ChatGPT (AI Assistant Session)"
	}
	if strings.Contains(lower, "claude") && (strings.Contains(lower, "anthropic") || strings.Contains(lower, "claude.ai")) {
		return prefix + "Claude AI (Session)"
	}
	if strings.Contains(lower, "gemini") && strings.Contains(lower, "google") {
		return prefix + "Google Gemini (AI Session)"
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
		}
		for _, s := range suffixes {
			if idx := strings.LastIndex(titlePart, s); idx != -1 {
				titlePart = titlePart[:idx]
			}
		}
		tLower := strings.ToLower(titlePart)
		if strings.Contains(tLower, "whatsapp") {
			return prefix + "WhatsApp Web (Chat)"
		}
		if strings.Contains(tLower, "slack") {
			return prefix + "Slack Web (Workspace)"
		}
		if strings.Contains(tLower, "teams") {
			return prefix + "Microsoft Teams Web (Workspace)"
		}
		if strings.Contains(tLower, "discord") {
			return prefix + "Discord Web (Chat)"
		}
		if strings.Contains(tLower, "telegram") {
			return prefix + "Telegram Web (Chat)"
		}
		if strings.Contains(tLower, "chatgpt") {
			return prefix + "ChatGPT (AI Assistant Session)"
		}
		if strings.Contains(tLower, "claude") {
			return prefix + "Claude AI (Session)"
		}

		if strings.Contains(tLower, "github") {
			if idx := strings.Index(titlePart, ":"); idx != -1 {
				return prefix + "GitHub: " + strings.TrimSpace(titlePart[:idx])
			}
			return prefix + "GitHub (Workspace)"
		}
		if strings.Contains(tLower, "jira") || strings.Contains(tLower, "atlassian") {
			return prefix + "Jira (Workspace)"
		}
		if strings.Contains(tLower, "notion") {
			return prefix + "Notion (Workspace)"
		}
		if strings.Contains(tLower, "figma") {
			return prefix + "Figma (Workspace)"
		}
		if strings.Contains(tLower, "google docs") || strings.Contains(tLower, "google sheets") {
			return prefix + "Google Docs (Workspace)"
		}
		if strings.Contains(tLower, "aws") || strings.Contains(tLower, "amazon web services") {
			return prefix + "AWS Console (Cloud Workspace)"
		}

		if len(titlePart) > 65 {
			if pos := strings.Index(titlePart, " - "); pos > 3 {
				return prefix + titlePart[:pos]
			}
			return prefix + titlePart[:65]
		}
		return prefix + titlePart
	}

	// 3. IDEs / Editors: keep workspace name and editor
	if strings.Contains(imgLower, "code") || strings.Contains(imgLower, "antigravity") || strings.Contains(lower, "visual studio") {
		parts := strings.Split(clean, " - ")
		if len(parts) >= 2 {
			return prefix + parts[0] + " - " + parts[1]
		}
	}

	return raw
}

