package ingest

import (
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
		row.WindowTitle = p.Window.WindowTitle
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
