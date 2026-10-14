package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type ClickHouseStore struct {
	mu   sync.Mutex
	dsn  string
	conn driver.Conn
}

func NewClickHouseStore(dsn string) (*ClickHouseStore, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}
	return &ClickHouseStore{dsn: dsn, conn: conn}, nil
}

func (s *ClickHouseStore) getConn(ctx context.Context) driver.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()

	pingCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if s.conn == nil || s.conn.Ping(pingCtx) != nil {
		if opts, err := clickhouse.ParseDSN(s.dsn); err == nil {
			if newConn, err := clickhouse.Open(opts); err == nil {
				s.conn = newConn
			}
		}
	}
	return s.conn
}

type FlatEvent struct {
	EventID      string
	AgentID      string
	Hostname     string
	EventType    string
	EventTime    time.Time
	ProcessID    uint32
	ParentPID    uint32
	ImagePath    string
	CommandLine  string
	UserName     string
	WindowTitle  string
	IsIdle       uint8
	CPUPct       float32
	MemUsedBytes uint64
	BatteryPct   float32
	DLPCategory  string
	RawJSON      string
}

func (s *ClickHouseStore) InsertBatch(ctx context.Context, rows []FlatEvent) error {
	if len(rows) == 0 {
		return nil
	}
	conn := s.getConn(ctx)
	if conn == nil {
		return fmt.Errorf("clickhouse connection unavailable")
	}

	batch, err := conn.PrepareBatch(ctx, `
		INSERT INTO endpointguard.telemetry_events
		(event_id, agent_id, hostname, event_type, event_time,
		 process_id, parent_pid, image_path, command_line, user_name,
		 window_title, is_idle, cpu_pct, mem_used_bytes, battery_pct,
		 dlp_category, raw_json)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := batch.Append(
			r.EventID, r.AgentID, r.Hostname, r.EventType, r.EventTime,
			r.ProcessID, r.ParentPID, r.ImagePath, r.CommandLine, r.UserName,
			r.WindowTitle, r.IsIdle, r.CPUPct, r.MemUsedBytes, r.BatteryPct,
			r.DLPCategory, r.RawJSON,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

// QueryEvents — used by the REST API for dashboard queries.
type EventRow struct {
	EventID      string    `json:"event_id"`
	AgentID      string    `json:"agent_id"`
	EventType    string    `json:"event_type"`
	EventTime    time.Time `json:"event_time"`
	Hostname     string    `json:"hostname"`
	ProcessID    uint32    `json:"process_id"`
	ParentPID    uint32    `json:"parent_pid"`
	ImagePath    string    `json:"image_path,omitempty"`
	CommandLine  string    `json:"command_line,omitempty"`
	UserName     string    `json:"user_name,omitempty"`
	WindowTitle  string    `json:"window_title,omitempty"`
	IsIdle       uint8     `json:"is_idle"`
	CPUPct       float32   `json:"cpu_pct"`
	MemUsedBytes uint64    `json:"mem_used_bytes"`
	BatteryPct   float32   `json:"battery_pct"`
	DLPCategory  string    `json:"dlp_category,omitempty"`
	RawJSON      string    `json:"raw_json"`
}

func (s *ClickHouseStore) QueryEvents(
	ctx context.Context,
	agentID, eventType, since, limit string,
) ([]EventRow, error) {
	conn := s.getConn(ctx)
	if conn == nil {
		return nil, fmt.Errorf("clickhouse connection unavailable")
	}

	lim := "1000"
	if limit != "" {
		if limit == "all" || limit == "0" || limit == "unlimited" {
			lim = "50000"
		} else {
			lim = limit
		}
	}

	where := "1=1"
	var args []interface{}

	if agentID != "" && agentID != "all" {
		where += " AND agent_id = ?"
		args = append(args, agentID)
	}

	if eventType != "" && eventType != "ALL" {
		where += " AND event_type = ?"
		args = append(args, eventType)
	}
	if since != "" {
		where += " AND event_time >= parseDateTimeBestEffort(?)"
		args = append(args, since)
	}

	q := fmt.Sprintf(`
		SELECT event_id, agent_id, event_type, event_time, hostname,
		       process_id, parent_pid, image_path, command_line, user_name,
		       window_title, is_idle, cpu_pct, mem_used_bytes, battery_pct,
		       dlp_category, raw_json
		FROM endpointguard.telemetry_events
		WHERE %s
		ORDER BY event_time DESC
		LIMIT %s`, where, lim)

	rows, err := conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []EventRow{}
	for rows.Next() {
		var r EventRow
		if err := rows.Scan(
			&r.EventID, &r.AgentID, &r.EventType, &r.EventTime, &r.Hostname,
			&r.ProcessID, &r.ParentPID, &r.ImagePath, &r.CommandLine, &r.UserName,
			&r.WindowTitle, &r.IsIdle, &r.CPUPct, &r.MemUsedBytes, &r.BatteryPct,
			&r.DLPCategory, &r.RawJSON,
		); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (s *ClickHouseStore) PurgeEvents(ctx context.Context) error {
	conn := s.getConn(ctx)
	if conn == nil {
		return fmt.Errorf("clickhouse connection unavailable")
	}
	return conn.Exec(ctx, "TRUNCATE TABLE endpointguard.telemetry_events")
}

func (s *ClickHouseStore) DeleteAgentEvents(ctx context.Context, agentID string) error {
	if agentID == "" {
		return nil
	}
	conn := s.getConn(ctx)
	if conn == nil {
		return fmt.Errorf("clickhouse connection unavailable")
	}
	err := conn.Exec(ctx, "ALTER TABLE endpointguard.telemetry_events DELETE WHERE agent_id = ?", agentID)
	if err != nil {
		return conn.Exec(ctx, "DELETE FROM endpointguard.telemetry_events WHERE agent_id = ?", agentID)
	}
	return nil
}
