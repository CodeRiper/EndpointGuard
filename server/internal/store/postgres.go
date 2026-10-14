package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &PostgresStore{pool: pool}, nil
}

// Pool exposes the underlying connection pool so other packages (e.g. auth)
// can run their own queries without PostgresStore growing a method per caller.
func (s *PostgresStore) Pool() *pgxpool.Pool {
	return s.pool
}

// Agent status management
//
// Both functions below are genuine upserts (INSERT ... ON CONFLICT), not
// UPDATE-only. Found by live-testing a brand-new agent_id end to end: an
// UPDATE-only version silently affects zero rows for an agent that was
// never pre-enrolled, so it never appears in /api/agents at all — its
// telemetry lands in ClickHouse and its command stream genuinely connects,
// but the dashboard shows nothing and REST dispatch 404s with "agent not
// found". There is no separate enrollment step in this build (the
// enrollment_tokens table is schema-only, reserved for a future signed
// enrollment flow) — first contact, whichever service sees it first
// (telemetry or the command stream), is what creates the row.
func (s *PostgresStore) UpsertHeartbeat(ctx context.Context, agentID, hostname string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO enterprise_control.agents (agent_id, hostname, os_version, status, last_heartbeat)
		VALUES ($1, $2, '', 'ONLINE', $3)
		ON CONFLICT (agent_id) DO UPDATE
		SET status = 'ONLINE',
		    last_heartbeat = EXCLUDED.last_heartbeat,
		    hostname = CASE WHEN EXCLUDED.hostname <> '' THEN EXCLUDED.hostname ELSE enterprise_control.agents.hostname END`,
		agentID, hostname, time.Now().UTC())
	return err
}

func (s *PostgresStore) SetAgentStatus(ctx context.Context, agentID, status string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO enterprise_control.agents (agent_id, hostname, os_version, status)
		VALUES ($1, '', '', $2)
		ON CONFLICT (agent_id) DO UPDATE SET status = EXCLUDED.status`,
		agentID, status)
	return err
}

type AgentRow struct {
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	OsVersion string `json:"os_version"`
	Status    string `json:"status"`
	// Pointer, not time.Time: a freshly-enrolled agent has NULL here
	// until its first heartbeat lands. pgx cannot scan SQL NULL into a
	// non-pointer time.Time ("cannot scan NULL into *time.Time"), and a
	// pointer also serializes cleanly as JSON null instead of Go's
	// zero-value timestamp string.
	LastHeartbeat *time.Time `json:"last_heartbeat"`
}

func (s *PostgresStore) ListAgents(ctx context.Context) ([]AgentRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, hostname, os_version, status, last_heartbeat
		FROM enterprise_control.agents
		ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []AgentRow
	for rows.Next() {
		var a AgentRow
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.OsVersion,
			&a.Status, &a.LastHeartbeat); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// AgentExists reports whether an agent_id is actually enrolled. Callers
// that are about to queue a command for an offline agent should check this
// first: command_queue.agent_id has a foreign key into agents(agent_id), so
// queuing a command for an ID that was never enrolled fails with a raw FK
// violation rather than a clean "not found" — easy to hit by typo-ing an
// agent_id, confirmed by testing exactly that against a live database.
func (s *PostgresStore) AgentExists(ctx context.Context, agentID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM enterprise_control.agents WHERE agent_id=$1)`,
		agentID).Scan(&exists)
	return exists, err
}

// Command queue

type QueuedCommand struct {
	CommandID  string
	ActionType string
}

func (s *PostgresStore) EnqueueCommand(ctx context.Context, agentID, action, cmdID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO enterprise_control.command_queue
			(command_id, agent_id, action_type, parameters, status, issued_by)
		VALUES ($1, $2, $3, '{}'::jsonb, 'QUEUED', 'api')`,
		cmdID, agentID, action)
	return err
}

func (s *PostgresStore) ListQueuedCommands(ctx context.Context, agentID string) ([]QueuedCommand, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT command_id, action_type
		FROM enterprise_control.command_queue
		WHERE agent_id=$1 AND status='QUEUED'
		ORDER BY command_id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cmds []QueuedCommand
	for rows.Next() {
		var c QueuedCommand
		if err := rows.Scan(&c.CommandID, &c.ActionType); err != nil {
			return nil, err
		}
		cmds = append(cmds, c)
	}
	return cmds, nil
}

func (s *PostgresStore) MarkCommandDispatched(ctx context.Context, cmdID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE enterprise_control.command_queue
		SET status='DISPATCHED', dispatched_at=now()
		WHERE command_id=$1`, cmdID)
	return err
}

func (s *PostgresStore) DeleteAgent(ctx context.Context, agentID string) error {
	_, _ = s.pool.Exec(ctx, `DELETE FROM enterprise_control.command_queue WHERE agent_id=$1`, agentID)
	_, err := s.pool.Exec(ctx, `DELETE FROM enterprise_control.agents WHERE agent_id=$1`, agentID)
	return err
}

func (s *PostgresStore) PurgeCommands(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM enterprise_control.command_queue`)
	return err
}

