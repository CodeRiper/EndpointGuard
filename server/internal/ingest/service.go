package ingest

import (
	"context"
	"io"
	"log"
	"sync"
	"time"

	"github.com/yourorg/endpointguard/server/internal/pb"
	"github.com/yourorg/endpointguard/server/internal/store"
)

// Flush policy straight from the blueprint: every 2 seconds, or once
// 10,000 rows have queued up, whichever comes first.
const (
	flushInterval = 2 * time.Second
	flushMaxRows  = 10_000
)

type Service struct {
	pb.UnimplementedIngestionServiceServer
	ch *store.ClickHouseStore
	pg *store.PostgresStore

	mu  sync.Mutex
	buf []store.FlatEvent
}

func New(ch *store.ClickHouseStore, pg *store.PostgresStore) *Service {
	s := &Service{ch: ch, pg: pg}
	go s.flushLoop()
	return s
}

// StreamTelemetry is the one RPC: the agent keeps this stream open
// for its whole lifetime, sending a TelemetryBatch whenever its ring
// buffer flushes, and reading back an ack after each one.
func (s *Service) StreamTelemetry(stream pb.IngestionService_StreamTelemetryServer) error {
	ctx := stream.Context()

	// Identity comes from the verified mTLS client certificate's
	// CommonName, never from the self-reported batch.AgentId field.
	agentID, err := AgentIDFromContext(ctx)
	if err != nil {
		return err
	}

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if err := s.pg.UpsertHeartbeat(ctx, agentID, hostnameOf(batch)); err != nil {
			log.Printf("heartbeat upsert failed for %s: %v", agentID, err)
		}

		s.ingest(agentID, batch)

		if err := stream.Send(&pb.IngestAck{
			AcceptedCount: uint32(len(batch.Events)),
			ServerTimeIso: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
}

func (s *Service) ingest(agentID string, batch *pb.TelemetryBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range batch.Events {
		s.buf = append(s.buf, flatten(agentID, ev))
	}
	if len(s.buf) >= flushMaxRows {
		s.flushLocked()
	}
}

func (s *Service) flushLoop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		s.flushLocked()
		s.mu.Unlock()
	}
}

// flushLocked must be called with s.mu held.
func (s *Service) flushLocked() {
	if len(s.buf) == 0 {
		return
	}
	rows := s.buf
	s.buf = nil
	go func() {
		if err := s.ch.InsertBatch(context.Background(), rows); err != nil {
			log.Printf("clickhouse insert failed (%d rows): %v", len(rows), err)
		}
	}()
}

func hostnameOf(b *pb.TelemetryBatch) string {
	if len(b.Events) > 0 {
		return b.Events[0].Hostname
	}
	return ""
}
