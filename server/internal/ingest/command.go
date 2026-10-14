package ingest

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/yourorg/endpointguard/server/internal/pb"
	"github.com/yourorg/endpointguard/server/internal/store"
)

// CommandBroker routes small, latency-sensitive server→agent commands
// (lock / sign-out / popup / shutdown / restart / cancel) over the agent's
// open StreamCommands connection and returns results to callers.
//
// This is deliberately its own gRPC service, separate from telemetry and
// shell: a slow bulk telemetry upload or a long-running shell session must
// never delay a lock-screen or shutdown command queued behind it.
type CommandBroker struct {
	pb.UnimplementedCommandServiceServer

	mu sync.RWMutex
	// agentID → channel that feeds that agent's open StreamCommands loop
	streams map[string]chan *pb.CommandEnvelope
	// commandID → channel that receives the result once the agent replies
	pending map[string]chan *pb.CommandResult

	pg *store.PostgresStore
	ch *store.ClickHouseStore
}

func NewCommandBroker(pg *store.PostgresStore, ch *store.ClickHouseStore) *CommandBroker {
	return &CommandBroker{
		streams: make(map[string]chan *pb.CommandEnvelope),
		pending: make(map[string]chan *pb.CommandResult),
		pg:      pg,
		ch:      ch,
	}
}

// StreamCommands is called once per agent on connect — same outbound mTLS
// connection as every other service, just a different HTTP/2 stream on it.
func (b *CommandBroker) StreamCommands(stream pb.CommandService_StreamCommandsServer) error {
	ctx := stream.Context()
	agentID, err := AgentIDFromContext(ctx)
	if err != nil {
		return err
	}

	var clientIP string
	if pr, ok := peer.FromContext(ctx); ok && pr.Addr != nil {
		clientIP = pr.Addr.String()
	}

	log.Printf("command stream opened: agent=%s (from %s)", agentID, clientIP)
	_ = stream.SendHeader(metadata.MD{})

	outCh := make(chan *pb.CommandEnvelope, 32)
	b.mu.Lock()
	b.streams[agentID] = outCh
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.streams, agentID)
		b.mu.Unlock()
		close(outCh)
		if err := b.pg.SetAgentStatus(context.Background(), agentID, "OFFLINE"); err != nil {
			log.Printf("set offline failed for %s: %v", agentID, err)
		}
		if b.ch != nil {
			_ = b.ch.InsertBatch(context.Background(), []store.FlatEvent{
				{
					EventID:     uuid.NewString(),
					AgentID:     agentID,
					Hostname:    agentID,
					EventType:   "EVENT_TYPE_AGENT_OFFLINE",
					EventTime:   time.Now().UTC(),
					RawJSON:     fmt.Sprintf(`{"status":"OFFLINE","agent_id":"%s"}`, agentID),
					WindowTitle: "Agent Disconnected / Stream Closed",
				},
			})
		}
		log.Printf("command stream closed: agent=%s", agentID)
	}()

	_ = b.pg.SetAgentStatus(context.Background(), agentID, "ONLINE")
	if b.ch != nil {
		_ = b.ch.InsertBatch(context.Background(), []store.FlatEvent{
			{
				EventID:     uuid.NewString(),
				AgentID:     agentID,
				Hostname:    agentID,
				EventType:   "EVENT_TYPE_AGENT_ONLINE",
				EventTime:   time.Now().UTC(),
				UserName:    clientIP,
				RawJSON:     fmt.Sprintf(`{"status":"ONLINE","agent_id":"%s","remote_addr":"%s"}`, agentID, clientIP),
				WindowTitle: fmt.Sprintf("Agent Connected (%s)", clientIP),
			},
		})
	}

	// Replay anything queued while the agent was offline.
	go b.drainCommandQueue(agentID, outCh)

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for cmd := range outCh {
			if err := stream.Send(cmd); err != nil {
				log.Printf("send to agent %s failed: %v", agentID, err)
				return
			}
		}
	}()

	for {
		result, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Trust the stream's own identity for routing, not whatever the
		// agent put in the message body.
		result.AgentId = agentID
		b.routeResult(result)
	}
}

// Dispatch enqueues a command for an online agent and returns its result
// channel, or (nil, false) if the agent is not currently connected.
func (b *CommandBroker) IsConnected(agentID string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.streams[agentID]
	return ok
}

func (b *CommandBroker) IsOnline(agentID string) bool {
	return b.IsConnected(agentID)
}

func (b *CommandBroker) ConnectedAgents() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	list := make([]string, 0, len(b.streams))
	for id := range b.streams {
		list = append(list, id)
	}
	return list
}

// ResolveOnlineAgentID matches the requested agentID to an actively connected gRPC stream.
// Handles case mismatches, CN differences, or fallback when a single agent is connected.
func (b *CommandBroker) ResolveOnlineAgentID(agentID string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if agentID != "" {
		if _, ok := b.streams[agentID]; ok {
			return agentID
		}
		for id := range b.streams {
			if strings.EqualFold(id, agentID) {
				return id
			}
		}
	}
	if len(b.streams) == 1 {
		for id := range b.streams {
			return id
		}
	}
	if _, ok := b.streams["agnt-test-001"]; ok {
		return "agnt-test-001"
	}
	return ""
}

func (b *CommandBroker) Dispatch(agentID string, cmd *pb.CommandEnvelope) (<-chan *pb.CommandResult, bool) {
	b.mu.RLock()
	outCh, ok := b.streams[agentID]
	b.mu.RUnlock()
	if !ok {
		return nil, false
	}

	resultCh := make(chan *pb.CommandResult, 1)
	b.mu.Lock()
	b.pending[cmd.CommandId] = resultCh
	b.mu.Unlock()

	select {
	case outCh <- cmd:
		return resultCh, true
	case <-time.After(5 * time.Second):
		// The agent's send loop is stuck/dead but hasn't torn the stream
		// down yet — don't block the HTTP handler forever.
		b.mu.Lock()
		delete(b.pending, cmd.CommandId)
		b.mu.Unlock()
		return nil, false
	}
}

func (b *CommandBroker) routeResult(r *pb.CommandResult) {
	b.mu.Lock()
	ch, ok := b.pending[r.CommandId]
	if ok {
		delete(b.pending, r.CommandId)
	}
	b.mu.Unlock()

	if ok {
		ch <- r
	}
}

func (b *CommandBroker) drainCommandQueue(agentID string, outCh chan *pb.CommandEnvelope) {
	queued, err := b.pg.ListQueuedCommands(context.Background(), agentID)
	if err != nil {
		log.Printf("drain: list queued: %v", err)
		return
	}
	for _, row := range queued {
		env, err := BuildEnvelope(row.CommandID, agentID, row.ActionType, nil)
		if err != nil {
			log.Printf("drain: skip malformed queued command %s: %v", row.CommandID, err)
			continue
		}
		outCh <- env
		_ = b.pg.MarkCommandDispatched(context.Background(), row.CommandID)
	}
}

// BuildEnvelope turns a REST-API action name + params map into the matching
// CommandEnvelope oneof. Shared by the HTTP handlers and the queue-replay
// path above so there is exactly one place that understands the mapping.
//
// Supported actions: LOCK, SIGN_OUT, POPUP, SHUTDOWN, RESTART,
// CANCEL_POWER_ACTION.
func BuildEnvelope(commandID, agentID, action string, params map[string]interface{}) (*pb.CommandEnvelope, error) {
	if commandID == "" {
		commandID = uuid.NewString()
	}
	env := &pb.CommandEnvelope{CommandId: commandID, AgentId: agentID}

	switch action {
	case "LOCK":
		env.Command = &pb.CommandEnvelope_Lock{Lock: &pb.LockCommand{}}

	case "SIGN_OUT":
		env.Command = &pb.CommandEnvelope_SignOut{SignOut: &pb.SignOutCommand{}}

	case "POPUP":
		env.Command = &pb.CommandEnvelope_Popup{Popup: &pb.PopupCommand{
			Title:   str(params["title"], "Message from IT"),
			Message: str(params["message"], ""),
		}}

	case "SHUTDOWN", "RESTART":
		actionType := pb.PowerActionType_POWER_ACTION_SHUTDOWN
		if action == "RESTART" {
			actionType = pb.PowerActionType_POWER_ACTION_RESTART
		}
		env.Command = &pb.CommandEnvelope_PowerAction{PowerAction: &pb.PowerActionCommand{
			Action:          actionType,
			DelaySeconds:    uint32(num(params["delay_seconds"], 60)),
			Message:         str(params["message"], defaultPowerMessage(action)),
			ForceAppsClosed: boolv(params["force_apps_closed"], false),
			Reason:          str(params["reason"], ""),
		}}

	case "CANCEL_POWER_ACTION":
		env.Command = &pb.CommandEnvelope_CancelPowerAction{CancelPowerAction: &pb.CancelPowerActionCommand{}}

	default:
		return nil, fmt.Errorf("unknown action type %q", action)
	}

	return env, nil
}

func defaultPowerMessage(action string) string {
	if action == "RESTART" {
		return "This computer will restart shortly. Please save your work."
	}
	return "This computer will shut down shortly. Please save your work."
}

func str(v interface{}, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func num(v interface{}, def float64) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return def
}

func boolv(v interface{}, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
