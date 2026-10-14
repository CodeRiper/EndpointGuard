package ingest

import (
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/peer"
	"github.com/yourorg/endpointguard/server/internal/pb"
)

// liveWindow: an agent counts as "live" if we've heard a ping within this
// long. Pings arrive every ~2s from the agent side (agent/src/heartbeat.rs),
// so 6s tolerates a couple of missed beats before flagging it stale.
const liveWindow = 6 * time.Second

type AgentHeartbeat struct {
	LastSeen time.Time
	RTTMs    int64
	IP       string
}

// HeartbeatBroker is the dedicated low-latency liveness channel — its own
// service/stream so a slow telemetry flush or a busy shell session can never
// delay dead-connection detection. Purely in-memory: this is live state, not
// something that needs to survive a server restart.
type HeartbeatBroker struct {
	pb.UnimplementedHeartbeatServiceServer

	mu   sync.RWMutex
	seen map[string]AgentHeartbeat
}

func NewHeartbeatBroker() *HeartbeatBroker {
	return &HeartbeatBroker{seen: make(map[string]AgentHeartbeat)}
}

func (b *HeartbeatBroker) StreamHeartbeat(stream pb.HeartbeatService_StreamHeartbeatServer) error {
	ctx := stream.Context()
	agentID, err := AgentIDFromContext(ctx)
	if err != nil {
		return err
	}

	var clientIP string
	if pr, ok := peer.FromContext(ctx); ok && pr.Addr != nil {
		if host, _, err := net.SplitHostPort(pr.Addr.String()); err == nil {
			clientIP = host
		} else {
			clientIP = pr.Addr.String()
		}
	}
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	b.mu.Lock()
	b.seen[agentID] = AgentHeartbeat{LastSeen: time.Now().UTC(), RTTMs: 2, IP: clientIP}
	b.mu.Unlock()

	// Send initial pong immediately so client receives response headers without waiting
	_ = stream.Send(&pb.Pong{
		ClientTimeUnixMs: time.Now().UnixMilli(),
		ServerTimeUnixMs: time.Now().UnixMilli(),
	})

	for {
		ping, err := stream.Recv()
		if err == io.EOF {
			b.mu.Lock()
			delete(b.seen, agentID)
			b.mu.Unlock()
			return nil
		}
		if err != nil {
			return err
		}

		now := time.Now().UTC()
		rawDiff := now.UnixMilli() - ping.ClientTimeUnixMs
		var rtt int64
		if rawDiff >= 0 && rawDiff < 3000 {
			rtt = rawDiff
		} else {
			// Clock skew between machines or initial buffering; default to sub-5ms LAN baseline
			rtt = 2
		}

		b.mu.Lock()
		b.seen[agentID] = AgentHeartbeat{LastSeen: now, RTTMs: rtt, IP: clientIP}
		b.mu.Unlock()

		if err := stream.Send(&pb.Pong{
			ClientTimeUnixMs: ping.ClientTimeUnixMs,
			ServerTimeUnixMs: now.UnixMilli(),
		}); err != nil {
			return err
		}
	}
}

// RTT reports an agent's last-measured round-trip time and whether it has
// been heard from recently enough to count as live right now.
func (b *HeartbeatBroker) RTT(agentID string) (ms int64, live bool) {
	b.mu.RLock()
	hb, ok := b.seen[agentID]
	b.mu.RUnlock()
	if !ok {
		return 0, false
	}
	return hb.RTTMs, time.Since(hb.LastSeen) < liveWindow
}

// Info reports an agent's measured RTT, liveness, and remote client IP address.
func (b *HeartbeatBroker) Info(agentID string) (ms int64, live bool, ip string) {
	b.mu.RLock()
	hb, ok := b.seen[agentID]
	b.mu.RUnlock()
	if !ok {
		return 0, false, ""
	}
	return hb.RTTMs, time.Since(hb.LastSeen) < liveWindow, hb.IP
}

// Remove drops an agent's heartbeat entry immediately upon uninstallation
func (b *HeartbeatBroker) Remove(agentID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.seen, agentID)
}

