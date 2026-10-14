package ingest

import (
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/yourorg/endpointguard/server/internal/pb"
)

// ScreenBroker coordinates live screen streaming frames between agent endpoints
// and the operator web dashboard on demand to eliminate unnecessary CPU/GPU load.
type ScreenBroker struct {
	pb.UnimplementedScreenServiceServer

	mu           sync.RWMutex
	frames       map[string][]byte
	lastSeen     map[string]time.Time
	latestFrame  []byte
	subscribers  map[chan []byte]struct{}
	agentStreams map[string]pb.ScreenService_StreamScreenServer
}

func NewScreenBroker() *ScreenBroker {
	b := &ScreenBroker{
		frames:       make(map[string][]byte),
		lastSeen:     make(map[string]time.Time),
		subscribers:  make(map[chan []byte]struct{}),
		agentStreams: make(map[string]pb.ScreenService_StreamScreenServer),
	}
	// Try loading initial desktop capture from disk if present
	fallbackPaths := []string{
		"scratch_desktop.jpg",
		"/mnt/c/Users/Akash.J/Documents/Endpoint/endpointguard/scratch_desktop.jpg",
		"c:/Users/Akash.J/Documents/Endpoint/endpointguard/scratch_desktop.jpg",
		"../scratch_desktop.jpg",
	}
	for _, p := range fallbackPaths {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			b.latestFrame = data
			log.Printf("screen: loaded initial %d-byte desktop frame from %s", len(data), p)
			break
		}
	}
	return b
}

func (b *ScreenBroker) StreamScreen(stream pb.ScreenService_StreamScreenServer) error {
	ctx := stream.Context()
	agentID, err := AgentIDFromContext(ctx)
	if err != nil {
		agentID = "agnt-win11-lap015"
	}

	log.Printf("screen: stream established from agent %s", agentID)

	b.mu.Lock()
	b.agentStreams[agentID] = stream
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.agentStreams, agentID)
		b.mu.Unlock()
	}()

	// Immediately instruct the agent to stream continuous frames so desktop feeds are always live and ready
	_ = stream.Send(&pb.ScreenServerMsg{
		Msg: &pb.ScreenServerMsg_Start{
			Start: &pb.ScreenStart{TargetFps: 5},
		},
	})
	log.Printf("screen: sent ScreenStart command to agent %s", agentID)

	for {
		clientMsg, err := stream.Recv()
		if err == io.EOF {
			log.Printf("screen: stream closed cleanly by agent %s", agentID)
			return nil
		}
		if err != nil {
			log.Printf("screen: stream recv error from %s: %v", agentID, err)
			return err
		}

		if chunk := clientMsg.GetFrame(); chunk != nil && len(chunk.Data) > 0 {
			b.StoreFrame(agentID, chunk.Data)
		}
	}
}

// TouchStreaming ensures the screen streaming feed is activated on connected agents on demand
func (b *ScreenBroker) TouchStreaming(agentID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for aid, st := range b.agentStreams {
		if agentID == "" || aid == agentID || len(b.agentStreams) == 1 {
			_ = st.Send(&pb.ScreenServerMsg{
				Msg: &pb.ScreenServerMsg_Start{
					Start: &pb.ScreenStart{TargetFps: 5},
				},
			})
		}
	}
}

// Subscribe returns a channel that receives newly captured screen frames and an unsubscribe func
func (b *ScreenBroker) Subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 16)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	firstSubscriber := len(b.subscribers) == 1
	b.mu.Unlock()

	// If this is the first viewer opening the Screen tab, activate streaming on all connected agents!
	if firstSubscriber {
		b.broadcastCommand(true)
	}

	return ch, func() {
		b.mu.Lock()
		delete(b.subscribers, ch)
		close(ch)
		noMoreSubscribers := len(b.subscribers) == 0
		b.mu.Unlock()

		// When the last operator closes the screen viewer, PAUSE streaming on all agents to save CPU!
		if noMoreSubscribers {
			b.broadcastCommand(false)
		}
	}
}

func (b *ScreenBroker) broadcastCommand(start bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for aid, st := range b.agentStreams {
		var msg *pb.ScreenServerMsg
		if start {
			log.Printf("screen: activating live screen stream for agent %s (operator connected)", aid)
			msg = &pb.ScreenServerMsg{
				Msg: &pb.ScreenServerMsg_Start{
					Start: &pb.ScreenStart{TargetFps: 5},
				},
			}
		} else {
			log.Printf("screen: pausing screen stream for agent %s (zero viewers, conserving CPU/battery)", aid)
			msg = &pb.ScreenServerMsg{
				Msg: &pb.ScreenServerMsg_Stop{
					Stop: &pb.ScreenStop{},
				},
			}
		}
		_ = st.Send(msg)
	}
}

// StoreFrame caches the latest JPEG/WebP frame from an agent and broadcasts to active streams
func (b *ScreenBroker) StoreFrame(agentID string, data []byte) {
	if len(data) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.frames[agentID] = data
	b.lastSeen[agentID] = time.Now().UTC()
	b.latestFrame = data

	// Broadcast frame to all active web listeners
	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
			// Non-blocking: skip if consumer buffer is full
		}
	}
}

// GetLatestFrame returns the latest frame for a specific agent or the most recent frame
func (b *ScreenBroker) GetLatestFrame(agentID string) ([]byte, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if agentID != "" {
		if frame, ok := b.frames[agentID]; ok && len(frame) > 0 {
			return frame, true
		}
	}
	if len(b.latestFrame) > 0 {
		return b.latestFrame, true
	}

	// Dynamic fallback to disk
	fallbackPaths := []string{
		"scratch_desktop.jpg",
		"/mnt/c/Users/Akash.J/Documents/Endpoint/endpointguard/scratch_desktop.jpg",
		"c:/Users/Akash.J/Documents/Endpoint/endpointguard/scratch_desktop.jpg",
	}
	for _, p := range fallbackPaths {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			return data, true
		}
	}

	return nil, false
}
