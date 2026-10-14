package ingest

import (
	"io"
	"log"
	"sync"

	"google.golang.org/grpc/metadata"

	"github.com/yourorg/endpointguard/server/internal/pb"
)

// ShellBroker owns the interactive-terminal service: its own gRPC stream,
// fully independent of telemetry and commands, so a keystroke never queues
// behind a batch upload or a stuck command.
//
// One agent can have several concurrent shell sessions (shell_id), e.g. two
// admins opening a terminal on the same machine at once; each shell_id gets
// its own fan-out channel for viewers (dashboard websocket/SSE clients) that
// subscribe to that session's output.
type ShellBroker struct {
	pb.UnimplementedShellServiceServer

	mu sync.RWMutex
	// agentID → channel feeding that agent's open StreamShell loop
	agentStreams map[string]chan *pb.ShellServerMsg
	// shell_id → fan-out subscribers (dashboard viewers) for that session's output
	viewers map[string][]chan *pb.ShellClientMsg
}

func NewShellBroker() *ShellBroker {
	return &ShellBroker{
		agentStreams: make(map[string]chan *pb.ShellServerMsg),
		viewers:      make(map[string][]chan *pb.ShellClientMsg),
	}
}

// StreamShell is called once per agent on connect.
func (b *ShellBroker) StreamShell(stream pb.ShellService_StreamShellServer) error {
	ctx := stream.Context()
	agentID, err := AgentIDFromContext(ctx)
	if err != nil {
		return err
	}

	outCh := make(chan *pb.ShellServerMsg, 64)
	b.mu.Lock()
	b.agentStreams[agentID] = outCh
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.agentStreams, agentID)
		b.mu.Unlock()
		close(outCh)
		log.Printf("shell stream closed: agent=%s", agentID)
	}()

	log.Printf("shell stream opened: agent=%s", agentID)
	_ = stream.SendHeader(metadata.MD{})

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for msg := range outCh {
			if err := stream.Send(msg); err != nil {
				log.Printf("shell send to %s failed: %v", agentID, err)
				return
			}
		}
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		msg.AgentId = agentID
		b.fanOut(msg)
	}
}

// StartShell asks an agent to open a new ConPTY session.
func (b *ShellBroker) StartShell(agentID, shellID string, cols, rows uint32) bool {
	return b.send(agentID, &pb.ShellServerMsg{Msg: &pb.ShellServerMsg_Start{
		Start: &pb.ShellStart{ShellId: shellID, Cols: cols, Rows: rows},
	}})
}

// SendInput forwards a dashboard viewer's keystrokes to the agent.
func (b *ShellBroker) SendInput(agentID, shellID string, data []byte) bool {
	return b.send(agentID, &pb.ShellServerMsg{Msg: &pb.ShellServerMsg_Input{
		Input: &pb.ShellInput{ShellId: shellID, Data: data},
	}})
}

// Resize tells the agent the viewer's terminal dimensions changed.
func (b *ShellBroker) Resize(agentID, shellID string, cols, rows uint32) bool {
	return b.send(agentID, &pb.ShellServerMsg{Msg: &pb.ShellServerMsg_Resize{
		Resize: &pb.ShellResize{ShellId: shellID, Cols: cols, Rows: rows},
	}})
}

// Close tears a shell session down.
func (b *ShellBroker) Close(agentID, shellID string) bool {
	return b.send(agentID, &pb.ShellServerMsg{Msg: &pb.ShellServerMsg_Close{
		Close: &pb.ShellClose{ShellId: shellID},
	}})
}

func (b *ShellBroker) send(agentID string, msg *pb.ShellServerMsg) bool {
	b.mu.RLock()
	ch, ok := b.agentStreams[agentID]
	b.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case ch <- msg:
		return true
	default:
		log.Printf("shell: outbound buffer full for agent %s, dropping message", agentID)
		return false
	}
}

// Subscribe registers a viewer channel for a shell_id's output/exit events.
// Callers (e.g. a dashboard websocket handler) read from the returned
// channel until it closes.
func (b *ShellBroker) Subscribe(shellID string) <-chan *pb.ShellClientMsg {
	ch := make(chan *pb.ShellClientMsg, 64)
	b.mu.Lock()
	b.viewers[shellID] = append(b.viewers[shellID], ch)
	b.mu.Unlock()
	return ch
}

func (b *ShellBroker) fanOut(msg *pb.ShellClientMsg) {
	var shellID string
	switch m := msg.Msg.(type) {
	case *pb.ShellClientMsg_Output:
		shellID = m.Output.ShellId
	case *pb.ShellClientMsg_Exited:
		shellID = m.Exited.ShellId
	default:
		return
	}

	b.mu.RLock()
	subs := b.viewers[shellID]
	b.mu.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- msg:
		default:
			// A slow/gone viewer must never block the agent's shell stream.
		}
	}
}
