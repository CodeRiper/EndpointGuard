// testclient is a real mTLS gRPC client used to exercise each of the
// server's 5 services end-to-end — not a mock: it uses the actual
// generated pb types and real client certs, the same way a genuine agent
// would, just driven from the command line instead of from Rust.
//
// Usage:
//
//	testclient telemetry  <cert> <key> <ca> <addr>
//	testclient command    <cert> <key> <ca> <addr> <seconds>
//	testclient heartbeat  <cert> <key> <ca> <addr> <pings>
//	testclient screen     <cert> <key> <ca> <addr>
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yourorg/endpointguard/server/internal/pb"
)

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintln(os.Stderr, "usage: testclient <mode> <cert> <key> <ca> <addr> [extra...]")
		os.Exit(1)
	}
	mode := os.Args[1]
	certPath, keyPath, caPath, addr := os.Args[2], os.Args[3], os.Args[4], os.Args[5]

	creds, err := buildCreds(certPath, keyPath, caPath)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	switch mode {
	case "telemetry":
		runTelemetry(conn)
	case "command":
		seconds := 10
		if len(os.Args) > 6 {
			seconds, _ = strconv.Atoi(os.Args[6])
		}
		runCommand(conn, seconds)
	case "heartbeat":
		pings := 3
		if len(os.Args) > 6 {
			pings, _ = strconv.Atoi(os.Args[6])
		}
		runHeartbeat(conn, pings)
	case "screen":
		runScreen(conn)
	case "shell":
		runShell(conn)
	default:
		log.Fatalf("unknown mode %q", mode)
	}
}

func buildCreds(certPath, keyPath, caPath string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

func runTelemetry(conn *grpc.ClientConn) {
	client := pb.NewIngestionServiceClient(conn)
	stream, err := client.StreamTelemetry(context.Background())
	if err != nil {
		log.Fatalf("StreamTelemetry: %v", err)
	}

	batch := &pb.TelemetryBatch{
		AgentId: "agnt-test-001", // informational only — server trusts the cert CN, not this
		Events: []*pb.TelemetryEvent{
			{
				EventId:         "evt-1",
				Hostname:        "TEST-HOST-01",
				TimestampUnixMs: time.Now().UnixMilli(),
				EventType:       pb.EventType_EVENT_TYPE_WINDOW_FOCUS,
				Payload: &pb.TelemetryEvent_Window{Window: &pb.WindowEvent{
					WindowTitle:  "Invoice_Q3.xlsx — Excel",
					ProcessImage: "EXCEL.EXE",
					ProcessId:    4242,
				}},
			},
			{
				EventId:         "evt-2",
				Hostname:        "TEST-HOST-01",
				TimestampUnixMs: time.Now().UnixMilli(),
				EventType:       pb.EventType_EVENT_TYPE_DLP_CLIPBOARD,
				Payload: &pb.TelemetryEvent_ClipboardDlp{ClipboardDlp: &pb.ClipboardDlpEvent{
					SourceProcess: "OUTLOOK.EXE",
					MatchCategory: "CARD_NUMBER",
					MatchCount:    1,
				}},
			},
		},
	}

	if err := stream.Send(batch); err != nil {
		log.Fatalf("send: %v", err)
	}
	ack, err := stream.Recv()
	if err != nil {
		log.Fatalf("recv ack: %v", err)
	}
	fmt.Printf("OK telemetry: ack accepted_count=%d server_time=%s\n", ack.AcceptedCount, ack.ServerTimeIso)
	stream.CloseSend()
}

func runCommand(conn *grpc.ClientConn, seconds int) {
	client := pb.NewCommandServiceClient(conn)
	stream, err := client.StreamCommands(context.Background())
	if err != nil {
		log.Fatalf("StreamCommands: %v", err)
	}

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	fmt.Printf("OK command: stream open, waiting up to %ds for envelopes...\n", seconds)
	for time.Now().Before(deadline) {
		stream.Context()
		recvCh := make(chan *pb.CommandEnvelope, 1)
		errCh := make(chan error, 1)
		go func() {
			env, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			recvCh <- env
		}()
		select {
		case env := <-recvCh:
			kind := describeCommand(env)
			fmt.Printf("OK command: received %s (command_id=%s)\n", kind, env.CommandId)
			_ = stream.Send(&pb.CommandResult{
				CommandId: env.CommandId,
				Result:    &pb.CommandResult_Action{Action: &pb.ActionResult{Success: true}},
			})
		case err := <-errCh:
			log.Fatalf("recv: %v", err)
		case <-time.After(time.Until(deadline)):
			fmt.Println("OK command: idle timeout reached, closing")
			return
		}
	}
}

func describeCommand(env *pb.CommandEnvelope) string {
	switch env.Command.(type) {
	case *pb.CommandEnvelope_Lock:
		return "LOCK"
	case *pb.CommandEnvelope_SignOut:
		return "SIGN_OUT"
	case *pb.CommandEnvelope_Popup:
		return "POPUP"
	case *pb.CommandEnvelope_PowerAction:
		pa := env.GetPowerAction()
		return fmt.Sprintf("POWER_ACTION action=%s delay=%ds message=%q", pa.Action, pa.DelaySeconds, pa.Message)
	case *pb.CommandEnvelope_CancelPowerAction:
		return "CANCEL_POWER_ACTION"
	default:
		return "UNKNOWN"
	}
}

func runHeartbeat(conn *grpc.ClientConn, pings int) {
	client := pb.NewHeartbeatServiceClient(conn)
	stream, err := client.StreamHeartbeat(context.Background())
	if err != nil {
		log.Fatalf("StreamHeartbeat: %v", err)
	}
	for i := 0; i < pings; i++ {
		sent := time.Now().UnixMilli()
		if err := stream.Send(&pb.Ping{ClientTimeUnixMs: sent}); err != nil {
			log.Fatalf("send ping: %v", err)
		}
		pong, err := stream.Recv()
		if err != nil {
			log.Fatalf("recv pong: %v", err)
		}
		rtt := time.Now().UnixMilli() - pong.ClientTimeUnixMs
		fmt.Printf("OK heartbeat: pong %d/%d rtt=%dms server_time=%d\n", i+1, pings, rtt, pong.ServerTimeUnixMs)
		time.Sleep(time.Second)
	}
	stream.CloseSend()
}

// runShell confirms the ShellService stream opens, identity resolves via
// the cert (same as the other services), and a ShellClientMsg can be sent
// and fanned out without error. Nothing calls ShellBroker.StartShell in
// this test (that's driven by a dashboard, not the REST API yet), so there
// is no server->agent push to receive here — this proves the wiring, not a
// full interactive session.
func runShell(conn *grpc.ClientConn) {
	client := pb.NewShellServiceClient(conn)
	stream, err := client.StreamShell(context.Background())
	if err != nil {
		log.Fatalf("StreamShell (open): %v", err)
	}
	err = stream.Send(&pb.ShellClientMsg{
		Msg: &pb.ShellClientMsg_Output{Output: &pb.ShellOutput{
			ShellId: "test-shell-1",
			Data:    []byte("hello from test shell\n"),
		}},
	})
	if err != nil {
		log.Fatalf("send shell output: %v", err)
	}
	fmt.Println("OK shell: stream opened and output chunk sent without error")
	stream.CloseSend()
}

func runScreen(conn *grpc.ClientConn) {
	client := pb.NewScreenServiceClient(conn)
	stream, err := client.StreamScreen(context.Background())
	if err != nil {
		log.Fatalf("StreamScreen (open): %v", err)
	}
	if err := stream.Send(&pb.ScreenClientMsg{}); err != nil {
		fmt.Printf("OK screen: send failed as expected: %v\n", err)
		return
	}
	_, err = stream.Recv()
	if err == nil {
		log.Fatalf("expected UNIMPLEMENTED, got success")
	}
	fmt.Printf("OK screen: got expected error: %v\n", err)
}
