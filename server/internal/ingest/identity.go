package ingest

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// AgentIDFromContext pulls the calling agent's identity out of the verified
// mTLS client certificate's CommonName — never from a self-reported field in
// the message payload. mTLS proves the client holds a private key the server
// trusts; it does NOT by itself prove which agent_id that client claims to
// be, so every streaming service calls this instead of trusting
// batch.AgentId / result.AgentId.
//
// Dev certs (scripts/dev-certs.sh) set CN directly to the agent_id, e.g.
// "agnt-test-001", so AgentIDFromContext(ctx) == that string.
func AgentIDFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("identity: no peer info on context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("identity: connection is not mTLS")
	}
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", fmt.Errorf("identity: no verified client certificate")
	}
	cert := chains[0][0]
	cn := cert.Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("identity: client certificate has empty CommonName")
	}
	return cn, nil
}
