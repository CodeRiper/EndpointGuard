## Description
Please include a summary of the change and which issue it fixes. Also include relevant motivation and context.

Fixes #(issue)

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement / Refactoring

## How Has This Been Tested?
Please describe the tests that you ran to verify your changes:
- [ ] Compiled Go server (`go build ./cmd/...`)
- [ ] Compiled Rust agent (`cargo check` or `cargo build --release`)
- [ ] Verified live WebSocket / gRPC multiplexed streams
- [ ] Verified Dashboard Console UI rendering and actions

## Security & Performance Checklist:
- [ ] Zero unauthenticated telemetry or command endpoints exposed
- [ ] mTLS certificate pinning and CN identity preserved
- [ ] No private keys (`*.key`) committed
- [ ] Resource footprint verified (low CPU and memory utilization)
