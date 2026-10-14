.PHONY: proto
proto:
	protoc \
		--go_out=. --go_opt=module=github.com/yourorg/endpointguard/server \
		--go-grpc_out=. --go-grpc_opt=module=github.com/yourorg/endpointguard/server \
		proto/telemetry.proto
# The Rust side generates its proto bindings automatically at build
# time via agent/build.rs (tonic-build) — no separate step needed.
