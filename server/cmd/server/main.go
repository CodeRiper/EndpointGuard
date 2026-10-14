// EndpointGuard control server.
//
// One binary, identical on Windows and Linux (see scripts/install-windows.ps1
// and scripts/install-linux.sh): it terminates the agents' mTLS tunnel
// (5 multiplexed gRPC services over one connection per agent), stores
// telemetry in ClickHouse and fleet state in PostgreSQL, and serves the
// dashboard's REST API with username/password login.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yourorg/endpointguard/server/internal/api"
	"github.com/yourorg/endpointguard/server/internal/auth"
	"github.com/yourorg/endpointguard/server/internal/config"
	"github.com/yourorg/endpointguard/server/internal/ingest"
	"github.com/yourorg/endpointguard/server/internal/pb"
	"github.com/yourorg/endpointguard/server/internal/storage"
	"github.com/yourorg/endpointguard/server/internal/store"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	// ── CLI Actions ─────────────────────────────────────────────────────
	if cfg.RunSetupWizard {
		if err := config.RunInteractiveSetup(&cfg); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
	}

	if cfg.ShowStatus {
		fmt.Println("EndpointGuard Server Status:")
		fmt.Printf("  Listen Mode: %s\n", cfg.ListenMode)
		fmt.Printf("  HTTP Port:   %s (%s)\n", cfg.HTTPPort, cfg.HTTPAddr)
		fmt.Printf("  gRPC Port:   %s (%s)\n", cfg.GRPCPort, cfg.ListenAddr)
		fmt.Printf("  Storage Dir: %s\n", cfg.StorageDir)
		for _, ip := range config.GetLocalIPs() {
			fmt.Printf("  LAN URL:     http://%s:%s\n", ip, cfg.HTTPPort)
		}
		return
	}

	// ── Storage Subsystem (Logs, Audits, Telemetry) ──────────────────────
	storageMgr, err := storage.New(cfg.StorageDir)
	if err != nil {
		log.Fatalf("initialize storage at %s: %v", cfg.StorageDir, err)
	}

	// ── Databases ───────────────────────────────────────────────────────
	ch, err := store.NewClickHouseStore(cfg.ClickHouseDSN)
	if err != nil {
		log.Fatalf("clickhouse: %v", err)
	}
	pg, err := store.NewPostgresStore(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}

	// ── Dashboard auth (username/password, bcrypt + sessions) ─────────────
	authStore := auth.New(pg.Pool())
	if cfg.AdminPassword != "" {
		if err := authStore.SetAdminPassword(ctx, cfg.AdminPassword); err != nil {
			log.Printf("Warning: failed to set admin password from config/CLI: %v", err)
		} else {
			log.Printf("Admin password configured from configuration/CLI")
		}
	} else if createdPassword, err := authStore.EnsureDefaultAdmin(ctx); err != nil {
		log.Fatalf("auth bootstrap: %v", err)
	} else if createdPassword != "" {
		printFirstRunBanner(createdPassword)
	}

	// ── mTLS credentials for the agent-facing gRPC listener ────────────────
	creds, err := buildMTLS(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ClientCAFile)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	// ── gRPC server: 5 services multiplexed over ONE mTLS connection per
	// agent (one TLS handshake, one listening port, no extra exposed
	// surface) — see proto/telemetry.proto for why each is its own service.
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.ListenAddr, err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(creds))

	ingestSvc := ingest.New(ch, pg)
	pb.RegisterIngestionServiceServer(grpcServer, ingestSvc)

	cmdBroker := ingest.NewCommandBroker(pg, ch)
	pb.RegisterCommandServiceServer(grpcServer, cmdBroker)

	shellBroker := ingest.NewShellBroker()
	pb.RegisterShellServiceServer(grpcServer, shellBroker)

	heartbeatBroker := ingest.NewHeartbeatBroker()
	pb.RegisterHeartbeatServiceServer(grpcServer, heartbeatBroker)

	screenBroker := ingest.NewScreenBroker()
	pb.RegisterScreenServiceServer(grpcServer, screenBroker)

	log.Printf("gRPC (agent tunnel) listening on %s — Ingestion+Command+Shell+Heartbeat+Screen", cfg.ListenAddr)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("grpc serve: %v", err)
		}
	}()

	// ── REST API (dashboard backend) ────────────────────────────────────
	mux := http.NewServeMux()
	apiSrv := api.New(ch, pg, cmdBroker, heartbeatBroker, screenBroker, authStore, &cfg, storageMgr)
	apiSrv.RegisterRoutes(mux)

	printStartupBanner(cfg)

	// If TLS certificates exist, also launch an enterprise-grade hardened HTTPS server on port 8443
	if _, err := os.Stat(cfg.TLSCertFile); err == nil {
		if _, err := os.Stat(cfg.TLSKeyFile); err == nil {
			httpsPort := "8443"
			httpsAddr := ":" + httpsPort
			tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err == nil {
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
					MinVersion:   tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
					},
					PreferServerCipherSuites: true,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					},
				}
				httpsServer := &http.Server{
					Addr:      httpsAddr,
					Handler:   withSecurityHeaders(withCORS(withNetworkPolicy(mux, &cfg))),
					TLSConfig: tlsConfig,
				}
				go func() {
					log.Printf("🔒 OpenSSL TLS 1.3 / 1.2 Enterprise HTTPS listening on %s (HSTS & Strict Ciphers Enabled)", httpsAddr)
					if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
						log.Printf("https serve warning: %v", err)
					}
				}()
			}
		}
	}

	if err := http.ListenAndServe(cfg.HTTPAddr, withCORS(withNetworkPolicy(mux, &cfg))); err != nil {
		log.Fatalf("http serve: %v", err)
	}
}

func withNetworkPolicy(next http.Handler, cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If configured for internal network restriction:
		// Agents connect to gRPC 4443. Web Dashboard / API can be restricted to internal network (RFC1918 / localhost / local IPs).
		if cfg.ListenMode == "localhost" || cfg.ListenMode == "internal" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := net.ParseIP(host)
			if ip != nil {
				isInternal := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
				if !isInternal {
					http.Error(w, "403 Forbidden: Dashboard access restricted to internal network only", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func printStartupBanner(cfg config.Config) {
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println(" 🛡️  EndpointGuard Enterprise Control Server Running")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Printf("   Web Dashboard:     http://localhost:%s\n", cfg.HTTPPort)
	fmt.Printf("   HTTPS Secure:      https://localhost:8443 (TLS / OpenSSL)\n")
	for _, ip := range config.GetLocalIPs() {
		fmt.Printf("   LAN Network URL:   http://%s:%s\n", ip, cfg.HTTPPort)
		fmt.Printf("   LAN HTTPS URL:     https://%s:8443\n", ip)
	}
	fmt.Printf("   Setup & Config:    http://localhost:%s/setup\n", cfg.HTTPPort)
	fmt.Printf("   Agent Tunnel gRPC: %s (Worldwide Encrypted mTLS)\n", cfg.ListenAddr)
	fmt.Printf("   Storage Directory: %s\n", cfg.StorageDir)
	fmt.Println("════════════════════════════════════════════════════════════════")
}

func buildMTLS(certFile, keyFile, clientCAFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caBytes, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// withCORS is permissive by default so the dashboard (served from anywhere
// on your network) can call the API. Tighten Access-Control-Allow-Origin to
// your dashboard's actual origin before exposing this server beyond a
// trusted LAN.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func printFirstRunBanner(password string) {
	line := "════════════════════════════════════════════════════════════════"
	fmt.Println(line)
	fmt.Println(" EndpointGuard — first run: dashboard admin account created")
	fmt.Println(line)
	fmt.Println("   username: admin")
	fmt.Printf("   password: %s\n", password)
	fmt.Println()
	fmt.Println("   This password is shown ONLY this once. Store it now —")
	fmt.Println("   sign in, then add named accounts with scripts/create-user.sh")
	fmt.Println(line)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

