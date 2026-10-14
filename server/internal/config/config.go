// Package config manages server configuration from JSON files, CLI flags,
// interactive onboarding, and environment variables.
package config

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config represents the complete runtime configuration of the EndpointGuard server.
type Config struct {
	ConfigFile       string   `json:"config_file,omitempty"`
	ListenMode       string   `json:"listen_mode"` // "network" (0.0.0.0) or "localhost" (127.0.0.1)
	HTTPPort         string   `json:"http_port"`   // e.g. "8080"
	GRPCPort         string   `json:"grpc_port"`   // e.g. "4443"
	ListenAddr       string   `json:"grpc_addr"`   // computed or explicit ":4443"
	HTTPAddr         string   `json:"http_addr"`   // computed or explicit ":8080"
	StorageDir       string   `json:"storage_dir"`
	LogRetentionDays int      `json:"log_retention_days"`
	AdminPassword    string   `json:"admin_password,omitempty"`
	ClickHouseDSN    string   `json:"clickhouse_dsn"`
	PostgresDSN      string   `json:"postgres_dsn"`
	TLSCertFile      string   `json:"tls_cert_file"`
	TLSKeyFile       string   `json:"tls_key_file"`
	ClientCAFile     string   `json:"client_ca_file"`
	LocalIPs         []string `json:"local_ips,omitempty"`

	// CLI action flags
	RunSetupWizard   bool   `json:"-"`
	SetAdminPassword string `json:"-"`
	InstallService   bool   `json:"-"`
	UninstallService bool   `json:"-"`
	ShowStatus       bool   `json:"-"`
}

// DefaultStoragePath returns an OS-appropriate default storage directory.
func DefaultStoragePath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "EndpointGuard", "storage")
	}
	return "/var/log/endpointguard"
}

// DefaultConfigPath returns an OS-appropriate default config.json path.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "EndpointGuard", "config.json")
	}
	return "/etc/endpointguard/config.json"
}

// GetLocalIPs enumerates all non-loopback IPv4 addresses assigned to the machine.
func GetLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips
}

// Load reads server settings from CLI flags, config.json, or environment variables.
func Load() Config {
	fs := flag.NewFlagSet("endpointguard-server", flag.ContinueOnError)

	configPath := fs.String("config", "", "Path to server configuration JSON file")
	setupFlag := fs.Bool("setup", false, "Launch interactive CLI configuration wizard")
	adminPass := fs.String("admin-password", "", "Set or reset the dashboard admin password")
	bindFlag := fs.String("bind", "", "Bind mode: 'localhost' (127.0.0.1) or 'network' (0.0.0.0)")
	httpPort := fs.String("http-port", "", "HTTP dashboard port, e.g. 8080")
	grpcPort := fs.String("grpc-port", "", "gRPC agent tunnel port, e.g. 4443")
	storageDir := fs.String("storage-dir", "", "Directory path for persistent logs and data")
	retentionDays := fs.Int("retention-days", 30, "Log retention in days (0 for unlimited)")
	listenAddr := fs.String("grpc-addr", "", "gRPC listen address override, e.g. :4443")
	httpAddr := fs.String("http-addr", "", "REST API listen address override, e.g. :8080")
	tlsCert := fs.String("tls-cert", "", "Server TLS cert path")
	tlsKey := fs.String("tls-key", "", "Server TLS key path")
	clientCA := fs.String("client-ca", "", "Client CA certificate path")
	clickhouse := fs.String("clickhouse", "", "ClickHouse DSN")
	postgres := fs.String("postgres", "", "PostgreSQL DSN")
	installSvc := fs.Bool("install-service", false, "Install as system service (systemd / Windows)")
	uninstallSvc := fs.Bool("uninstall-service", false, "Uninstall system service")
	statusFlag := fs.Bool("status", false, "Check server and service status")

	_ = fs.Parse(filterKnownArgs(os.Args[1:], fs))

	// Determine configuration file path
	resolvedConfigPath := *configPath
	if resolvedConfigPath == "" {
		if _, err := os.Stat("config.json"); err == nil {
			resolvedConfigPath = "config.json"
		} else if def := DefaultConfigPath(); fileExists(def) {
			resolvedConfigPath = def
		} else {
			resolvedConfigPath = "config.json"
		}
	}

	cfg := Config{
		ConfigFile:       resolvedConfigPath,
		ListenMode:       "network",
		HTTPPort:         "8080",
		GRPCPort:         "4443",
		StorageDir:       DefaultStoragePath(),
		LogRetentionDays: 30,
		ClickHouseDSN:    "clickhouse://localhost:9000/endpointguard",
		PostgresDSN:      "postgres://eg:eg@localhost:5432/endpointguard",
		TLSCertFile:      "certs/server.crt",
		TLSKeyFile:       "certs/server.key",
		ClientCAFile:     "certs/client-ca.crt",
	}

	// Read existing config file if present
	if data, err := os.ReadFile(resolvedConfigPath); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}

	// Environment variable overrides
	if v := os.Getenv("EG_LISTEN_MODE"); v != "" {
		cfg.ListenMode = v
	}
	if v := os.Getenv("EG_HTTP_PORT"); v != "" {
		cfg.HTTPPort = v
	}
	if v := os.Getenv("EG_GRPC_PORT"); v != "" {
		cfg.GRPCPort = v
	}
	if v := os.Getenv("EG_STORAGE_DIR"); v != "" {
		cfg.StorageDir = v
	}
	if v := os.Getenv("EG_ADMIN_PASSWORD"); v != "" {
		cfg.AdminPassword = v
	}
	if v := os.Getenv("EG_CLICKHOUSE_DSN"); v != "" {
		cfg.ClickHouseDSN = v
	}
	if v := os.Getenv("EG_POSTGRES_DSN"); v != "" {
		cfg.PostgresDSN = v
	}
	if v := os.Getenv("EG_TLS_CERT"); v != "" {
		cfg.TLSCertFile = v
	}
	if v := os.Getenv("EG_TLS_KEY"); v != "" {
		cfg.TLSKeyFile = v
	}
	if v := os.Getenv("EG_CLIENT_CA"); v != "" {
		cfg.ClientCAFile = v
	}

	// CLI flag overrides (highest priority)
	if *bindFlag != "" {
		cfg.ListenMode = *bindFlag
	}
	if *httpPort != "" {
		cfg.HTTPPort = *httpPort
	}
	if *grpcPort != "" {
		cfg.GRPCPort = *grpcPort
	}
	if *storageDir != "" {
		cfg.StorageDir = *storageDir
	}
	if *retentionDays != 30 || cfg.LogRetentionDays == 0 {
		cfg.LogRetentionDays = *retentionDays
	}
	if *adminPass != "" {
		cfg.AdminPassword = *adminPass
		cfg.SetAdminPassword = *adminPass
	}
	if *clickhouse != "" {
		cfg.ClickHouseDSN = *clickhouse
	}
	if *postgres != "" {
		cfg.PostgresDSN = *postgres
	}
	if *tlsCert != "" {
		cfg.TLSCertFile = *tlsCert
	}
	if *tlsKey != "" {
		cfg.TLSKeyFile = *tlsKey
	}
	if *clientCA != "" {
		cfg.ClientCAFile = *clientCA
	}

	cfg.RunSetupWizard = *setupFlag
	cfg.InstallService = *installSvc
	cfg.UninstallService = *uninstallSvc
	cfg.ShowStatus = *statusFlag

	// Compute network listen addresses based on ListenMode
	if *httpAddr != "" {
		cfg.HTTPAddr = *httpAddr
	} else if os.Getenv("EG_HTTP_ADDR") != "" {
		cfg.HTTPAddr = os.Getenv("EG_HTTP_ADDR")
	} else {
		if strings.EqualFold(cfg.ListenMode, "localhost") || cfg.ListenMode == "127.0.0.1" {
			cfg.HTTPAddr = "127.0.0.1:" + cfg.HTTPPort
		} else {
			cfg.HTTPAddr = "0.0.0.0:" + cfg.HTTPPort
		}
	}

	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	} else if os.Getenv("EG_LISTEN") != "" {
		cfg.ListenAddr = os.Getenv("EG_LISTEN")
	} else {
		if strings.EqualFold(cfg.ListenMode, "localhost") || cfg.ListenMode == "127.0.0.1" {
			cfg.ListenAddr = "127.0.0.1:" + cfg.GRPCPort
		} else {
			cfg.ListenAddr = "0.0.0.0:" + cfg.GRPCPort
		}
	}

	cfg.LocalIPs = GetLocalIPs()

	// Locate certificates or auto-generate if missing
	cfg.EnsureCertificates()

	return cfg
}

// EnsureCertificates searches for TLS certificates and generates self-signed certs if missing.
func (c *Config) EnsureCertificates() {
	// Search candidates for server.crt
	candidates := []string{
		c.TLSCertFile,
		"certs/server.crt",
		"../certs/server.crt",
		`C:\ProgramData\EndpointGuard\certs\server.crt`,
		"/etc/endpointguard/certs/server.crt",
	}

	for _, p := range candidates {
		if fileExists(p) {
			c.TLSCertFile = p
			dir := filepath.Dir(p)
			keyCandidate := filepath.Join(dir, "server.key")
			caCandidate := filepath.Join(dir, "client-ca.crt")
			if fileExists(keyCandidate) {
				c.TLSKeyFile = keyCandidate
			}
			if fileExists(caCandidate) {
				c.ClientCAFile = caCandidate
			}
			return
		}
	}

	// If certificates cannot be found anywhere, automatically generate them in ./certs
	_ = GenerateSelfSignedCerts("certs")
	if fileExists("certs/server.crt") {
		c.TLSCertFile = "certs/server.crt"
		c.TLSKeyFile = "certs/server.key"
		c.ClientCAFile = "certs/client-ca.crt"
	}
}

// Save writes the current configuration to disk.
func (c *Config) Save(path string) error {
	if path == "" {
		path = c.ConfigFile
	}
	if path == "" {
		path = "config.json"
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// RunInteractiveSetup executes a CLI configuration wizard in the terminal.
func RunInteractiveSetup(cfg *Config) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("╔═══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║               EndpointGuard Server Setup & Onboarding                 ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// 1. Admin Password
	fmt.Println("== Step 1: Admin Dashboard Password ==")
	currentMsg := "leave blank to auto-generate or keep existing"
	if cfg.AdminPassword != "" {
		currentMsg = fmt.Sprintf("current: '%s'", cfg.AdminPassword)
	}
	fmt.Printf("Enter admin password (%s): ", currentMsg)
	passInput, _ := reader.ReadString('\n')
	passInput = strings.TrimSpace(passInput)
	if passInput != "" {
		cfg.AdminPassword = passInput
		cfg.SetAdminPassword = passInput
	}

	// 2. Network Binding / Web GUI Access
	fmt.Println()
	fmt.Println("== Step 2: Web GUI & Network Access ==")
	fmt.Println("  [1] Localhost Only (127.0.0.1) — Accessible only from this machine")
	fmt.Println("  [2] Network Access (0.0.0.0)   — Accessible across LAN by other devices & agents")
	localIPs := GetLocalIPs()
	if len(localIPs) > 0 {
		fmt.Printf("      (Detected LAN IPs: %s)\n", strings.Join(localIPs, ", "))
	}
	fmt.Printf("Select network binding mode [1 or 2, default: 2]: ")
	bindChoice, _ := reader.ReadString('\n')
	bindChoice = strings.TrimSpace(bindChoice)
	if bindChoice == "1" {
		cfg.ListenMode = "localhost"
		cfg.HTTPAddr = "127.0.0.1:" + cfg.HTTPPort
		cfg.ListenAddr = "127.0.0.1:" + cfg.GRPCPort
	} else {
		cfg.ListenMode = "network"
		cfg.HTTPAddr = "0.0.0.0:" + cfg.HTTPPort
		cfg.ListenAddr = "0.0.0.0:" + cfg.GRPCPort
	}

	// 3. Storage Setup
	fmt.Println()
	fmt.Println("== Step 3: Log & Data Storage Setup ==")
	fmt.Printf("Directory where all server logs, audit trail, and telemetry are saved\n")
	fmt.Printf("Storage directory path [%s]: ", cfg.StorageDir)
	storageInput, _ := reader.ReadString('\n')
	storageInput = strings.TrimSpace(storageInput)
	if storageInput != "" {
		cfg.StorageDir = storageInput
	}

	// 4. Ports
	fmt.Println()
	fmt.Println("== Step 4: Network Ports ==")
	fmt.Printf("HTTP Dashboard Port [%s]: ", cfg.HTTPPort)
	httpInput, _ := reader.ReadString('\n')
	httpInput = strings.TrimSpace(httpInput)
	if httpInput != "" {
		cfg.HTTPPort = httpInput
	}

	fmt.Printf("gRPC Agent Tunnel Port [%s]: ", cfg.GRPCPort)
	grpcInput, _ := reader.ReadString('\n')
	grpcInput = strings.TrimSpace(grpcInput)
	if grpcInput != "" {
		cfg.GRPCPort = grpcInput
	}

	// Recompute addresses
	if cfg.ListenMode == "localhost" {
		cfg.HTTPAddr = "127.0.0.1:" + cfg.HTTPPort
		cfg.ListenAddr = "127.0.0.1:" + cfg.GRPCPort
	} else {
		cfg.HTTPAddr = "0.0.0.0:" + cfg.HTTPPort
		cfg.ListenAddr = "0.0.0.0:" + cfg.GRPCPort
	}

	// Save configuration
	if err := cfg.Save(cfg.ConfigFile); err != nil {
		fmt.Printf("Warning: failed to save config file: %v\n", err)
	} else {
		fmt.Printf("\n✓ Configuration saved to: %s\n", cfg.ConfigFile)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println(" EndpointGuard Server Ready")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Printf("   Web Dashboard URL: http://localhost:%s\n", cfg.HTTPPort)
	for _, ip := range localIPs {
		fmt.Printf("   Network LAN URL:   http://%s:%s\n", ip, cfg.HTTPPort)
	}
	fmt.Printf("   Agent Tunnel Port: %s\n", cfg.GRPCPort)
	fmt.Printf("   Storage Directory: %s\n", cfg.StorageDir)
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println()
	return nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func filterKnownArgs(args []string, fs *flag.FlagSet) []string {
	known := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { known["-"+f.Name] = true; known["--"+f.Name] = true })

	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := a
		if eq := strings.IndexByte(a, '='); eq != -1 {
			name = a[:eq]
		}
		if known[name] {
			out = append(out, a)
			if strings.IndexByte(a, '=') == -1 && i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				out = append(out, args[i+1])
				i++
			}
		}
	}
	return out
}

// GenerateSelfSignedCerts creates a self-signed CA and server cert/key if none exist.
func GenerateSelfSignedCerts(certDir string) error {
	_ = os.MkdirAll(certDir, 0755)

	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"EndpointGuard Internal CA"},
			CommonName:   "EndpointGuard CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}

	// Write CA cert & client-ca.crt
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	_ = os.WriteFile(filepath.Join(certDir, "ca.crt"), caPEM, 0644)
	_ = os.WriteFile(filepath.Join(certDir, "client-ca.crt"), caPEM, 0644)

	// Server Cert
	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"EndpointGuard Server"},
			CommonName:   "localhost",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
		DNSNames:    []string{"localhost", "endpointguard-server"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, ipStr := range GetLocalIPs() {
		if ip := net.ParseIP(ipStr); ip != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
		}
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPriv)})

	_ = os.WriteFile(filepath.Join(certDir, "server.crt"), serverCertPEM, 0644)
	_ = os.WriteFile(filepath.Join(certDir, "server.key"), serverKeyPEM, 0600)

	return nil
}
