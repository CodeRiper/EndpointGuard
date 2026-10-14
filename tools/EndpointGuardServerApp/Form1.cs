using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace EndpointGuardServerApp
{
    public partial class Form1 : Form
    {
        private Process? _serverProcess;
        private string _configPath = "";
        private string _serverExePath = "";
        private ServerConfig _config = new();

        // UI Controls
        private Label _lblStatusBadge = null!;
        private Label _lblStatusDetails = null!;
        private Button _btnStart = null!;
        private Button _btnStop = null!;
        private Button _btnRestart = null!;
        private Button _btnOpenBrowser = null!;

        private TextBox _txtAdminPass = null!;
        private CheckBox _chkShowPass = null!;
        private Button _btnApplyPass = null!;

        private RadioButton _rbLocalhost = null!;
        private RadioButton _rbNetwork = null!;
        private TextBox _txtHttpPort = null!;
        private TextBox _txtGrpcPort = null!;
        private Label _lblDetectedIps = null!;

        private TextBox _txtStorageDir = null!;
        private Button _btnBrowseStorage = null!;
        private Button _btnOpenExplorer = null!;
        private Label _lblDiskFree = null!;
        private ComboBox _cmbRetention = null!;

        private RichTextBox _rtbLogs = null!;
        private NotifyIcon _trayIcon = null!;

        public Form1()
        {
            InitializeComponentCustom();
            LocateFilesAndLoadConfig();
            RefreshDiskSpace();
            StartServerProcess();
        }

        private void InitializeComponentCustom()
        {
            this.Text = "EndpointGuard Enterprise Server — Control Center";
            this.Size = new Size(880, 760);
            this.MinimumSize = new Size(820, 680);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(11, 15, 25); // Slate 950
            this.ForeColor = Color.FromArgb(243, 244, 246);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            // Tray Icon
            _trayIcon = new NotifyIcon
            {
                Text = "EndpointGuard Server",
                Icon = SystemIcons.Shield,
                Visible = true
            };
            var trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("🌐 Open Dashboard", null, (s, e) => OpenDashboardInBrowser());
            trayMenu.Items.Add("🖥️ Show Control Center", null, (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("❌ Exit", null, (s, e) => { ExitApplication(); });
            _trayIcon.ContextMenuStrip = trayMenu;
            _trayIcon.DoubleClick += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; };

            // Main Layout Panel
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(16),
                BackColor = Color.Transparent
            };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));  // Header
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 100)); // Status & Controls
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 330)); // Setup & Configuration
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // Live Console Logs
            this.Controls.Add(root);

            // 1. Header
            var pnlHeader = new Panel { Dock = DockStyle.Fill };
            var lblTitle = new Label
            {
                Text = "🛡️ EndpointGuard Control Server",
                Font = new Font("Segoe UI", 16f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 229, 255), // Cyan
                AutoSize = true,
                Location = new Point(0, 8)
            };
            var lblSub = new Label
            {
                Text = "Enterprise EDR / RMM Control Engine — Agent Tunnel & Web Console Management",
                Font = new Font("Segoe UI", 9f),
                ForeColor = Color.FromArgb(156, 163, 175),
                AutoSize = true,
                Location = new Point(2, 40)
            };
            pnlHeader.Controls.AddRange(new Control[] { lblTitle, lblSub });
            root.Controls.Add(pnlHeader, 0, 0);

            // 2. Status & Quick Actions Card
            var pnlStatus = CreateCardPanel();
            pnlStatus.Dock = DockStyle.Fill;
            pnlStatus.Padding = new Padding(12);

            _lblStatusBadge = new Label
            {
                Text = "● SERVER STARTING...",
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                ForeColor = Color.FromArgb(234, 179, 8),
                AutoSize = true,
                Location = new Point(14, 14)
            };
            _lblStatusDetails = new Label
            {
                Text = "HTTP: http://localhost:8080 | gRPC: :4443",
                Font = new Font("Segoe UI", 9f),
                ForeColor = Color.FromArgb(156, 163, 175),
                AutoSize = true,
                Location = new Point(16, 42)
            };

            _btnOpenBrowser = new Button
            {
                Text = "🚀 Open Dashboard in Browser",
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                BackColor = Color.FromArgb(2, 132, 199),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(240, 44),
                Location = new Point(560, 14),
                Cursor = Cursors.Hand
            };
            _btnOpenBrowser.FlatAppearance.BorderSize = 0;
            _btnOpenBrowser.Click += (s, e) => OpenDashboardInBrowser();

            _btnStart = CreateSmallButton("▶ Start", 14, 65, (s, e) => StartServerProcess());
            _btnStop = CreateSmallButton("⏹ Stop", 90, 65, (s, e) => StopServerProcess());
            _btnRestart = CreateSmallButton("🔄 Restart", 166, 65, (s, e) => RestartServerProcess());

            pnlStatus.Controls.AddRange(new Control[] { _lblStatusBadge, _lblStatusDetails, _btnOpenBrowser, _btnStart, _btnStop, _btnRestart });
            root.Controls.Add(pnlStatus, 0, 1);

            // 3. Setup & Configuration Panel
            var pnlConfig = CreateCardPanel();
            pnlConfig.Dock = DockStyle.Fill;
            pnlConfig.Padding = new Padding(14);

            int y = 12;

            // Section 1: Admin Password
            var lblSecAdmin = CreateSectionLabel("🔑 1. Administrator Dashboard Password", y);
            pnlConfig.Controls.Add(lblSecAdmin);
            y += 26;

            var lblPass = new Label { Text = "Admin Password:", Location = new Point(16, y + 4), AutoSize = true, ForeColor = Color.FromArgb(209, 213, 219) };
            _txtAdminPass = new TextBox
            {
                Location = new Point(140, y),
                Size = new Size(200, 26),
                UseSystemPasswordChar = true,
                BackColor = Color.FromArgb(17, 24, 39),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            _chkShowPass = new CheckBox
            {
                Text = "Show",
                Location = new Point(350, y + 2),
                AutoSize = true,
                ForeColor = Color.FromArgb(156, 163, 175)
            };
            _chkShowPass.CheckedChanged += (s, e) => { _txtAdminPass.UseSystemPasswordChar = !_chkShowPass.Checked; };

            _btnApplyPass = CreateSmallButton("Save Password", 420, y, (s, e) => SaveAdminPassword());
            _btnApplyPass.Width = 120;
            pnlConfig.Controls.AddRange(new Control[] { lblPass, _txtAdminPass, _chkShowPass, _btnApplyPass });

            y += 42;

            // Section 2: Web GUI & Network Access
            var lblSecNet = CreateSectionLabel("🌐 2. Web GUI & Network Access", y);
            pnlConfig.Controls.Add(lblSecNet);
            y += 26;

            _rbLocalhost = new RadioButton
            {
                Text = "Localhost Only (127.0.0.1) — Current PC Only",
                Location = new Point(16, y),
                AutoSize = true,
                ForeColor = Color.FromArgb(209, 213, 219)
            };
            _rbNetwork = new RadioButton
            {
                Text = "Network Access (0.0.0.0) — Accessible across Local Area Network",
                Location = new Point(320, y),
                AutoSize = true,
                Checked = true,
                ForeColor = Color.FromArgb(209, 213, 219)
            };
            pnlConfig.Controls.AddRange(new Control[] { _rbLocalhost, _rbNetwork });
            y += 28;

            var lblPorts = new Label { Text = "HTTP Port:", Location = new Point(16, y + 3), AutoSize = true, ForeColor = Color.FromArgb(156, 163, 175) };
            _txtHttpPort = new TextBox { Text = "8080", Location = new Point(90, y), Size = new Size(60, 24), BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            var lblGrpc = new Label { Text = "gRPC Port:", Location = new Point(170, y + 3), AutoSize = true, ForeColor = Color.FromArgb(156, 163, 175) };
            _txtGrpcPort = new TextBox { Text = "4443", Location = new Point(245, y), Size = new Size(60, 24), BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            _lblDetectedIps = new Label
            {
                Text = "Reachable LAN URLs: Detecting...",
                Location = new Point(320, y + 3),
                AutoSize = true,
                ForeColor = Color.FromArgb(52, 211, 153),
                Font = new Font("Segoe UI", 9f, FontStyle.Bold)
            };
            pnlConfig.Controls.AddRange(new Control[] { lblPorts, _txtHttpPort, lblGrpc, _txtGrpcPort, _lblDetectedIps });

            y += 42;

            // Section 3: Storage Setup & Log Persistence
            var lblSecStorage = CreateSectionLabel("💾 3. Log & Data Storage Setup", y);
            pnlConfig.Controls.Add(lblSecStorage);
            y += 26;

            var lblStorage = new Label { Text = "Storage Path:", Location = new Point(16, y + 4), AutoSize = true, ForeColor = Color.FromArgb(209, 213, 219) };
            _txtStorageDir = new TextBox
            {
                Location = new Point(110, y),
                Size = new Size(420, 26),
                BackColor = Color.FromArgb(17, 24, 39),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            _btnBrowseStorage = CreateSmallButton("Browse...", 540, y, (s, e) => BrowseStorageFolder());
            _btnOpenExplorer = CreateSmallButton("Open Folder", 630, y, (s, e) => OpenStorageInExplorer());
            _btnOpenExplorer.Width = 100;

            pnlConfig.Controls.AddRange(new Control[] { lblStorage, _txtStorageDir, _btnBrowseStorage, _btnOpenExplorer });
            y += 36;

            _lblDiskFree = new Label
            {
                Text = "Available Disk Space: Calculating...",
                Location = new Point(110, y + 4),
                AutoSize = true,
                ForeColor = Color.FromArgb(156, 163, 175)
            };

            var lblRet = new Label { Text = "Retention:", Location = new Point(380, y + 4), AutoSize = true, ForeColor = Color.FromArgb(209, 213, 219) };
            _cmbRetention = new ComboBox
            {
                Location = new Point(450, y),
                Size = new Size(160, 26),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(17, 24, 39),
                ForeColor = Color.White
            };
            _cmbRetention.Items.AddRange(new object[] { "14 Days", "30 Days (Recommended)", "60 Days", "90 Days", "Unlimited" });
            _cmbRetention.SelectedIndex = 1;

            var btnSaveAll = new Button
            {
                Text = "💾 Save Configuration",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(180, 32),
                Location = new Point(630, y - 2),
                Cursor = Cursors.Hand
            };
            btnSaveAll.FlatAppearance.BorderSize = 0;
            btnSaveAll.Click += (s, e) => SaveAllSettings();

            pnlConfig.Controls.AddRange(new Control[] { _lblDiskFree, lblRet, _cmbRetention, btnSaveAll });
            root.Controls.Add(pnlConfig, 0, 2);

            // 4. Live Server Console Logs
            var pnlLogs = CreateCardPanel();
            pnlLogs.Dock = DockStyle.Fill;
            pnlLogs.Padding = new Padding(12);

            var lblLogHeader = new Label
            {
                Text = "📟 Live Server Console Output (Real-time telemetry & agent traffic)",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 229, 255),
                Dock = DockStyle.Top,
                Height = 24
            };

            _rtbLogs = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(6, 10, 18),
                ForeColor = Color.FromArgb(165, 243, 252),
                Font = new Font("Consolas", 9f),
                BorderStyle = BorderStyle.None,
                ReadOnly = true
            };

            pnlLogs.Controls.Add(_rtbLogs);
            pnlLogs.Controls.Add(lblLogHeader);
            root.Controls.Add(pnlLogs, 0, 3);
        }

        private Panel CreateCardPanel()
        {
            return new Panel
            {
                BackColor = Color.FromArgb(17, 24, 39), // Slate 900
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 0, 0, 12)
            };
        }

        private Label CreateSectionLabel(string text, int y)
        {
            return new Label
            {
                Text = text,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 229, 255),
                Location = new Point(14, y),
                AutoSize = true
            };
        }

        private Button CreateSmallButton(string text, int x, int y, EventHandler onClick)
        {
            var btn = new Button
            {
                Text = text,
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                BackColor = Color.FromArgb(31, 41, 55),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(70, 28),
                Location = new Point(x, y),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderColor = Color.FromArgb(55, 65, 81);
            btn.Click += onClick;
            return btn;
        }

        private void LocateFilesAndLoadConfig()
        {
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string parentDir = Directory.GetParent(appDir)?.FullName ?? appDir;
            string rootDir = Directory.GetParent(parentDir)?.FullName ?? parentDir;

            string[] exeCandidates = new[]
            {
                Path.Combine(appDir, "eg-server.exe"),
                Path.Combine(parentDir, "server", "eg-server.exe"),
                Path.Combine(rootDir, "server", "eg-server.exe"),
                @"C:\Program Files\EndpointGuard\eg-server.exe"
            };

            foreach (var c in exeCandidates)
            {
                if (File.Exists(c))
                {
                    _serverExePath = c;
                    break;
                }
            }

            string[] configCandidates = new[]
            {
                Path.Combine(appDir, "config.json"),
                Path.Combine(parentDir, "server", "config.json"),
                Path.Combine(rootDir, "server", "config.json"),
                @"C:\ProgramData\EndpointGuard\config.json"
            };

            foreach (var c in configCandidates)
            {
                if (File.Exists(c))
                {
                    _configPath = c;
                    break;
                }
            }

            if (string.IsNullOrEmpty(_configPath))
            {
                _configPath = Path.Combine(appDir, "config.json");
            }

            LoadConfigFromFile();
            PopulateConfigUI();
        }

        private void LoadConfigFromFile()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    string json = File.ReadAllText(_configPath);
                    _config = JsonSerializer.Deserialize<ServerConfig>(json) ?? new ServerConfig();
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[CONFIG] Error loading {_configPath}: {ex.Message}");
            }
        }

        private void PopulateConfigUI()
        {
            _txtAdminPass.Text = _config.AdminPassword ?? "";
            _txtHttpPort.Text = string.IsNullOrEmpty(_config.HttpPort) ? "8080" : _config.HttpPort;
            _txtGrpcPort.Text = string.IsNullOrEmpty(_config.GrpcPort) ? "4443" : _config.GrpcPort;

            if (_config.ListenMode?.ToLower() == "localhost")
                _rbLocalhost.Checked = true;
            else
                _rbNetwork.Checked = true;

            string defaultStorage = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EndpointGuard", "storage");
            _txtStorageDir.Text = string.IsNullOrEmpty(_config.StorageDir) ? defaultStorage : _config.StorageDir;

            switch (_config.LogRetentionDays)
            {
                case 14: _cmbRetention.SelectedIndex = 0; break;
                case 30: _cmbRetention.SelectedIndex = 1; break;
                case 60: _cmbRetention.SelectedIndex = 2; break;
                case 90: _cmbRetention.SelectedIndex = 3; break;
                case 0: _cmbRetention.SelectedIndex = 4; break;
                default: _cmbRetention.SelectedIndex = 1; break;
            }

            DisplayDetectedIps();
        }

        private void DisplayDetectedIps()
        {
            var ips = new System.Collections.Generic.List<string>();
            try
            {
                foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                    {
                        ips.Add(ip.ToString());
                    }
                }
            }
            catch { }

            string port = _txtHttpPort.Text.Trim();
            if (ips.Count > 0)
            {
                var sb = new StringBuilder();
                foreach (var ip in ips)
                {
                    sb.Append($"http://{ip}:{port}  ");
                }
                _lblDetectedIps.Text = $"LAN: {sb.ToString().Trim()}";
            }
            else
            {
                _lblDetectedIps.Text = $"LAN: http://localhost:{port}";
            }
        }

        private void RefreshDiskSpace()
        {
            try
            {
                string dir = _txtStorageDir.Text.Trim();
                if (string.IsNullOrEmpty(dir)) return;
                string root = Path.GetPathRoot(Path.GetFullPath(dir)) ?? "C:\\";
                var drive = new DriveInfo(root);
                if (drive.IsReady)
                {
                    double freeGb = drive.AvailableFreeSpace / (1024.0 * 1024 * 1024);
                    _lblDiskFree.Text = $"Drive {root}: {freeGb:F1} GB free of {drive.TotalSize / (1024.0 * 1024 * 1024):F1} GB";
                }
            }
            catch
            {
                _lblDiskFree.Text = "Drive space calculated automatically";
            }
        }

        private void StartServerProcess()
        {
            if (_serverProcess != null && !_serverProcess.HasExited)
            {
                AppendLog("[SERVER] Server is already running.");
                return;
            }

            if (!File.Exists(_serverExePath))
            {
                AppendLog($"[ERROR] eg-server.exe binary not found at {_serverExePath}");
                _lblStatusBadge.Text = "● SERVER NOT FOUND";
                _lblStatusBadge.ForeColor = Color.FromArgb(244, 63, 94);
                return;
            }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = _serverExePath,
                    Arguments = $"-config \"{_configPath}\"",
                    WorkingDirectory = Path.GetDirectoryName(_serverExePath) ?? "",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                _serverProcess = new Process { StartInfo = psi, EnableRaisingEvents = true };
                _serverProcess.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) AppendLog(e.Data); };
                _serverProcess.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) AppendLog(e.Data); };
                _serverProcess.Exited += (s, e) =>
                {
                    this.BeginInvoke((Action)(() =>
                    {
                        _lblStatusBadge.Text = "● SERVER STOPPED";
                        _lblStatusBadge.ForeColor = Color.FromArgb(244, 63, 94);
                    }));
                };

                _serverProcess.Start();
                _serverProcess.BeginOutputReadLine();
                _serverProcess.BeginErrorReadLine();

                _lblStatusBadge.Text = $"● SERVER RUNNING (PID: {_serverProcess.Id})";
                _lblStatusBadge.ForeColor = Color.FromArgb(16, 185, 129);
                _lblStatusDetails.Text = $"HTTP: http://localhost:{_txtHttpPort.Text} | gRPC: :{_txtGrpcPort.Text} | Bound: {(_rbLocalhost.Checked ? "127.0.0.1" : "0.0.0.0")}";

                AppendLog($"[SERVER] Started eg-server.exe (PID: {_serverProcess.Id}) using config: {_configPath}");
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Failed to launch server: {ex.Message}");
                _lblStatusBadge.Text = "● START FAILED";
                _lblStatusBadge.ForeColor = Color.FromArgb(244, 63, 94);
            }
        }

        private void StopServerProcess()
        {
            if (_serverProcess != null && !_serverProcess.HasExited)
            {
                try
                {
                    _serverProcess.Kill();
                    _serverProcess.WaitForExit(3000);
                    AppendLog("[SERVER] Server process stopped.");
                }
                catch (Exception ex)
                {
                    AppendLog($"[ERROR] Stop server: {ex.Message}");
                }
            }
            _lblStatusBadge.Text = "● SERVER STOPPED";
            _lblStatusBadge.ForeColor = Color.FromArgb(244, 63, 94);
        }

        private void RestartServerProcess()
        {
            StopServerProcess();
            System.Threading.Thread.Sleep(800);
            StartServerProcess();
        }

        private void OpenDashboardInBrowser()
        {
            string port = _txtHttpPort.Text.Trim();
            if (string.IsNullOrEmpty(port)) port = "8080";
            string url = $"http://localhost:{port}";
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not launch browser: {ex.Message}\nPlease open {url} manually.", "Open Dashboard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void BrowseStorageFolder()
        {
            using var dlg = new FolderBrowserDialog();
            dlg.Description = "Select Storage Directory for EndpointGuard Logs & Data";
            if (Directory.Exists(_txtStorageDir.Text.Trim()))
            {
                dlg.SelectedPath = _txtStorageDir.Text.Trim();
            }
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                _txtStorageDir.Text = dlg.SelectedPath;
                RefreshDiskSpace();
            }
        }

        private void OpenStorageInExplorer()
        {
            string dir = _txtStorageDir.Text.Trim();
            try
            {
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open directory: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SaveAdminPassword()
        {
            string newPass = _txtAdminPass.Text.Trim();
            if (string.IsNullOrEmpty(newPass))
            {
                MessageBox.Show("Please enter a valid password.", "Validation", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _config.AdminPassword = newPass;
            SaveConfigToFile();

            // Also send to live running server API
            _ = UpdatePasswordViaHttp(newPass);

            MessageBox.Show("Admin password saved successfully!", "Security Updated", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private async System.Threading.Tasks.Task UpdatePasswordViaHttp(string password)
        {
            try
            {
                using var client = new HttpClient();
                string url = $"http://localhost:{_txtHttpPort.Text.Trim()}/api/admin/set-password";
                var content = new StringContent(JsonSerializer.Serialize(new { password }), Encoding.UTF8, "application/json");
                await client.PostAsync(url, content);
            }
            catch { }
        }

        private void SaveAllSettings()
        {
            _config.AdminPassword = _txtAdminPass.Text.Trim();
            _config.ListenMode = _rbLocalhost.Checked ? "localhost" : "network";
            _config.HttpPort = _txtHttpPort.Text.Trim();
            _config.GrpcPort = _txtGrpcPort.Text.Trim();
            _config.StorageDir = _txtStorageDir.Text.Trim();

            int retention = 30;
            switch (_cmbRetention.SelectedIndex)
            {
                case 0: retention = 14; break;
                case 1: retention = 30; break;
                case 2: retention = 60; break;
                case 3: retention = 90; break;
                case 4: retention = 0; break;
            }
            _config.LogRetentionDays = retention;

            SaveConfigToFile();
            RefreshDiskSpace();
            DisplayDetectedIps();

            var res = MessageBox.Show("Configuration saved! Would you like to restart the server now to apply network changes?", "Settings Saved", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (res == DialogResult.Yes)
            {
                RestartServerProcess();
            }
        }

        private void SaveConfigToFile()
        {
            try
            {
                string dir = Path.GetDirectoryName(_configPath) ?? "";
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                string json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_configPath, json);
                AppendLog($"[CONFIG] Saved configuration to {_configPath}");
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Save config failed: {ex.Message}");
            }
        }

        private void AppendLog(string message)
        {
            if (this.IsDisposed || !this.IsHandleCreated) return;
            this.BeginInvoke((Action)(() =>
            {
                string line = $"[{DateTime.Now:HH:mm:ss}] {message}\n";
                _rtbLogs.AppendText(line);
                if (_rtbLogs.TextLength > 50000)
                {
                    _rtbLogs.Select(0, 10000);
                    _rtbLogs.SelectedText = "";
                }
                _rtbLogs.SelectionStart = _rtbLogs.TextLength;
                _rtbLogs.ScrollToCaret();
            }));
        }

        private void ExitApplication()
        {
            StopServerProcess();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            Application.Exit();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                var res = MessageBox.Show("Do you want to minimize EndpointGuard Server to the system tray?\n\nClick 'Yes' to keep the server running in background,\nor 'No' to shut down the server.", "EndpointGuard Server", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (res == DialogResult.Yes)
                {
                    e.Cancel = true;
                    this.Hide();
                    _trayIcon.ShowBalloonTip(2000, "EndpointGuard Server", "Server is still running in the background.", ToolTipIcon.Info);
                    return;
                }
                else if (res == DialogResult.Cancel)
                {
                    e.Cancel = true;
                    return;
                }
            }

            StopServerProcess();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            base.OnFormClosing(e);
        }
    }

    public class ServerConfig
    {
        public string? ListenMode { get; set; } = "network";
        public string? HttpPort { get; set; } = "8080";
        public string? GrpcPort { get; set; } = "4443";
        public string? StorageDir { get; set; }
        public int LogRetentionDays { get; set; } = 30;
        public string? AdminPassword { get; set; }
        public string? ClickHouseDsn { get; set; }
        public string? PostgresDsn { get; set; }
        public string? TlsCertFile { get; set; }
        public string? TlsKeyFile { get; set; }
        public string? ClientCaFile { get; set; }
    }
}
