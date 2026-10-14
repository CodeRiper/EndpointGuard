using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace EndpointGuardInstaller
{
    public partial class Form1 : Form
    {
        private TextBox _txtInstallPath = null!;
        private TextBox _txtStoragePath = null!;
        private CheckBox _chkDesktopShortcut = null!;
        private CheckBox _chkStartMenu = null!;
        private CheckBox _chkFirewall = null!;
        private CheckBox _chkLaunchAfter = null!;
        private ProgressBar _progressBar = null!;
        private Label _lblStatus = null!;
        private Button _btnInstall = null!;

        public Form1()
        {
            InitializeComponentCustom();
        }

        private void InitializeComponentCustom()
        {
            this.Text = "EndpointGuard Enterprise Server — Setup Wizard";
            this.Size = new Size(640, 560);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.BackColor = Color.FromArgb(11, 15, 25); // Slate 950
            this.ForeColor = Color.FromArgb(243, 244, 246);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            int y = 20;

            // Header Banner
            var lblLogo = new Label
            {
                Text = "🛡️ EndpointGuard Server Setup",
                Font = new Font("Segoe UI", 16f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 229, 255),
                Location = new Point(24, y),
                AutoSize = true
            };
            this.Controls.Add(lblLogo);
            y += 34;

            var lblSubtitle = new Label
            {
                Text = "Installs the control server, agent mTLS tunnel, and desktop control center.",
                Font = new Font("Segoe UI", 9.5f),
                ForeColor = Color.FromArgb(156, 163, 175),
                Location = new Point(26, y),
                AutoSize = true
            };
            this.Controls.Add(lblSubtitle);
            y += 40;

            // Divider
            var pnlDiv = new Panel
            {
                Height = 1,
                Width = 574,
                Location = new Point(24, y),
                BackColor = Color.FromArgb(31, 41, 55)
            };
            this.Controls.Add(pnlDiv);
            y += 18;

            // Install Directory
            var lblInstall = new Label
            {
                Text = "Installation Directory:",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(24, y),
                AutoSize = true
            };
            this.Controls.Add(lblInstall);
            y += 24;

            string defaultInstall = @"C:\Program Files\EndpointGuard";
            if (!HasAdminPrivileges())
            {
                defaultInstall = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EndpointGuard");
            }

            _txtInstallPath = new TextBox
            {
                Text = defaultInstall,
                Location = new Point(26, y),
                Size = new Size(470, 26),
                BackColor = Color.FromArgb(17, 24, 39),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            var btnBrowseInstall = CreateButton("Browse...", 504, y - 1, 94, 28, (s, e) => BrowseFolder(_txtInstallPath));
            this.Controls.AddRange(new Control[] { _txtInstallPath, btnBrowseInstall });
            y += 40;

            // Storage Directory
            var lblStorage = new Label
            {
                Text = "Log & Telemetry Storage Directory:",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(24, y),
                AutoSize = true
            };
            this.Controls.Add(lblStorage);
            y += 24;

            string defaultStorage = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EndpointGuard", "storage");
            _txtStoragePath = new TextBox
            {
                Text = defaultStorage,
                Location = new Point(26, y),
                Size = new Size(470, 26),
                BackColor = Color.FromArgb(17, 24, 39),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            var btnBrowseStorage = CreateButton("Browse...", 504, y - 1, 94, 28, (s, e) => BrowseFolder(_txtStoragePath));
            this.Controls.AddRange(new Control[] { _txtStoragePath, btnBrowseStorage });
            y += 44;

            // Options Checkboxes
            _chkDesktopShortcut = CreateCheckBox("Create Desktop Shortcut for EndpointGuard Server", 26, y, true);
            this.Controls.Add(_chkDesktopShortcut);
            y += 28;

            _chkStartMenu = CreateCheckBox("Create Start Menu Program Shortcut", 26, y, true);
            this.Controls.Add(_chkStartMenu);
            y += 28;

            _chkFirewall = CreateCheckBox("Configure Windows Firewall Rules (Port 8080 & 4443)", 26, y, true);
            this.Controls.Add(_chkFirewall);
            y += 28;

            _chkLaunchAfter = CreateCheckBox("Open EndpointGuard Server Application after installation", 26, y, true);
            this.Controls.Add(_chkLaunchAfter);
            y += 36;

            // Progress Bar & Status
            _progressBar = new ProgressBar
            {
                Location = new Point(26, y),
                Size = new Size(572, 14),
                Style = ProgressBarStyle.Continuous,
                Value = 0
            };
            this.Controls.Add(_progressBar);
            y += 22;

            _lblStatus = new Label
            {
                Text = "Ready to install. Click Install to begin setup.",
                Font = new Font("Segoe UI", 9f),
                ForeColor = Color.FromArgb(156, 163, 175),
                Location = new Point(26, y),
                AutoSize = true
            };
            this.Controls.Add(_lblStatus);
            y += 36;

            // Install Button
            _btnInstall = new Button
            {
                Text = "📦 Install EndpointGuard Server",
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                BackColor = Color.FromArgb(2, 132, 199),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(572, 42),
                Location = new Point(26, y),
                Cursor = Cursors.Hand
            };
            _btnInstall.FlatAppearance.BorderSize = 0;
            _btnInstall.Click += (s, e) => PerformInstallation();
            this.Controls.Add(_btnInstall);
        }

        private CheckBox CreateCheckBox(string text, int x, int y, bool isChecked)
        {
            return new CheckBox
            {
                Text = text,
                Location = new Point(x, y),
                AutoSize = true,
                Checked = isChecked,
                ForeColor = Color.FromArgb(209, 213, 219)
            };
        }

        private Button CreateButton(string text, int x, int y, int w, int h, EventHandler onClick)
        {
            var btn = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, h),
                BackColor = Color.FromArgb(31, 41, 55),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderColor = Color.FromArgb(55, 65, 81);
            btn.Click += onClick;
            return btn;
        }

        private void BrowseFolder(TextBox target)
        {
            using var dlg = new FolderBrowserDialog();
            if (Directory.Exists(target.Text)) dlg.SelectedPath = target.Text;
            if (dlg.ShowDialog() == DialogResult.OK) target.Text = dlg.SelectedPath;
        }

        private bool HasAdminPrivileges()
        {
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(id);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private async void PerformInstallation()
        {
            _btnInstall.Enabled = false;
            _btnInstall.Text = "⏳ Installing...";

            string targetDir = _txtInstallPath.Text.Trim();
            string storageDir = _txtStoragePath.Text.Trim();

            try
            {
                UpdateProgress(15, "Creating destination folders...");
                Directory.CreateDirectory(targetDir);
                Directory.CreateDirectory(storageDir);
                Directory.CreateDirectory(Path.Combine(storageDir, "logs"));
                Directory.CreateDirectory(Path.Combine(storageDir, "audit"));
                Directory.CreateDirectory(Path.Combine(storageDir, "telemetry"));

                string sourceDir = AppDomain.CurrentDomain.BaseDirectory;
                string parentDir = Directory.GetParent(sourceDir)?.FullName ?? sourceDir;
                string rootDir = Directory.GetParent(parentDir)?.FullName ?? parentDir;

                UpdateProgress(35, "Deploying core server binaries...");
                CopyFileIfFound(new[] { Path.Combine(sourceDir, "eg-server.exe"), Path.Combine(parentDir, "server", "eg-server.exe"), Path.Combine(rootDir, "server", "eg-server.exe") }, Path.Combine(targetDir, "eg-server.exe"));
                CopyFileIfFound(new[] { Path.Combine(sourceDir, "EndpointGuardServer.exe"), Path.Combine(sourceDir, "EndpointGuardServerApp.exe"), Path.Combine(parentDir, "server", "EndpointGuardServer.exe"), Path.Combine(rootDir, "server", "EndpointGuardServer.exe") }, Path.Combine(targetDir, "EndpointGuardServer.exe"));

                UpdateProgress(55, "Deploying certificates and default config...");
                string certDest = Path.Combine(targetDir, "certs");
                Directory.CreateDirectory(certDest);
                string[] certCandidates = new[] { Path.Combine(sourceDir, "certs"), Path.Combine(parentDir, "certs"), Path.Combine(rootDir, "certs") };
                foreach (var cd in certCandidates)
                {
                    if (Directory.Exists(cd))
                    {
                        foreach (var f in Directory.GetFiles(cd))
                        {
                            File.Copy(f, Path.Combine(certDest, Path.GetFileName(f)), true);
                        }
                        break;
                    }
                }

                // Write config.json
                string configPath = Path.Combine(targetDir, "config.json");
                string configJson = @"{
  ""listen_mode"": ""network"",
  ""http_port"": ""8080"",
  ""grpc_port"": ""4443"",
  ""storage_dir"": """ + storageDir.Replace("\\", "\\\\") + @""",
  ""log_retention_days"": 30,
  ""clickhouse_dsn"": ""clickhouse://localhost:9000/endpointguard"",
  ""postgres_dsn"": ""postgres://eg:eg@localhost:5432/endpointguard"",
  ""tls_cert_file"": ""certs/server.crt"",
  ""tls_key_file"": ""certs/server.key"",
  ""client_ca_file"": ""certs/client-ca.crt""
}";
                File.WriteAllText(configPath, configJson);

                UpdateProgress(75, "Creating shortcuts...");
                string exeTarget = Path.Combine(targetDir, "EndpointGuardServer.exe");

                if (_chkDesktopShortcut.Checked)
                {
                    string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                    CreateShortcut(Path.Combine(desktop, "EndpointGuard Server.lnk"), exeTarget, "EndpointGuard Server Control Center");
                }

                if (_chkStartMenu.Checked)
                {
                    string startMenu = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "EndpointGuard");
                    Directory.CreateDirectory(startMenu);
                    CreateShortcut(Path.Combine(startMenu, "EndpointGuard Server.lnk"), exeTarget, "EndpointGuard Server Control Center");
                }

                if (_chkFirewall.Checked && HasAdminPrivileges())
                {
                    UpdateProgress(90, "Configuring Windows Firewall...");
                    try
                    {
                        Process.Start(new ProcessStartInfo("netsh", "advfirewall firewall add rule name=\"EndpointGuard Web Dashboard\" dir=in action=allow protocol=TCP localport=8080") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit(2000);
                        Process.Start(new ProcessStartInfo("netsh", "advfirewall firewall add rule name=\"EndpointGuard Agent Tunnel\" dir=in action=allow protocol=TCP localport=4443") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit(2000);
                    }
                    catch { }
                }

                UpdateProgress(100, "Installation complete!");
                await System.Threading.Tasks.Task.Delay(500);

                if (_chkLaunchAfter.Checked && File.Exists(exeTarget))
                {
                    Process.Start(new ProcessStartInfo(exeTarget) { UseShellExecute = true });
                }

                MessageBox.Show("EndpointGuard Server has been installed successfully!\n\nThe control center will now launch so you can set your administrator password and start managing endpoints.", "Installation Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Installation failed: {ex.Message}", "Installation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                _btnInstall.Enabled = true;
                _btnInstall.Text = "📦 Install EndpointGuard Server";
            }
        }

        private void UpdateProgress(int pct, string status)
        {
            _progressBar.Value = pct;
            _lblStatus.Text = status;
            Application.DoEvents();
        }

        private void CopyFileIfFound(string[] sources, string dest)
        {
            foreach (var s in sources)
            {
                if (File.Exists(s))
                {
                    File.Copy(s, dest, true);
                    return;
                }
            }
        }

        private void CreateShortcut(string shortcutPath, string targetPath, string description)
        {
            try
            {
                Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType != null)
                {
                    dynamic? shell = Activator.CreateInstance(shellType);
                    if (shell != null)
                    {
                        dynamic shortcut = shell.CreateShortcut(shortcutPath);
                        shortcut.TargetPath = targetPath;
                        shortcut.WorkingDirectory = Path.GetDirectoryName(targetPath);
                        shortcut.Description = description;
                        shortcut.Save();
                    }
                }
            }
            catch { }
        }
    }
}
