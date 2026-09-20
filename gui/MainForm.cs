using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NroDecrypt.Gui
{
    static class Startup
    {
        [STAThread]
        static void Main()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.Run(new MainForm());
        }
    }

    /// <summary>Line-buffered TextWriter that appends to a TextBox on the UI thread.</summary>
    sealed class LogWriter : TextWriter
    {
        readonly TextBox box;
        readonly StringBuilder line = new StringBuilder();

        public LogWriter(TextBox box) { this.box = box; }
        public override Encoding Encoding { get { return Encoding.UTF8; } }

        public override void Write(char c)
        {
            lock (line)
            {
                line.Append(c);
                if (c == '\n') FlushLine();
            }
        }

        public override void Flush() { lock (line) FlushLine(); }

        void FlushLine()
        {
            if (line.Length == 0) return;
            string s = line.ToString();
            line.Clear();
            box.BeginInvoke(new Action(() => box.AppendText(s)));
        }
    }

    sealed class MainForm : Form
    {
        readonly TextBox path = new TextBox();
        readonly Button browse = new Button();
        readonly Button go = new Button();
        readonly TextBox log = new TextBox();
        readonly ProgressBar bar = new ProgressBar();
        readonly Label status = new Label();

        public MainForm()
        {
            Text = "NRO decrypt";
            AutoScaleDimensions = new SizeF(96f, 96f);
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(700, 600);
            MinimumSize = new Size(480, 300);
            AllowDrop = true;
            DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            DragDrop += (s, e) =>
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0) path.Text = files[0];
            };

            path.Dock = DockStyle.Fill;
            path.Margin = new Padding(0, 4, 8, 0);
            browse.Text = "Browse...";
            browse.AutoSize = true;
            browse.MinimumSize = new Size(90, 30);
            browse.Margin = new Padding(0, 0, 8, 0);
            browse.Click += OnBrowse;
            go.Text = "Decrypt";
            go.AutoSize = true;
            go.MinimumSize = new Size(90, 30);
            go.Margin = new Padding(0);
            go.Click += OnDecrypt;

            log.Dock = DockStyle.Fill;
            log.Margin = new Padding(0, 10, 0, 10);
            log.Multiline = true;
            log.ReadOnly = true;
            log.ScrollBars = ScrollBars.Vertical;
            log.Font = new Font(FontFamily.GenericMonospace, 9f);
            log.BackColor = SystemColors.Window;
            log.Text = string.Join("\r\n", new[]
            {
                "Intended for NightmareRO.",
                "",
                "Please use responsibly. This is a great server and I have the utmost respect for TwilightsCall, but there are some annoying quirks that can be tailored to the player's preferences here. IMO, GRF edits should be bannable so everyone is on the same playing field, but as they are allowed here and other players are gatekeeping how to do this, this tool exists to decrypt an encrypted GRF and names it <file>_decrypted.grf.",
                "",
                "From here, you can name the original file \"<file>_orig.grf\" or something and name the decrypted file the original file name.",
                "",
                "Note: if TwilightsCall decides to start doing checksum verification on GRFs and action on them when they differ, you could get in trouble!",
            });

            bar.Style = ProgressBarStyle.Marquee;
            bar.MarqueeAnimationSpeed = 0;
            bar.Size = new Size(150, 20);
            bar.Anchor = AnchorStyles.Left;
            bar.Margin = new Padding(0, 0, 12, 0);
            status.AutoSize = true;
            status.Anchor = AnchorStyles.Left;
            status.Margin = new Padding(0);
            status.Text = "Select an encrypted .grf (or drop one here).";

            var top = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3, RowCount = 1, Margin = new Padding(0) };
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.Controls.Add(path, 0, 0);
            top.Controls.Add(browse, 1, 0);
            top.Controls.Add(go, 2, 0);

            var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2, RowCount = 1, Margin = new Padding(0) };
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            bottom.Controls.Add(bar, 0, 0);
            bottom.Controls.Add(status, 1, 0);

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 3 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(top, 0, 0);
            root.Controls.Add(log, 0, 1);
            root.Controls.Add(bottom, 0, 2);
            Controls.Add(root);
            AcceptButton = go;
        }

        void OnBrowse(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Title = "Select encrypted GRF";
                dlg.Filter = "GRF archives (*.grf)|*.grf|All files (*.*)|*.*";
                if (path.Text.Length > 0)
                {
                    try { dlg.InitialDirectory = Path.GetDirectoryName(Path.GetFullPath(path.Text)); } catch { }
                }
                if (dlg.ShowDialog(this) == DialogResult.OK) path.Text = dlg.FileName;
            }
        }

        void SetBusy(bool busy)
        {
            go.Enabled = browse.Enabled = path.Enabled = !busy;
            bar.MarqueeAnimationSpeed = busy ? 30 : 0;
        }

        async void OnDecrypt(object sender, EventArgs e)
        {
            string input = path.Text.Trim().Trim('"');
            if (!File.Exists(input))
            {
                MessageBox.Show(this, "No such file:\n" + input, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            input = Path.GetFullPath(input);

            // same name the engine picks by default: <name>_decrypted<ext>, beside the source
            string output = Path.Combine(Path.GetDirectoryName(input),
                Path.GetFileNameWithoutExtension(input) + "_decrypted" + Path.GetExtension(input));
            bool force = false;
            if (File.Exists(output))
            {
                var r = MessageBox.Show(this, Path.GetFileName(output) + " already exists. Overwrite it?",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                if (r != DialogResult.Yes) return;
                force = true;
            }

            log.Clear();
            status.Text = "Decrypting " + Path.GetFileName(input) + "...";
            SetBusy(true);

            var writer = new LogWriter(log);
            var oldOut = Console.Out;
            var oldErr = Console.Error;
            Console.SetOut(writer);
            Console.SetError(writer);

            int code;
            string error = null;
            try
            {
                code = await Task.Run(() => Program.Run(force ? new[] { input, "-f" } : new[] { input }));
            }
            catch (Exception ex) { code = 1; error = ex.Message; }
            finally
            {
                writer.Flush();
                Console.SetOut(oldOut);
                Console.SetError(oldErr);
            }

            SetBusy(false);
            if (error != null)
            {
                log.AppendText("error: " + error + "\r\n");
                status.Text = "Failed.";
            }
            else if (code != 0) status.Text = "Finished with problems (exit code " + code + "). See log.";
            else if (log.Text.Contains("nothing to do")) status.Text = "Nothing to do: archive is not encrypted.";
            else status.Text = "Done -> " + Path.GetFileName(output);
        }
    }
}
