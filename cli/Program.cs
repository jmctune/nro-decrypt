using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NroDecrypt
{
    static class Program
    {
        const string EncMarker = "__encryption.info";

        static int Main(string[] argv)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            try { return Run(argv); }
            catch (Exception ex) { Err(ex.Message); return 1; }
        }

        static void Err(string m) { Console.Error.WriteLine("error: " + m); }

        internal static int Run(string[] argv)
        {
            if (argv.Length == 0 || argv[0] == "-h" || argv[0] == "--help") { Usage(); return 0; }

            // A leading known verb selects the command; anything else (a path, a
            // wildcard, an option) means the default: decrypt.
            string[] verbs = { "decrypt", "extract", "verify", "key" };
            var rest = new List<string>(argv);
            string cmd = "decrypt";
            if (Array.IndexOf(verbs, argv[0].ToLowerInvariant()) >= 0)
            {
                cmd = argv[0].ToLowerInvariant();
                rest.RemoveAt(0);
            }

            string output = null, dll = null;
            int codepage = 1252;
            bool force = false, keepInfo = false, flat = false;
            var pos = new List<string>();
            var only = new List<string>();

            for (int i = 0; i < rest.Count; i++)
            {
                string a = rest[i];
                switch (a)
                {
                    case "-o": case "--out": output = rest[++i]; break;
                    case "-k": case "--dll": dll = rest[++i]; break;
                    case "-c": case "--codepage": codepage = int.Parse(rest[++i]); break;
                    case "-f": case "--force": force = true; break;
                    case "--keep-info": keepInfo = true; break;
                    case "--only": only.Add(rest[++i]); break;
                    case "--list": only.AddRange(ReadList(rest[++i])); break;
                    case "--flat": flat = true; break;
                    default:
                        if (a.StartsWith("-")) throw new ArgumentException("unknown option " + a);
                        pos.Add(a);
                        break;
                }
            }

            switch (cmd)
            {
                case "decrypt":
                {
                    var ins = ExpandInputs(pos);
                    if (ins.Count == 0) throw new ArgumentException("give at least one archive path");
                    if (ins.Count > 1 && output != null)
                        throw new ArgumentException("-o cannot be combined with multiple archives");
                    return ins.Count == 1
                        ? DecryptOne(ins[0], output, dll, force, keepInfo).Code
                        : DecryptMany(ins, dll, force, keepInfo);
                }
                case "extract":
                    if (pos.Count < 2) throw new ArgumentException("give an archive and an output directory");
                    return Extract(pos[0], pos[1], dll, codepage, only, flat);
                case "verify":
                {
                    var ins = ExpandInputs(pos);
                    if (ins.Count == 0) throw new ArgumentException("give at least one archive path");
                    int worst = 0;
                    foreach (string f in ins) { int r = Verify(f, codepage); if (r > worst) worst = r; }
                    return worst;
                }
                case "key": return ShowKey(dll ?? (pos.Count > 0 ? pos[0] : null));
                default: throw new ArgumentException("unknown command '" + cmd + "' (try --help)");
            }
        }

        static void Usage()
        {
            Console.WriteLine(@"nrodecrypt - decrypt GRF archives protected by GRF Editor's client encryption

  The RC4 key is read out of the generated cps.dll (often renamed, e.g. jem.dll).
  The original encryption password is NOT stored in that DLL and cannot be
  recovered -- only the derived key is, which is all decryption needs.

USAGE
  nrodecrypt <archive.grf>... [-o out.grf] [-k cps.dll] [-f]
  nrodecrypt decrypt <archive.grf>... [-o out.grf] [-k cps.dll] [-f]
  nrodecrypt extract <archive.grf> <outdir>  [-k cps.dll] [-c 1252]
                     [--only <grf\path>]... [--list <file>] [--flat]
  nrodecrypt verify  <archive.grf>... [-c 1252]
  nrodecrypt key     [cps.dll]

  decrypt and verify accept several archives, and expand * / ? themselves
  (cmd.exe does not glob). Wildcard matches skip existing *_decrypted.grf
  outputs, so 'nrodecrypt *.grf' is safe to re-run. Archives that turn out
  not to be encrypted are reported and skipped rather than failing.
  -o applies only when a single archive is given.

OPTIONS
  -o, --out <path>       output archive (default: <name>_decrypted.grf)
  -k, --dll <path>       cps.dll holding the key. If omitted, every *.dll and
                         *.exe next to the archive is probed automatically.
  -c, --codepage <n>     filename codepage (default 1252; use 949 for Korean)
  -f, --force            overwrite an existing output file
      --only <path>      extract just this GRF path (repeatable). Matching is
                         case-insensitive and / == \. Paths not present in the
                         archive are listed at the end and set exit code 2;
                         the ones that do match are still extracted.
      --list <file>      read paths from a file, one per line (# comments and
                         leading '- ' bullets are ignored)
      --flat             write basenames into outdir, no directory tree
      --keep-info        keep the __encryption.info marker (default: dropped,
                         since its presence makes GRF Editor prompt for a key)

NOTES
  decrypt  rebuilds the archive with every entry decrypted in place, preserving
           the original signature, version, table-header layout and record size.
  verify   re-opens an archive and inflates every entry, asserting that the
           record count matches the header and the table ends exactly at EOF.");
        }

        // ---------- key loading ----------

        /// <summary>
        /// Collect a handful of genuinely-encrypted entries. A candidate key must
        /// turn these into inflatable zlib streams of the declared size -- deriving
        /// a valid permutation is not on its own evidence of the right key.
        /// </summary>
        static List<byte[][]> SampleCipherBlocks(Archive a, string path, int want)
        {
            var samples = new List<byte[][]>();
            using (var fs = File.OpenRead(path))
            {
                foreach (var e in a.Entries)
                {
                    if (samples.Count >= want) break;
                    if (!e.IsFile || e.CLen < 16 || e.CLen > 262144) continue;
                    var d = new byte[e.CLen];
                    fs.Position = (long)e.Offset + Archive.HeaderSize;
                    if (fs.Read(d, 0, (int)e.CLen) != e.CLen) continue;
                    if (InflatesTo(d, (int)e.CLen, e.RLen)) continue; // plaintext proves nothing
                    samples.Add(new[] { d, BitConverter.GetBytes(e.RLen) });
                }
            }
            return samples;
        }

        static bool Validates(GrfKey k, List<byte[][]> samples)
        {
            if (samples.Count == 0) return false;
            foreach (var s in samples)
            {
                var d = (byte[])s[0].Clone();
                uint rlen = BitConverter.ToUInt32(s[1], 0);
                k.Apply(d, d.Length, (int)rlen);
                if (!InflatesTo(d, d.Length, rlen)) return false;
            }
            return true;
        }

        /// <summary>Expand wildcards (cmd.exe does not glob) and drop our own outputs.</summary>
        static List<string> ExpandInputs(List<string> pos)
        {
            var hits = new List<string>();
            foreach (string p in pos)
            {
                if (p.IndexOf('*') < 0 && p.IndexOf('?') < 0) { hits.Add(p); continue; }
                string dir = Path.GetDirectoryName(p);
                if (string.IsNullOrEmpty(dir)) dir = ".";
                var found = Directory.GetFiles(dir, Path.GetFileName(p));
                Array.Sort(found, StringComparer.OrdinalIgnoreCase);
                foreach (string f in found)
                    if (!Path.GetFileNameWithoutExtension(f).EndsWith("_decrypted", StringComparison.OrdinalIgnoreCase))
                        hits.Add(f);
            }
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var final = new List<string>();
            foreach (string f in hits)
                if (seen.Add(Path.GetFullPath(f))) final.Add(f);
            return final;
        }

        static GrfKey LoadKey(string dllPath, List<byte[][]> samples, string archivePath)
        {
            if (dllPath != null)
            {
                if (!File.Exists(dllPath)) throw new FileNotFoundException("no such file: " + dllPath);
                var k = PickValidated(File.ReadAllBytes(dllPath), samples, true);
                if (k == null) throw new InvalidDataException(
                    "no key in " + dllPath + " decrypts this archive");
                Report(dllPath, k, false);
                return k;
            }

            string dir = Path.GetDirectoryName(Path.GetFullPath(archivePath));
            var files = new List<string>();
            files.AddRange(Directory.GetFiles(dir, "*.dll"));
            files.AddRange(Directory.GetFiles(dir, "*.exe"));

            // Cheap pass over every binary first, exhaustive scan only if that fails.
            foreach (bool scan in new[] { false, true })
            {
                foreach (string f in files)
                {
                    byte[] b;
                    try { b = File.ReadAllBytes(f); } catch { continue; }
                    if (b.Length < 300 || b.Length > 64 * 1024 * 1024) continue;
                    var k = PickValidated(b, samples, scan);
                    if (k != null) { Report(f, k, true); return k; }
                }
            }
            throw new InvalidDataException("no .dll/.exe beside the archive yielded a working key; pass -k explicitly");
        }

        static GrfKey PickValidated(byte[] bin, List<byte[][]> samples, bool scan)
        {
            foreach (var k in GrfKey.Candidates(bin, scan))
                if (Validates(k, samples)) return k;
            return null;
        }

        static void Report(string file, GrfKey k, bool auto)
        {
            Console.WriteLine("key    : " + Path.GetFileName(file) + " @0x" + k.FileOffset.ToString("X")
                + "  seed=0x" + k.Seed.ToString("X8")
                + "  (" + (auto ? "auto-detected, " : "") + k.FoundBy
                + ", validated on 5 entries)");
        }

        static int ShowKey(string dllPath)
        {
            if (dllPath == null) throw new ArgumentException("give a cps.dll path");
            GrfKey k = null;
            foreach (var c in GrfKey.Candidates(File.ReadAllBytes(dllPath), true)) { k = c; break; }
            if (k == null) { Err("no valid key found in " + dllPath); return 1; }
            if (k.FoundBy != "code pattern")
                Console.WriteLine("note        : found by scan, NOT validated against an archive -- "
                    + "run 'decrypt' or 'extract' to confirm it is the real key");
            Console.WriteLine("file        : " + dllPath);
            Console.WriteLine("key offset  : 0x" + k.FileOffset.ToString("X"));
            Console.WriteLine("seed        : 0x" + k.Seed.ToString("X8"));
            Console.WriteLine("found by    : " + k.FoundBy);
            Console.WriteLine("S-box:");
            for (int r = 0; r < 16; r++)
            {
                var sb = new StringBuilder("  ");
                for (int c = 0; c < 16; c++) sb.Append(k.SBox[r * 16 + c].ToString("X2")).Append(' ');
                Console.WriteLine(sb.ToString().TrimEnd());
            }
            return 0;
        }

        // ---------- shared helpers ----------

        static void Describe(Archive a)
        {
            Console.WriteLine("archive: " + Path.GetFileName(a.Path));
            Console.WriteLine("         signature \"" + a.Signature + "\"  version " + a.MajorVersion + "." + a.MinorVersion
                + "  entries " + a.Entries.Count);
            Console.WriteLine("         table header " + a.TableHeaderSize + "B, records " + a.RecordSize
                + "B, count field " + (a.CountIsLiteral ? "literal" : "count+7"));
        }

        /// <summary>
        /// Decide whether a block is already plaintext or needs decrypting, by
        /// actually inflating it. A zlib-header check alone false-positives on
        /// roughly 1 in 500 encrypted blocks. This mirrors the DLL, which calls
        /// the real uncompress() and branches on its return code.
        /// </summary>
        static bool InflatesTo(byte[] b, int len, uint expect)
        {
            if (len < 2 || (b[0] & 0x0F) != 8 || ((b[0] << 8) | b[1]) % 31 != 0) return false;
            try { return Archive.Inflate(b, 0, len).Length == expect; }
            catch { return false; }
        }

        static string NameOf(Entry e, Encoding enc) { return enc.GetString(e.Name); }

        // ---------- decrypt ----------

        class RunResult { public int Code; public string Status; }

        static int DecryptMany(List<string> inputs, string dllPath, bool force, bool keepInfo)
        {
            var results = new List<KeyValuePair<string, RunResult>>();
            foreach (string f in inputs)
            {
                Console.WriteLine("################ " + Path.GetFileName(f) + " ################");
                RunResult r;
                try { r = DecryptOne(f, null, dllPath, force, keepInfo); }
                catch (Exception ex) { Err(ex.Message); r = new RunResult { Code = 1, Status = "error: " + ex.Message }; Console.WriteLine(); }
                results.Add(new KeyValuePair<string, RunResult>(Path.GetFileName(f), r));
            }

            int worst = 0, width = 0;
            foreach (var kv in results) if (kv.Key.Length > width) width = kv.Key.Length;
            Console.WriteLine("================ summary ================");
            foreach (var kv in results)
            {
                Console.WriteLine("  " + kv.Key.PadRight(width) + "  " + kv.Value.Status);
                if (kv.Value.Code > worst) worst = kv.Value.Code;
            }
            return worst;
        }

        static RunResult DecryptOne(string input, string output, string dllPath, bool force, bool keepInfo)
        {
            if (input == null) throw new ArgumentException("give an archive path");
            var a = Archive.Load(input);
            Describe(a);

            var samples = SampleCipherBlocks(a, input, 5);
            if (samples.Count == 0)
            {
                Console.WriteLine("         no encrypted entries -- nothing to do");
                Console.WriteLine();
                return new RunResult { Code = 0, Status = "skipped (not encrypted)" };
            }
            var key = LoadKey(dllPath, samples, input);

            if (output == null)
                output = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(input)),
                    Path.GetFileNameWithoutExtension(input) + "_decrypted" + Path.GetExtension(input));
            if (File.Exists(output) && !force)
                throw new IOException("output exists (use -f to overwrite): " + output);
            if (Path.GetFullPath(output) == Path.GetFullPath(input))
                throw new IOException("refusing to write over the source archive");

            var ascii = Encoding.ASCII;
            int dec = 0, raw = 0, dropped = 0, failed = 0, dirs = 0;
            var kept = new List<Entry>();

            using (var inp = File.OpenRead(input))
            using (var outp = new FileStream(output, FileMode.Create, FileAccess.Write))
            {
                outp.Write(new byte[Archive.HeaderSize], 0, Archive.HeaderSize);

                foreach (var e in a.Entries)
                {
                    if (!keepInfo && NameOf(e, ascii).EndsWith(EncMarker, StringComparison.OrdinalIgnoreCase))
                    { dropped++; continue; }

                    if (!e.IsFile) { e.Off = 0; e.OffHi = 0; dirs++; kept.Add(e); continue; }

                    byte[] data = new byte[e.CLen];
                    inp.Position = (long)e.Offset + Archive.HeaderSize;
                    int got = inp.Read(data, 0, (int)e.CLen);
                    if (got != e.CLen) { failed++; Console.WriteLine("  SHORT READ  " + NameOf(e, ascii)); continue; }

                    if (InflatesTo(data, got, e.RLen)) raw++;
                    else
                    {
                        var test = (byte[])data.Clone();
                        key.Apply(test, got, (int)e.RLen);
                        if (InflatesTo(test, got, e.RLen)) { data = test; dec++; }
                        else { failed++; Console.WriteLine("  UNRESOLVED  " + NameOf(e, ascii)); continue; }
                    }

                    long pos = outp.Position - Archive.HeaderSize;
                    if (pos > uint.MaxValue) throw new IOException("output exceeds 4 GB; 64-bit offsets not supported");
                    e.Off = (uint)pos; e.OffHi = 0;
                    outp.Write(data, 0, got);
                    int pad = (int)e.CAlign - got;
                    if (pad > 0) outp.Write(new byte[pad], 0, pad);
                    kept.Add(e);
                }

                a.Entries = kept;
                byte[] table = a.BuildTable();
                byte[] comp = Archive.Deflate(table);
                long tpos = outp.Position - Archive.HeaderSize;
                if (tpos > uint.MaxValue) throw new IOException("table offset exceeds 4 GB");
                a.WriteTableHeader(outp, (uint)comp.Length, (uint)table.Length);
                outp.Write(comp, 0, comp.Length);

                byte[] h = a.FinalHeader((uint)tpos, kept.Count);
                outp.Position = 0;
                outp.Write(h, 0, Archive.HeaderSize);
            }

            Console.WriteLine();
            Console.WriteLine("decrypted   : " + dec);
            Console.WriteLine("already raw : " + raw);
            Console.WriteLine("dir entries : " + dirs);
            Console.WriteLine("dropped     : " + dropped + (dropped > 0 ? "  (" + EncMarker + ")" : ""));
            Console.WriteLine("failed      : " + failed);
            Console.WriteLine("written     : " + kept.Count + " entries -> " + output);
            if (failed > 0)
            {
                Err(failed + " entries could not be resolved");
                Console.WriteLine();
                return new RunResult { Code = 2, Status = "FAILED (" + failed + " unresolved)" };
            }

            Console.WriteLine();
            Console.WriteLine("=== verifying output ===");
            int vc = Verify(output, 1252);
            Console.WriteLine();
            return new RunResult
            {
                Code = vc,
                Status = vc == 0
                    ? "ok  " + kept.Count + " entries -> " + Path.GetFileName(output)
                    : "VERIFY FAILED -> " + Path.GetFileName(output),
            };
        }

        // ---------- verify ----------

        static int Verify(string path, int codepage)
        {
            if (path == null) throw new ArgumentException("give an archive path");
            var a = Archive.Load(path);
            var enc = Encoding.GetEncoding(codepage);
            Describe(a);

            long fileLen = new FileInfo(path).Length;
            uint tblOff = BitConverter.ToUInt32(a.Header, 0x1E);
            long tblEnd;
            using (var fs = File.OpenRead(path))
            {
                fs.Position = tblOff + Archive.HeaderSize;
                byte[] th = new byte[a.TableHeaderSize];
                fs.Read(th, 0, th.Length);
                uint clen = BitConverter.ToUInt32(th, a.TableHeaderSize - 8);
                tblEnd = tblOff + Archive.HeaderSize + a.TableHeaderSize + clen;
            }
            bool fits = tblEnd == fileLen;
            Console.WriteLine("         table ends at " + tblEnd + " / file " + fileLen
                + (fits ? "   EXACT FIT" : "   *** " + (tblEnd > fileLen ? "PAST EOF" : "SHORT") + " ***"));

            int ok = 0, bad = 0, dirs = 0;
            long total = 0;
            using (var fs = File.OpenRead(path))
            {
                foreach (var e in a.Entries)
                {
                    if (!e.IsFile) { dirs++; continue; }
                    byte[] d = new byte[e.CLen];
                    fs.Position = (long)e.Offset + Archive.HeaderSize;
                    if (fs.Read(d, 0, (int)e.CLen) != e.CLen)
                    { bad++; if (bad <= 5) Console.WriteLine("  SHORT READ " + NameOf(e, enc)); continue; }
                    try
                    {
                        var inf = Archive.Inflate(d, 0, (int)e.CLen);
                        if (inf.Length != e.RLen)
                        { bad++; if (bad <= 5) Console.WriteLine("  SIZE " + NameOf(e, enc) + " got " + inf.Length + " want " + e.RLen); }
                        else { ok++; total += inf.Length; }
                    }
                    catch (Exception ex)
                    { bad++; if (bad <= 5) Console.WriteLine("  INFLATE " + NameOf(e, enc) + ": " + ex.Message); }
                }
            }

            Console.WriteLine();
            Console.WriteLine("inflated OK : " + ok);
            Console.WriteLine("failed      : " + bad);
            Console.WriteLine("dir entries : " + dirs);
            Console.WriteLine("content     : " + total.ToString("N0") + " bytes");
            bool good = bad == 0 && fits;
            Console.WriteLine(good ? "RESULT: OK" : "RESULT: PROBLEMS FOUND");
            return good ? 0 : 3;
        }

        // ---------- extract ----------

        static List<string> ReadList(string path)
        {
            var outp = new List<string>();
            foreach (string raw in File.ReadAllLines(path))
            {
                string s = raw.Trim();
                if (s.Length == 0 || s.StartsWith("#")) continue;
                // tolerate list files written as markdown-ish bullets
                if (s.StartsWith("- ")) s = s.Substring(2).Trim();
                outp.Add(s);
            }
            return outp;
        }

        static string Norm(string s) { return s.Replace('/', '\\').Trim().ToLowerInvariant(); }

        static int Extract(string input, string dir, string dllPath, int codepage, List<string> only, bool flat)
        {
            if (input == null || dir == null) throw new ArgumentException("give an archive and an output directory");
            var a = Archive.Load(input);
            var enc = Encoding.GetEncoding(codepage);
            Describe(a);
            // An already-decrypted (or never-encrypted) archive needs no key at all;
            // only look for one when there is actually ciphertext to handle.
            var samples = SampleCipherBlocks(a, input, 5);
            GrfKey key = null;
            if (samples.Count > 0) key = LoadKey(dllPath, samples, input);
            else Console.WriteLine("key    : not needed (archive is not encrypted)");
            Directory.CreateDirectory(dir);
            string root = Path.GetFullPath(dir);

            // Requested paths are matched exactly (case-insensitive, / and \ equivalent).
            // Anything not present is reported at the end -- the entries that DO match
            // are still extracted, rather than the whole run aborting.
            var wanted = new HashSet<string>();
            var unseen = new HashSet<string>();
            foreach (string w in only) { wanted.Add(Norm(w)); unseen.Add(Norm(w)); }
            if (wanted.Count > 0) Console.WriteLine("filter : " + wanted.Count + " requested path(s)");

            int ok = 0, failed = 0, skipped = 0;
            using (var inp = File.OpenRead(input))
            {
                foreach (var e in a.Entries)
                {
                    string name = NameOf(e, enc);
                    if (!e.IsFile || name.EndsWith(EncMarker, StringComparison.OrdinalIgnoreCase)) { skipped++; continue; }
                    if (wanted.Count > 0)
                    {
                        if (!wanted.Contains(Norm(name))) { skipped++; continue; }
                        unseen.Remove(Norm(name));
                    }

                    byte[] data = new byte[e.CLen];
                    inp.Position = (long)e.Offset + Archive.HeaderSize;
                    if (inp.Read(data, 0, (int)e.CLen) != e.CLen) { failed++; continue; }

                    byte[] inf = null;
                    if (InflatesTo(data, (int)e.CLen, e.RLen)) inf = Archive.Inflate(data, 0, (int)e.CLen);
                    else if (key != null)
                    {
                        key.Apply(data, (int)e.CLen, (int)e.RLen);
                        if (InflatesTo(data, (int)e.CLen, e.RLen)) inf = Archive.Inflate(data, 0, (int)e.CLen);
                    }
                    if (inf == null) { failed++; Console.WriteLine("  UNRESOLVED  " + name); continue; }

                    string rel = flat ? SafeRelative(Path.GetFileName(name.Replace('/', '\\'))) : SafeRelative(name);
                    string dest = Path.GetFullPath(Path.Combine(root, rel));
                    if (!dest.StartsWith(root, StringComparison.OrdinalIgnoreCase)) { failed++; continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(dest));
                    File.WriteAllBytes(dest, inf);
                    if (wanted.Count > 0) Console.WriteLine("  ok  " + name + "  (" + inf.Length.ToString("N0") + " B)");
                    ok++;
                }
            }
            Console.WriteLine();
            Console.WriteLine("extracted : " + ok);
            if (wanted.Count == 0) Console.WriteLine("skipped   : " + skipped);
            Console.WriteLine("failed    : " + failed);
            foreach (string m in unseen) Console.WriteLine("  NOT FOUND  " + m);
            if (unseen.Count > 0) Console.WriteLine("missing   : " + unseen.Count);
            Console.WriteLine("output    : " + root);
            return (failed > 0 || unseen.Count > 0) ? 2 : 0;
        }

        static string SafeRelative(string name)
        {
            var parts = name.Replace('/', '\\').Split('\\');
            var clean = new List<string>();
            foreach (string raw in parts)
            {
                if (raw.Length == 0 || raw == "." || raw == "..") continue;
                var sb = new StringBuilder();
                foreach (char c in raw) sb.Append(Array.IndexOf(Path.GetInvalidFileNameChars(), c) >= 0 ? '_' : c);
                clean.Add(sb.ToString().TrimEnd(' ', '.'));
            }
            return clean.Count == 0 ? "_unnamed" : string.Join("\\", clean);
        }
    }
}
