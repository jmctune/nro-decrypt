using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace NroDecrypt
{
    public sealed class Entry
    {
        public byte[] Name;
        public uint CLen, CAlign, RLen;
        public byte Flags;
        public uint Off, OffHi;
        public bool IsFile { get { return (Flags & 1) != 0 && CLen != 0; } }
        public ulong Offset { get { return Off | ((ulong)OffHi << 32); } }
    }

    /// <summary>
    /// GRF container reader/writer.
    ///
    /// Two things vary by version and are the source of most breakage, so both
    /// are probed against the actual bytes rather than assumed:
    ///
    ///   table header : v3.0 is 12 bytes (leading dword, clen, ulen)
    ///                  v2.0 is  8 bytes (clen, ulen)
    ///   entry record : v3.0 is 21 bytes (adds the high dword of a 64-bit offset)
    ///                  v2.0 is 17 bytes
    ///
    /// The header's file-count field is also inconsistent: v3.0 stores the literal
    /// count, older files store count+7. Which one applies is decided by comparing
    /// against the number of records actually present.
    /// </summary>
    public sealed class Archive
    {
        public const int HeaderSize = 0x2E;

        public byte[] Header;
        public List<Entry> Entries = new List<Entry>();
        public int TableHeaderSize;
        public int RecordSize;
        public bool CountIsLiteral;
        public string Path;

        public int MajorVersion { get { return Header[0x2B]; } }
        public int MinorVersion { get { return Header[0x2A]; } }
        public string Signature
        {
            get { return System.Text.Encoding.ASCII.GetString(Header, 0, 15).TrimEnd('\0', ' '); }
        }

        public static byte[] Inflate(byte[] z, int off, int len)
        {
            using (var ms = new MemoryStream(z, off + 2, len - 2))
            using (var ds = new DeflateStream(ms, CompressionMode.Decompress))
            using (var o = new MemoryStream())
            { ds.CopyTo(o); return o.ToArray(); }
        }

        public static byte[] Deflate(byte[] data)
        {
            byte[] raw;
            using (var ms = new MemoryStream())
            {
                using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, true)) ds.Write(data, 0, data.Length);
                raw = ms.ToArray();
            }
            uint a = 1, b = 0;
            foreach (byte x in data) { a = (a + x) % 65521; b = (b + a) % 65521; }
            uint adler = (b << 16) | a;
            byte[] o = new byte[2 + raw.Length + 4];
            o[0] = 0x78; o[1] = 0x9C;
            Buffer.BlockCopy(raw, 0, o, 2, raw.Length);
            int p = 2 + raw.Length;
            o[p] = (byte)(adler >> 24); o[p + 1] = (byte)(adler >> 16);
            o[p + 2] = (byte)(adler >> 8); o[p + 3] = (byte)adler;
            return o;
        }

        public static Archive Load(string path)
        {
            var a = new Archive();
            a.Path = path;
            long fileLen = new FileInfo(path).Length;
            using (var fs = File.OpenRead(path))
            {
                a.Header = new byte[HeaderSize];
                if (fs.Read(a.Header, 0, HeaderSize) != HeaderSize)
                    throw new InvalidDataException("file is shorter than a GRF header");

                uint tblOff = BitConverter.ToUInt32(a.Header, 0x1E);
                uint cntField = BitConverter.ToUInt32(a.Header, 0x26);
                long tblPos = (long)tblOff + HeaderSize;
                if (tblPos < 0 || tblPos + 8 > fileLen)
                    throw new InvalidDataException("file table offset 0x" + tblOff.ToString("X") + " lies outside the file");

                // --- probe table header size ---
                byte[] table = null;
                int[] order = a.MajorVersion >= 3 ? new[] { 12, 8 } : new[] { 8, 12 };
                foreach (int ths in order)
                {
                    try
                    {
                        fs.Position = tblPos;
                        byte[] th = new byte[ths];
                        if (fs.Read(th, 0, ths) != ths) continue;
                        uint clen = BitConverter.ToUInt32(th, ths - 8);
                        uint ulen = BitConverter.ToUInt32(th, ths - 4);
                        if (clen < 3 || clen > fileLen - (tblPos + ths)) continue;
                        if (ulen == 0 || ulen > 512 * 1024 * 1024) continue;
                        byte[] z = new byte[clen];
                        if (fs.Read(z, 0, (int)clen) != clen) continue;
                        byte[] t = Inflate(z, 0, (int)clen);
                        if (t.Length != ulen) continue;
                        table = t;
                        a.TableHeaderSize = ths;
                        break;
                    }
                    catch { }
                }
                if (table == null)
                    throw new InvalidDataException("could not read the file table (tried 12- and 8-byte table headers)");

                // --- probe entry record size ---
                int[] rsOrder = a.MajorVersion >= 3 ? new[] { 21, 17 } : new[] { 17, 21 };
                List<Entry> best = null;
                foreach (int rs in rsOrder)
                {
                    var list = TryParse(table, rs);
                    if (list != null) { best = list; a.RecordSize = rs; break; }
                }
                if (best == null)
                    throw new InvalidDataException("could not parse the file table (tried 21- and 17-byte records)");
                a.Entries = best;

                if (cntField == best.Count) a.CountIsLiteral = true;
                else if (cntField == best.Count + 7) a.CountIsLiteral = false;
                else
                    throw new InvalidDataException("header file count " + cntField +
                        " matches neither the record count (" + best.Count + ") nor count+7");
            }
            return a;
        }

        /// <summary>Parse with a fixed record size; returns null unless the table is consumed exactly.</summary>
        static List<Entry> TryParse(byte[] t, int rs)
        {
            var list = new List<Entry>();
            int p = 0;
            while (p < t.Length)
            {
                int z = Array.IndexOf(t, (byte)0, p);
                if (z < 0) return null;
                if (z + 1 + rs > t.Length) return null;
                var e = new Entry();
                e.Name = new byte[z - p];
                Buffer.BlockCopy(t, p, e.Name, 0, z - p);
                int q = z + 1;
                e.CLen = BitConverter.ToUInt32(t, q);
                e.CAlign = BitConverter.ToUInt32(t, q + 4);
                e.RLen = BitConverter.ToUInt32(t, q + 8);
                e.Flags = t[q + 12];
                e.Off = BitConverter.ToUInt32(t, q + 13);
                e.OffHi = rs >= 21 ? BitConverter.ToUInt32(t, q + 17) : 0u;
                p = q + rs;
                list.Add(e);
            }
            return p == t.Length && list.Count > 0 ? list : null;
        }

        public byte[] BuildTable()
        {
            using (var ms = new MemoryStream())
            {
                foreach (var e in Entries)
                {
                    ms.Write(e.Name, 0, e.Name.Length);
                    ms.WriteByte(0);
                    ms.Write(BitConverter.GetBytes(e.CLen), 0, 4);
                    ms.Write(BitConverter.GetBytes(e.CAlign), 0, 4);
                    ms.Write(BitConverter.GetBytes(e.RLen), 0, 4);
                    ms.WriteByte(e.Flags);
                    ms.Write(BitConverter.GetBytes(e.Off), 0, 4);
                    if (RecordSize >= 21) ms.Write(BitConverter.GetBytes(e.OffHi), 0, 4);
                }
                return ms.ToArray();
            }
        }

        /// <summary>Write the table header in exactly the layout this archive was read with.</summary>
        public void WriteTableHeader(Stream s, uint clen, uint ulen)
        {
            if (TableHeaderSize >= 12) s.Write(BitConverter.GetBytes((uint)0), 0, 4);
            s.Write(BitConverter.GetBytes(clen), 0, 4);
            s.Write(BitConverter.GetBytes(ulen), 0, 4);
        }

        public byte[] FinalHeader(uint tableOffset, int entryCount)
        {
            byte[] h = (byte[])Header.Clone();
            Buffer.BlockCopy(BitConverter.GetBytes(tableOffset), 0, h, 0x1E, 4);
            uint field = (uint)(CountIsLiteral ? entryCount : entryCount + 7);
            Buffer.BlockCopy(BitConverter.GetBytes(field), 0, h, 0x26, 4);
            return h;
        }
    }
}
