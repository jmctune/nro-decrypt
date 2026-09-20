using System;
using System.Collections.Generic;

namespace NroDecrypt
{
    /// <summary>
    /// Recovers the RC4 key material that GRF Editor's "client encryption"
    /// bakes into the generated cps.dll (often renamed, e.g. jem.dll).
    ///
    /// The DLL stores a 260-byte key buffer: a 4-byte seed followed by 256
    /// key bytes. The initial RC4 permutation is derived as
    ///
    ///     seed = LE32(key[0..3])
    ///     for i in 0..255:
    ///         S[i] = (seed % 256) ^ key[4 + i]
    ///         seed *= 0x2F
    ///
    /// This is not the standard RC4 key schedule -- there is no KSA swap loop.
    /// In the unpatched template these 260 bytes sit behind a "TKTK" marker
    /// that the generator overwrites.
    /// </summary>
    public sealed class GrfKey
    {
        public byte[] SBox { get; private set; }
        public int FileOffset { get; private set; }
        public uint Seed { get; private set; }
        public string FoundBy { get; private set; }

        GrfKey() { }

        /// <summary>Derive the permutation from a 260-byte key buffer, or null if it isn't one.</summary>
        static byte[] Derive(byte[] buf, int off)
        {
            if (off < 0 || off + 260 > buf.Length) return null;
            uint seed = (uint)(buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24));
            byte[] s = new byte[256];
            bool[] seen = new bool[256];
            for (int i = 0; i < 256; i++)
            {
                byte v = (byte)((seed & 0xFF) ^ buf[off + 4 + i]);
                // A correct key buffer always yields a permutation of 0..255.
                // Bailing on the first repeat makes the brute-force scan cheap.
                if (seen[v]) return null;
                seen[v] = true;
                s[i] = v;
                seed = unchecked(seed * 0x2F);
            }
            return s;
        }

        /// <summary>
        /// Candidate keys inside a cps.dll, best first: the code pattern that loads
        /// the blob address, then (if <paramref name="scan"/>) every 260-byte window
        /// deriving to a permutation.
        ///
        /// A permutation check ALONE is not sufficient evidence. When the seed is
        /// zero the derivation degenerates into copying the key bytes verbatim, so
        /// any plain 256-byte permutation table -- identity tables, shuffle tables,
        /// other ciphers' S-boxes -- passes. Those are common in ordinary binaries.
        /// The scan therefore skips zero seeds, and callers should still confirm a
        /// candidate against real archive data before trusting it.
        /// </summary>
        public static IEnumerable<GrfKey> Candidates(byte[] dll, bool scan)
        {
            foreach (int at in FindByCodePatternAll(dll))
            {
                byte[] s = Derive(dll, at);
                if (s != null) yield return Make(dll, at, s, "code pattern");
            }
            if (!scan) yield break;

            for (int o = 0; o + 260 <= dll.Length; o++)
            {
                if (dll[o] == 0 && dll[o + 1] == 0 && dll[o + 2] == 0 && dll[o + 3] == 0) continue;
                byte[] s = Derive(dll, o);
                if (s != null) yield return Make(dll, o, s, "permutation scan");
            }
        }

        static GrfKey Make(byte[] dll, int at, byte[] s, string how)
        {
            return new GrfKey
            {
                SBox = s,
                FileOffset = at,
                FoundBy = how,
                Seed = (uint)(dll[at] | (dll[at + 1] << 8) | (dll[at + 2] << 16) | (dll[at + 3] << 24)),
            };
        }

        /// <summary>
        /// The init routine copies the blob with:
        ///     mov ecx, 0x42        B9 42 00 00 00
        ///     ...
        ///     mov esi, &lt;blob VA&gt;   BE xx xx xx xx
        ///     rep movsd            F3 A5
        /// The key buffer starts 4 bytes into that blob.
        /// </summary>
        static IEnumerable<int> FindByCodePatternAll(byte[] d)
        {
            for (int i = 0; i + 32 < d.Length; i++)
            {
                if (d[i] != 0xB9 || d[i + 1] != 0x42 || d[i + 2] != 0 || d[i + 3] != 0 || d[i + 4] != 0) continue;
                for (int j = i + 5; j < i + 24 && j + 6 < d.Length; j++)
                {
                    if (d[j] != 0xBE) continue;
                    if (d[j + 5] != 0xF3 || d[j + 6] != 0xA5) continue;
                    uint va = (uint)(d[j + 1] | (d[j + 2] << 8) | (d[j + 3] << 16) | (d[j + 4] << 24));
                    int fo = Pe.VaToFileOffset(d, va);
                    if (fo >= 0) yield return fo + 4; // skip the 4-byte marker slot
                }
            }
        }

        /// <summary>
        /// RC4 in place. Note the starting index comes from the caller: the DLL's
        /// hooked uncompress() seeds i with *destLen, i.e. the entry's real size.
        /// j always starts at 0 and the S-box is re-copied per call, so every
        /// entry decrypts independently.
        /// </summary>
        public void Apply(byte[] buf, int len, int startIndex)
        {
            byte[] s = (byte[])SBox.Clone();
            int i = startIndex & 0xFF, j = 0;
            for (int n = 0; n < len; n++)
            {
                i = (i + 1) & 0xFF;
                byte si = s[i];
                j = (j + si) & 0xFF;
                s[i] = s[j];
                s[j] = si;
                buf[n] ^= s[(si + s[i]) & 0xFF];
            }
        }
    }

    static class Pe
    {
        public static int VaToFileOffset(byte[] d, uint va)
        {
            try
            {
                int pe = BitConverter.ToInt32(d, 0x3C);
                if (pe <= 0 || pe + 24 > d.Length) return -1;
                if (BitConverter.ToUInt32(d, pe) != 0x00004550) return -1;
                int nsec = BitConverter.ToUInt16(d, pe + 6);
                int optsz = BitConverter.ToUInt16(d, pe + 20);
                uint imageBase = BitConverter.ToUInt32(d, pe + 24 + 28);
                uint rva = va - imageBase;
                for (int i = 0; i < nsec; i++)
                {
                    int s = pe + 24 + optsz + 40 * i;
                    if (s + 40 > d.Length) break;
                    uint vaddr = BitConverter.ToUInt32(d, s + 12);
                    uint vsize = BitConverter.ToUInt32(d, s + 8);
                    uint praw = BitConverter.ToUInt32(d, s + 20);
                    uint sraw = BitConverter.ToUInt32(d, s + 16);
                    uint span = vsize != 0 ? vsize : sraw;
                    if (rva >= vaddr && rva < vaddr + span) return (int)(praw + rva - vaddr);
                }
            }
            catch { }
            return -1;
        }
    }
}
