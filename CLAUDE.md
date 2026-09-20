This file contains technical specifics for an agent to interpret what is going on in this codebase.

### Pulling specific files

`extract` decrypts per entry on the fly, so there is no need to build a decrypted
archive first just to read a few files out of it:

```
nrodecrypt extract dream.grf C:\out \
  --only "data\luafiles514\lua files\skillinfoz\skilldescript.lub" \
  --only "data\luafiles514\lua files\navigation\navi_mob_krpri.lub"
```

Paths that are not in the archive are listed as `NOT FOUND` and set exit code 2, but everything that *did* match is still written - a bad path never discards the rest of the batch.

## There is no password to recover

GRF Editor asks for an encryption password or a `.grfkey`. **Neither is stored in the generated DLL** - only the expanded 260-byte key is, and the derivation is not invertible. Diffing a generated DLL against GRF Editor's embedded template (`GRFEditor.Files.cps.dll`) shows exactly three patched regions:

| region | template | generated |
|---|---|---|
| export name | `uncompress` | randomised, e.g. `nqesgxwjke` |
| key blob | `TKTK` + zeros | 4-byte seed + 256 key bytes |
| integrity target | zeros | bit-inverted client exe name |

So the password is gone, but it was never needed - the key is sufficient, which is what this tool uses.

## How the encryption works

The DLL exports a renamed `uncompress`. It:

1. calls `IsDebuggerPresent`; if set, shows a "Dll injection prevention" message box
   (an obfuscated wide string, each `WORD` XORed with `0x82B`) and exits
2. range-checks its own return address against the client's first PE section
3. tries the real `uncompress` on the raw data - if that returns `Z_OK` the entry
   was never encrypted
4. otherwise RC4-decrypts and retries

The S-box is **not** built with the standard RC4 KSA:

```c
seed = LE32(key[0..3]);
for (i = 0; i < 256; i++) {
    S[i] = (seed % 256) ^ key[4 + i];
    seed *= 0x2F;
}
```

RC4 then runs textbook PRGA, but `i` starts at the entry's **uncompressed size**
(the hooked `uncompress` seeds it from `*destLen`) with `j = 0`, and the S-box is
re-copied per call, so every entry decrypts independently.

## Format notes

Two things vary by GRF version and are probed against the actual bytes rather than
assumed, because getting either wrong produces a file that looks fine but fails to
open:

- **table header** - v3.0 is 12 bytes (leading dword, `clen`, `ulen`); v2.0 is 8
- **entry record** - v3.0 is 21 bytes (adds the high dword of a 64-bit offset); v2.0 is 17
- **file count field** - v3.0 stores the literal count; older files store `count + 7`

`decrypt` preserves whatever the source used, then re-opens its own output and
inflates every entry, asserting the record count matches the header and the table
ends exactly at EOF.

## Two traps worth knowing

**A zlib header check is not enough to tell plaintext from ciphertext.** `(b[0] & 0x0F) == 8`
plus the `%31` checksum passes on random data roughly 1 in 500 times, so a few
encrypted entries per thousand get waved through untouched. This tool inflates and
confirms the byte count instead - the same thing the DLL does by branching on
`uncompress`'s return code.

**A permutation check is not enough to confirm a key.** Any 260-byte window whose
derivation yields a permutation of 0..255 looks valid, and when the seed is zero the
derivation collapses to copying the key bytes verbatim - so every identity table,
shuffle table, and unrelated cipher S-box in any binary matches. Candidates are
therefore validated by actually decrypting five real entries from the target archive.
