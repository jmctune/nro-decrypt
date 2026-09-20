# nrodecrypt

Decrypts a GRF for NightmareRO.

## Requirements

- [dotnet 9 runtime](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-9.0.20-windows-x64-installer)

## gui Usage

- Open `nrodecrypt-gui.exe`
- Click "Browse" or drag the GRF into the window
- Click "Decrypt"
- A file named `<file>_decrypted.grf` is created relative to the GRF you selected

## cli Usage

```
nrodecrypt <archive.grf> [-o out.grf] [-k cps.dll] [-f]
nrodecrypt decrypt <archive.grf> [-o out.grf] [-k cps.dll] [-f]
nrodecrypt extract <archive.grf> <outdir>  [-k cps.dll] [-c 1252]
nrodecrypt verify  <archive.grf> [-c 1252]
nrodecrypt key     [cps.dll]
```

| option | meaning |
|---|---|
| `-o, --out <path>` | output archive (default `<name>_decrypted.grf`) |
| `-k, --dll <path>` | DLL holding the key; omit to probe every `*.dll`/`*.exe` beside the archive |
| `-c, --codepage <n>` | filename codepage, default `1252`; use `949` for Korean paths |
| `-f, --force` | overwrite an existing output |
| `--only <path>` | extract just this GRF path (repeatable); `/` and `\` equivalent, case-insensitive |
| `--list <file>` | read paths from a file, one per line (`#` comments and `- ` bullets ignored) |
| `--flat` | write basenames into the output dir, no directory tree |
| `--keep-info` | keep `__encryption.info` (dropped by default - its presence makes GRF Editor prompt for a key) |

Exit codes: `0` ok, `1` usage/IO error, `2` some entries unresolved, `3` verification failed.

### Example

```
> nrodecrypt dream.grf
archive: dream.grf
         signature "Event Horizon R"  version 3.0  entries 2766
         table header 12B, records 21B, count field literal
key    : jem.dll @0x294A4  seed=0x0F3E0FFB  (auto-detected, code pattern, validated on 5 entries)

decrypted   : 2765
dropped     : 1  (__encryption.info)
failed      : 0
written     : 2765 entries -> dream_decrypted.grf

=== verifying output ===
         table ends at 66995574 / file 66995574   EXACT FIT
inflated OK : 2765
failed      : 0
RESULT: OK
```

## Build

```
dotnet publish cli -c Release -r win-x64 --self-contained false -o dist
```

Requires the .NET 9 runtime. Add `--self-contained true` for a standalone exe.
