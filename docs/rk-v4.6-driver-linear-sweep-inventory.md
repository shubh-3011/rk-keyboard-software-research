# RK DeviceDriver 4.6 executable-section linear-sweep inventory

## Scope and evidence label

This report records a reproducible **linear sweep** of executable sections in
one hash-pinned PE32 image. It is an instruction-boundary and transfer-site
inventory, **not** a recovered function list, complete control-flow graph,
call graph, reachability proof, or runtime trace. The decoder may interpret
embedded data and tables as instructions; control transfers through vtables,
callbacks, COM, computed dispatch, and dynamically loaded code remain unresolved.

The input is the extracted 4.6-labeled `app/DeviceDriver.exe`: 2,418,176 bytes,
SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The image is PE32 x86, image base `0x00400000`, with PE entrypoint VA
`0x005750db` (RVA `0x001750db`). Its only executable section is `.text`, RVA
`0x1000`, file offset `0x400`, raw size 1,723,392 bytes, SHA-256
`899e0a5c3cda384c912a4bfcb5484eb565d0a92c46c02a8adcdc8ce2c2f5c695`.
The entrypoint is one of the decoded linear instruction boundaries. The PE
advertises no export or TLS callback roots in this scan.

## Result

Capstone 5.0.7 linearly decoded 570,401 instruction boundaries spanning
1,723,079 bytes in `.text`; 313 bytes fell into 36 one-byte-skip data runs.
The fact that most section bytes decode successfully does not show that those
bytes are code.

| Linear-sweep observation | Count |
| --- | ---: |
| Direct call, conditional-branch, or direct-jump sites | 102,205 |
| Those sites targeting an executable section | 102,190 |
| Unique such executable-section target addresses | 44,271 |
| Indirect call/jump candidates | 18,517 |
| Decoded return-mnemonic sites | 10,970 |
| Explicit PE roots recorded | 1 (entrypoint) |
| Undecoded bytes / runs | 313 / 36 |

These are syntactic counts from a linear sweep, not counts of reachable
branches or real function entries. The 44,271 target addresses include ordinary
intra-function branch targets and possible data-derived false positives; they
must not be read as 44,271 functions. Return mnemonics likewise do not define
function boundaries.

## Reproduction and outputs

The script rejects any input whose size or SHA-256 differs from the pinned
image, then checks that it is x86 PE32 before decoding. It requires Python,
`pefile`, and Capstone 5.x. Example from the repository root after extracting
the package:

```powershell
python scripts/audit_rk46_driver_linear_sweep.py `
  C:\path\to\extracted-package\app\DeviceDriver.exe `
  --output-dir .research/rk46_driver_linear_sweep
```

The generated deterministic `summary.json` records input identity, PE and
section hashes, tool versions, counts, and limitations. CSVs include all
linear decoded instruction boundaries, direct transfers, indirect transfer
candidates, return sites, undecoded runs (with per-run hashes and the full run
bytes in hex), and explicit PE roots. These machine-generated CSVs are kept in
the requested output directory and are not checked into this source repository;
the hash-pinned script and summary above allow regeneration against an
authorized extracted copy.

The audit is static only. No vendor executable, updater, or installer was run;
no HID, serial, Bluetooth, or other device interface was opened.

## Remaining function/CFG blocker

The 4.6 image is a stripped x86 PE without an export directory or unwind
function table. Its debug directory records the path
`d:\\OEM\\Beiying\\Src\\RK\\Debug\\DeviceDriver.pdb`, but a matching PDB was
not available in the inspected workspace. Function starts therefore cannot be
validated from symbols, and this report does not reconstruct code/data ranges.
Direct-call targets and known MFC/RTTI/vtable references can seed focused
follow-ups, but do not cover callback or computed targets by themselves. A
function-aware disassembly plus manual resolution of indirect dispatch is still
required before claiming a complete 4.6 CFG or function map.
