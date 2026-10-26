# Experimental lighting writes: operation evidence, not model certification

## Scope

The replacement's first configuration-writing operation is deliberately smaller
than the vendor's serializer: switch the ordinary-layout lighting mode between
wire values **0 and 1**, preserving every other byte of a current 128-byte block.
The meanings come from the observed vendor Off → first effect → Off workflow,
not a guessed enumeration of the catalogue's effects.

This is a general application's operation-specific evidence gate. It does not
change catalogue entries to supported, select a physical model from shared
VID/PID, or allow manual reference-profile selection to bypass validation.

## Evidence and eligibility

The starting evidence is
[`rk406-wireless-lighting-roundtrip-frida-2026-10-26.json`](runtime-evidence/rk406-wireless-lighting-roundtrip-frida-2026-10-26.json),
the retained direct-Frida observation from the installed executable with SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
The derived fixture is regression-tested against both queries and all outgoing
command-4 frames. The earlier native query independently confirmed restoration.

`LightingWritePolicy.cs` requires all of:

- The exact observed endpoint metadata: `258A:0150`, device version `518`,
  usage `FF02:0002`, input/output report lengths both 20, no discovery error.
- A complete lighting-read baseline, including the `5A A5` signature.
- Current and target mode both in `{0, 1}`.
- SHA-256 of the entire block after normalizing only byte `0x0A` to zero:
  either `b6e940753f8e26a8f9232418de25c11a77e6a00b4517dafb077efb6e824f09fd`
  or `abb54c49bff203b2e04b8c70f443f890f30c07147f500f23986dbd771ae2072e`.

The second fingerprint has its own complete
[post-reconnection vendor trace](runtime-evidence/rk406-wireless-lighting-reconnected-roundtrip-frida-2026-10-26.json),
again showing only byte `0x0A` changing and exact restoration. The policy does
**not** normalize the unexplained differing bytes or label them battery state.

The last check intentionally excludes **any unobserved configuration**, even
on this same keyboard. It will refuse a block whose other settings were changed
by the vendor utility. This is a conservative known-state limitation, not a
claim that that fingerprint uniquely identifies a keyboard or firmware. Never
replace the current block with the fixture to force eligibility.

## Transaction and failure handling

The operation acquires a session-wide named semaphore so two replacement
processes cannot consume each other's configuration replies. It refuses to run
while the vendor utility is present. This cannot prevent unrelated programs or
a subsequently started vendor utility from racing; such interference must fail
verification, not silently establish success.

A matching baseline is a prerequisite, not permission to blindly replay it.
The transport re-queries through the **same handle** and compares every byte
before applying the patch. A stale baseline fails before configuration writes.
Unchanged mode requires no configuration write. A changed mode is sent using
the observed ten command-4 frames, followed by complete readback verification.
There are no automatic retries, alternative protocols, resets or firmware calls.

After any partial write, timeout, cancellation or verification failure, hardware
state can be uncertain. Do not claim restoration and do not automatically write
the baseline back. The UI retires its baseline after each attempted apply; a
new query is required. The CLI requires an explicit confirmation flag, refuses
existing output paths, reserves the report before I/O, and records failures as
failures rather than success reports.

## Native hardware validation and failed attempts

The [retained native round trip](runtime-evidence/native-verified-lighting-mode-roundtrip-2026-10-26.json)
contains the application assembly SHA-256, native operation results and independent
before/after queries for **Off → first effect → Off**. Both transactions returned
success with ten configuration frames, each changed only offset 10, each was
independently queried again, and the final 128-byte block equals the initial
block exactly. The vendor utility was closed normally and restarted with `-s`
around each operation. These are authored native-test records, not REA Evidence.

Validation was not a clean first attempt. An initial query timed out while the
receiver remained enumerated. After the user woke/reconnected the keyboard, a
different block was correctly refused by the fingerprint gate. Wired connection
also exposed a separate 520-byte feature path; it was not treated as wireless.

An early UI probe after reconnection selected a recreated **profile** tree, not
the lighting tree. It restored the prior selection but produced non-lighting
commands. Those runs are excluded from lighting fixtures; no full keymap readback
was performed. One [excluded metadata-only probe](runtime-evidence/rk406-excluded-profile-tree-probe-2026-10-26.json)
is retained to make that scope failure inspectable; its original producer format
name does not make it a successful lighting round trip. The fixture extractor
rejects it. The runner now rejects anything except the observed lighting
tree shape (19 configuration rows, optional Music row, original Off item 18).
Actual target-local mouse messages with cursor hit testing, followed by a
target-only screenshot, established the later lighting page before its trace.

The first native write reached the intended mode but failed transaction
verification. A fresh independent query established the entire intended block;
no blind rollback was sent. A subsequent restore attempt timed out before any
configuration write ([failure record](runtime-evidence/native-mode-pre-settling-restore-failure-2026-10-26.json)).
Recovered wrapper instructions show a **200 ms pre-Apply**
wait (`0x40E73E/0x40E74D`) and **50 ms post-Apply** wait (`0x40E786/0x40E78A`),
in addition to 15 ms before each frame (`0x40DE16`, `0x40D8A1–0x40D8AA`). Adding
the two settling intervals was followed by a successful explicit restoration
and then the retained successful full round trip. All delays are asynchronous
and share the transaction deadline. This is corroboration on one fixture, not
a guarantee that these timings cover every revision or connection state.

## Remaining gaps and release scope

This operation does not enable general effect selection, brightness/color
adjustment, keymaps, macros, screen/media, HE features, firmware or reset.
Each broader operation needs its own wire observations and per-family/revision
validation. Matching metadata, a signature or an echo is not authentication.
Native tests and CLI hardware tests also do not establish full WPF interaction
coverage or a measured lag improvement.
