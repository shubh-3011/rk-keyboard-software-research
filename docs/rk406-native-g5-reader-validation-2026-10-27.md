# Native G5 reader and Windows preview 0.6

## Hardware result

The independently authored native reader successfully queried the connected
`258A:01AF`, version 8457, `FF02:0002` collection in USB/wired mode. Its descriptor
declared one Feature report ID, `09`, with a 520-byte report. The published
self-contained executable launched its own bounded worker and returned a
128-byte lighting block ending in `5A A5`.

Retained evidence:

- [Published query](runtime-evidence/native-g5-published-query-2026-10-27.json)
- [Validation and executable digest](runtime-evidence/native-g5-published-query-check-2026-10-27.json)
- [Bounded vendor object snapshot](runtime-evidence/rk406-g5-wired-identity-2026-10-27.json)
- [Exact static query recovery](rk406-g5-feature-lighting-query-2026-10-26.md)

The published query returned header `09 84 00 00 01 00 80 00`. Only that header
and the 128-byte lighting block were retained, not an entire report or input
buffer. Exactly one SetFeature request and one GetFeature response were used;
no settings writer, reset, bootloader or firmware command was invoked.
The vendor utility was closed normally and restarted with its original `-s`
argument after the check. No lighting/settings restoration was needed because
this test issued no settings changes.

The passive snapshot found a G5 root with VID/PID matching this interface but
report-ID field zero. This is not an endpoint binding or proof the cached
object was open/active. Fresh descriptor metadata, not that cached field,
selected report ID `09`. Do not infer physical model from the VID/PID or
the unresolved global profile scalar.

## Safety and failure boundaries

`--read-g5-lighting <VID:PID> <new-json-path>` requires catalogue membership,
one eligible 520-byte vendor endpoint and one distinct descriptor-declared
Feature report ID. Missing/ambiguous metadata fails closed. No report-ID
probing, guessed commands, transport fallback or automatic retry is used.
The 1032-byte collection is not eligible.

Synchronous HidD calls execute only in an owned helper process. A worker
watchdog exits after eight seconds; the parent bounds execution to ten
seconds with bounded cleanup. Task cancellation alone cannot interrupt a
native call. Standard output/error have independent 8192-character limits.
This remains an active configuration query, not passive observation or
firmware readback. It grants no permission for G5 writes.

## Other 0.6 work

- Independent per-user unsigned MSI, with payload hashes and read-only MSI
  database inspection. No service, startup entry, custom action or auto-launch.
- Disposable GitHub-hosted runner lifecycle tests cover previous-version
  install, upgrade, rejected downgrade, repair, installed offline catalogue
  export and uninstall. Actual CI results, not the existence of the script,
  determine whether those operations are validated.
- `--ui-smoke-test <new-json-path>` constructs and renders nine WPF pages with
  software rendering, absent vendor resources, fresh in-memory settings,
  suppressed network/registry/PnP/persistence and no hardware operations.
  It is not full interactive workflow coverage or a latency benchmark.
- Partial ordinary-action packing and seed-preserving offline matrix patches.
  Unsupported/special/macro actions are refused; these APIs do not establish
  a device-current keymap or enable writes. See the
  [keymap recovery boundary](rk406-g5-keymap-next-step-2026-10-27.md).

General brightness/color/effect controls, keymaps/layers/macros on hardware,
other transports/families, displays, HE controls, signed distribution and
broad model/revision validation remain incomplete. Catalogue entries remain
`CataloguedOnly`; this successful wired query is operation-specific evidence,
not universal RK support.
