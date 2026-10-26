# Installed RK 4.06: bounded G5 lighting-query specification

## Scope and outcome

Offline, read-only inspection of installed `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe` independently confirmed SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
Addresses below are preferred x86 VAs, image base `0x400000`. Existing Python
`pefile` and Capstone decoded the PE; no target execution, process attachment,
HID opening, metadata acquisition from hardware, or device command occurred.
Only this report and the new identity snapshot script were added. No git
operation was performed. Existing `G5FeatureCodec.cs` was not changed.

**A `native-bounded-lighting-query84` implementation can use the existing
520-byte codec, but must first obtain the selected endpoint's actual feature
report ID from standard HID metadata.** No report-ID constant is established
for the currently reconnected device. The vendor itself obtains that ID from
HID parser metadata, not a universal G5 constant. Do not guess IDs or transplant
the ID of the separate 1032-byte updater collection.

**Correction to earlier prose:** the G5 lighting reply copy begins at report
offset **8**, not 12. The prior follow-up's statement of offset 12 is incorrect;
the push immediately before the stack-relative source address explains it.
The existing codec's offset 8 agrees with the exact instructions.

## Selected root, class and object boundaries

`0x62B380` holds a **list-node pointer**, whose first DWORD is the selected
device pointer. The device's first DWORD is its vtable. It is not valid to
interpret the global's first pointee directly as a device object.

Exact byte witnesses:

```text
4011E6 A180B36200             mov eax,[0062B380]
401222 8B30                   mov esi,[eax]
401227 0FB7964A020000         movzx edx,word [esi+24A]
40122E 0FB78648020000         movzx eax,word [esi+248]
401238 8B16                   mov edx,[esi]
40123B 8B4214                 mov eax,[edx+14]
40ECE3 C7062CBA5C00           mov dword [esi],005CBA2C
40ED2E 895E08895E0466894622   zero secondary +8, primary +4, inline path +22
40ED38 899E50020000           zero fallback child +250
40F433 894704                 store primary handle at +4
40F4A3 894708                 store secondary handle at +8
40F51E 8D4722                 lea eax,[edi+22] (inline path, NOT a pointer)
40F53C 66898F48020000         store VID word at +248
40F546 6689974A020000         store PID word at +24A
40F44A 8897D0020000           store report-ID BYTE at +2D0
```

Constructor `0x40ECE3` identifies G5 vtable `0x5CBA2C`. These object offsets
must not be used on an unclassified root or on the list node. A root may also
be `CDevRKKB` (`0x5CBE0C`) or `CDev3632` (`0x5CA32C`). Root class is a
software-object observation, not proof of a physical model or transport.

The prepared, **unexecuted** `scripts/snapshot_rk406_g5_query_identity.js`
exposes only one bounded RPC snapshot: selected-root presence/class and, only
for G5, VID/PID words and report-ID byte. It never reads the handle fields,
inline path, fallback child, configuration, keymap or report buffers, and
returns no pointers. All selected instruction witnesses are checked before
state reads. Absolute image operands are rebased according to their actual
PE HIGHLOW relocation sites, rather than wildcarded. The host-supplied SHA
argument is an attestation requiring independent host verification, not a hash
calculated inside the script. Anchor/value rereads reject detectable changes;
they cannot make a live snapshot atomic or exclude ABA/pointer reuse. It has
not been attached or run in this investigation.

Do not use candidate config global `0x61158E` or value `0x023D` as physical
model/profile proof. An existing documented disagreement associates Cfg.ini
023D with G98 while the UI says S98. Neither a stale config code nor a root
VID/PID observation resolves that disagreement. This snapshot deliberately
does not read that global.

## Where the vendor report ID comes from

The installed enumerator calls standard `HidD_GetPreparsedData`,
`HidD_GetAttributes`, and `HidP_GetCaps`, then helper `0x416740`. That helper
tries report types in order **Feature (2), Input (0), Output (1)**. For each
type it tries button caps first if the advertised count is nonzero, then value
caps if their count is nonzero. The usage-page/link-collection/usage selectors
are zero; the local capacity is 100 caps. On `HIDP_STATUS_SUCCESS` (`0x110000`)
it returns the **first cap's `ReportID` byte**; it returns zero if no attempt
succeeds. This is metadata parsing, not report-ID probing. Its first-success
behavior does not establish uniqueness, and its zero failure sentinel must
not be copied as a replacement application's default report ID.

```text
41668D E8AE000000             call 416740
416695 0FB7D8                 movzx ebx,ax
416698 E8E3FDFFFF             call 416480 (descriptor-row allocator)
4166B9 0FB7C3                 movzx eax,bx
4166BC 898708020000           row+208 = returned report ID DWORD
41679C C744241002000000       first report type = Feature
4167A4 89742414               second report type = Input (ESI zero)
4167A8 C744241801000000       third report type = Output
4167C4 BD64000000             capacity 100
4167EC 6A006A006A00           zero selection criteria
4167F3 E89E2A1700             call 589296 -> HidP_GetSpecificButtonCaps
4167F8 3D00001100             success status comparison
416825 E8722A1700             call 58929C -> HidP_GetSpecificValueCaps
41682A 3D00001100             success status comparison
416856 660FB644241E           first button cap ReportID at cap+2
41687B 660FB684243E1C0000     first value cap ReportID at cap+2
41683E 33C0                   no successful query: return zero
40F3A1 BEB4006200             descriptor cursor = 6200B4
40F3B4 8DAEDCFDFFFF           row base = cursor-224
40F40F 817EF008020000         require FeatureReportByteLength = 520
40F443 8A56E4                 dl = byte [cursor-1C] = row+208
40F44A 8897D0020000           device+2D0 = dl
40F4DB 81C62C020000           next descriptor row, stride 22C
```

The report-ID data-flow witnesses are the exact `0x4166B9/BC` stores and
`0x40F443/44A` load/store.

Primary selection in `0x40F350` compares the requested VID/PID with descriptor
row VID/PID, accepts usage `FF00:0001`, `FF02:0001`, or `FF02:0002`, and
requires feature length 520. This describes vendor acceptance, not a safe
reason for the replacement to broaden its allowlist. The user's historical
wired metadata is `258A:01AF`, version 8457, usage `FF02:0002`, Feature 520,
Input 8, Output 0. The separate `FF00:0001` Feature 1032 collection is **not
equivalent**. Historical wired metadata is not an observation of today's
reconnected 2.4 GHz endpoint.

Replacement discovery should query **feature** caps for the exact currently
selected collection, collect distinct descriptor-declared report IDs from
both button and value caps, and refuse absent/ambiguous identities unless
additional exact descriptor evidence disambiguates the relevant feature.
Do not silently use an input/output cap as a feature ID. `HidD_GetPreparsedData`
and HID parser calls read descriptor metadata; no `GetFeature`, `SetFeature`,
or input-report read is required to learn the declared IDs. Free preparsed
data and close discovery handles on every path. These are proposed replacement
rules, stricter than the vendor's first-success helper.

## Exact `0x40FAD0` direct-G5 query

Arguments: destination in ECX, device pointer as its stack argument. It reads
primary handle at device `+4`. If absent and child `+250` is nonnull it instead
calls wireless helper `0x40DA80`, command `0x44`, requested length `0x80`, and
returns that result. With neither primary nor child it reports failure. This
branch is not the G5 feature query; do not fallback automatically from an
authorized G5 request to wireless or vice versa.

For a nonzero primary handle, the routine reads the device report ID at
`+2D0`, sets accumulated bytes to zero, and uses a single 128-byte chunk (the
general chunk cap is 512). It waits using `0x459A80(25)` before preparing the
request. That helper is a QueryPerformanceCounter/Frequency **busy wait**,
with a double multiplier of 1000, not an ordinary Sleep API call.

It zeroes **520 bytes**, then constructs this exact buffer:

```text
offset 0       discovered report ID
offset 1       84
offset 2       00
offset 3       00
offset 4       01  (packet count)
offset 5       00  (first/only packet index)
offset 6..7    80 00 (requested payload length, little-endian)
offset 8..519  zero
```

Witnesses:

```text
40FB27 0FB680D0020000         load report ID byte
40FB45 6A19E8349F0400         busy wait 25 ms
40FB64 6808020000             memset length 520
40FB70 E89B121600             memset
40FB8E 8854241C               buffer[0] = ID
40FB92 C644241D84             buffer[1] = 84
40FB97 C644241E00             buffer[2] = 00
40FB9C C644241F00             buffer[3] = 00
40FBA1 C644242001             buffer[4] = 01
40FB7D 8844242D               buffer[5] = packet index (before stack cleanup)
40FBA6 885C2422               buffer[6] = chunk length low byte
40FBAA 88442423               buffer[7] = chunk length high byte
40FBB3 6808020000             SetFeature length 520
40FBBE E8A9961700             call 58926C
58926C FF25E4E15900           thunk -> HidD_SetFeature
40FBED A0272B6100             post-send wait override byte [612B27]
40FBFC 6A19                   if override zero, wait 25 ms
40FBFE E87D9E0400             same busy-wait helper
40FC0A 6808020000             GetFeature length 520
40FC15 88442428               restore buffer[0] = original report ID
40FC19 E854961700             call 589272
589272 FF2504E25900           thunk -> HidD_GetFeature
40FC22 8A44241D3C84           compare response buffer[1] with 84
40FC32 53                     push chunk length (128)
40FC33 8D542428               source = buffer+8, accounting for push
40FC37 52                     push source
40FC38 8D0C07                 destination + accumulated bytes
40FC3C E8AF461600             memcpy
40FC46 81FF80000000           stop once accumulated bytes reach 128
```

At a stable stack position the buffer begins at ESP+1C. The copy's preceding
push lowers ESP by 4, so `[ESP+28]` is the old ESP+24, i.e. buffer+8. For this
single chunk it copies exactly report bytes **8..135** to block bytes 0..127.
No checksum is added or checked in this query helper. It checks successful
GetFeature and response command only: not echoed ID, option, count, index,
returned length, or a block signature. Success returns EAX=1; error paths
return zero. It reuses the initialized request buffer for GetFeature, restoring
only its report-ID byte, rather than clearing a fresh reply buffer.

### Vendor retry/error behavior (do not silently emulate the quirk)

`ESI=3` at `0x40FBAE`. On a failed SetFeature, `GetLastError` is tested against
1 (`ERROR_INVALID_FUNCTION`); that error immediately logs and fails. Otherwise
ESI is decremented. A negative count branches to a failure diagnostic, but
in this ordinary path it cannot be reached: after each decrement the code
waits 50 ms and repeats SetFeature only while ESI>0. Thus there are at most
**three sends**, with 50 ms waits even after the third failure. When the third
failure leaves ESI=0, control **falls through to GetFeature anyway**. A valid
GetFeature/command could therefore cause success even after all sends failed.
Do not describe the code as four attempts, or as guaranteed failure on retry
exhaustion. The relevant exact bytes are:

```text
40FBAE BE03000000
40FBC7 FF1560E45900           GetLastError
40FBCD 83F801                compare error with 1
40FBD0 0F849C000000          immediate error branch
40FBD6 83EE01                decrement attempts
40FBD9 0F88AB000000          negative-count diagnostic branch
40FBDF 6A32E89A9E0400        wait 50 ms
40FBE9 85F67FC6              repeat only while ESI>0
40FC20 747A                  GetFeature false -> failure
40FC28 0F8585000000          wrong response command -> failure
40FCFA 33C0                  common failure return value
```

There is no GetFeature retry inside `0x40FAD0`. Its failed read and command
mismatch go directly to failure diagnostics.

### Signature and five-attempt loop are caller policy

`0x411B90`'s lighting apply branch sleeps 30 ms at `0x411FFA/FFC`, initializes
five attempts (`0x412042 BE05000000`) and BL=5A (`0x412047 B35A`). Each
iteration clears 128 bytes and calls the query (`0x412050..69`). Successful
queries are checked at block offsets 126/127 for `5A A5`:

```text
4120D4 389C24BA000000         block[126] == 5A
4120DD 80BC24BB000000A5       block[127] == A5
4120F5 6A644EFFD5             Sleep(100), with attempt decrement before call
4120FA 85F6
4120FC 0F8F4EFFFFFF           retry while attempts remain
```

For this caller the block starts at ESP+3C; BA-3C=7E and BB-3C=7F.
Bad signature consumes an attempt and sleeps 100 ms, including the final
failure. Query failure can abort immediately when caller flag `[ESP+24]` is
zero, or enter the same retry loop when nonzero (`0x41206E..7C`). Thus “always
five retries on any error” is inaccurate. These checks are in an apply path
that later packs and writes command 4: **never call the apply routine merely
to obtain a query**. A stand-alone query may adopt the signature check without
calling any packer/writer. Signature is a structural guard, not authentication.

## Proposed replacement bounds, explicitly not observed execution

1. Explicit opt-in to an **active query**; SetFeature(84) is an outbound
   device request, not a passive read or permission to write lighting settings.
   No command 04, 11, 12, updater, screen query or arbitrary vendor command.
2. Select exactly one current endpoint by the established collection/VID/PID/
   version/report-length allowlist; reject wrong transport, disappearance,
   duplicate matches and the 1032-byte updater endpoint. Historical wired
   `258A:01AF/8457/FF02:0002/8/0/520` is only a candidate identity until freshly
   enumerated. Do not relax wireless writer policies or reuse old block data.
3. Discover unique feature report ID from standard descriptor caps. A prepared
   G5 object snapshot can corroborate software selection; it does not prove
   descriptor identity or bind a new native handle to that object. Do not use
   config code 023D, screen naming, or guessed report IDs as authorization.
4. Build exactly one 520-byte request with command 84 and 128-byte requested
   data length. Adopt 25 ms pre-send/post-send waits as explicit replacement
   policy; vendor post-send delay is its nonzero byte override or 25 ms, so
   fixed 25 is not a claim that the current vendor global is zero.
5. Prefer **one SetFeature and one GetFeature maximum per invocation**,
   fail immediately on either error. No automatic signature retry, blind ID
   scan or transport fallback. If retries are later required, explicitly cap
   them and fail closed after failed sends rather than reproducing vendor
   fallthrough. No concurrent vendor/native query or writer transaction.
6. Require exact response length 520, matching command 84, then extract
   exactly 128 bytes at offset 8 and require trailing 5A A5. More restrictive
   header checks can be policy, but vendor does not prove their reply values;
   do not invent echo semantics from the outgoing header. Never normalize the
   block or coerce missing signature bytes. No query result authorizes writes.
7. Give the command a bounded total deadline (e.g. 2 seconds) and emit no
   success until every check passes. **Synchronous HidD_SetFeature/GetFeature
   do not take a timeout argument**: a stopwatch check around a blocking call
   is not a hard deadline. Use an owned worker process with supervisor deadline
   for bounded caller return, disposal/termination on timeout, and no repeated
   query while a previous worker might remain active. Process termination is
   not proof that firmware did not receive the request or that a stuck kernel
   request has been cancelled. Until this lifecycle is implemented/tested,
   describe the prototype as bounded attempts/bytes, not guaranteed bounded
   device-call latency.
8. Close owned handles on all normal/error paths; keep raw handles, device
   paths, process pointers and unrelated keymap/macro data out of evidence.
   Return endpoint metadata, discovered ID, attempt counts, elapsed time,
   structural validation outcome and (only when explicitly desired) the
   validated 128-byte lighting block.

Answered statically: selected-root indirection, G5 field boundaries, metadata
report-ID provenance, query frame/length/data offset, waits, retry quirk and
caller signature policy. Unresolved: current root class, current descriptor
report ID and endpoint binding after 2.4 reconnection, actual device response,
firmware interpretation of every block byte and synchronous-call latency.
No runtime or hardware result is asserted by this report.

Validation performed offline: Node `--check` passed for the new script; all
10 script instruction witnesses matched the exact PE, with complete equality
between their declared relocation offsets and the PE's HIGHLOW entries in
each witnessed span; all 81 address/hex witness lines in this report matched
the corresponding PE bytes. No script RPC was invoked.
