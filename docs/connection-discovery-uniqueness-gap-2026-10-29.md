# Discovery: unresolved endpoint uniqueness on incomplete scans

The replacement's Windows HID discovery returns both metadata endpoints and
per-interface or enumeration errors. `DetectedConnection.Build` displays
matching successfully inspected collections, groups by VID/PID, and reports
ambiguity when more than one supported shape is visible. The wireless and G5
query resolvers rescan and each require exactly one successfully inspected
endpoint of their respective shape.

That count is **not proof of physical uniqueness when a scan is incomplete**:
an interface that could not be inspected may lack VID/PID or capabilities,
and an enumeration or detail-path failure may hide an interface entirely.
The displayed scan errors are useful, but the resolvers currently count the
successful matching endpoints without incorporating those errors. Nor does
grouping by VID/PID establish that the visible collections are one physical
keyboard. This is a code-inspection finding, not a reproduced wrong-device
operation. No device query was sent in this inspection.

Do not simply block every scan containing any error without investigating
Windows environments: unrelated inaccessible HID collections may make that
rule unusable. A follow-up should classify errors by scope, determine whether
an unknown interface can be associated with the target using privacy-preserving
PnP/container metadata, distinguish a complete enumeration from per-collection
metadata failure, and test duplicate/partial-device cases on Windows. Any
query or write should have a separately defined conservative policy; a
catalogue match or a visible endpoint alone cannot grant write permission.

Relevant code: `rebuild/windows/HidDiscovery.cs`, `DetectedConnection.cs`,
`WirelessLightingCommand.cs`, and `G5LightingCommand.cs`. The live .NET test
could not be run in this environment on 2026-10-29 because `dotnet` reported
that no SDK was installed; no SDK was downloaded for this inspection.
