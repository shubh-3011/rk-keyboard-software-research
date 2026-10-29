# Installed 4.06 Ghidra function inventory

REA with Ghidra 12.1.4 analyzed the installed PE32
`DeviceDriver.exe` with SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
`list_procedures` returned **13,735** entries: 12,870 non-external,
non-thunk procedures, 191 local thunks, and 674 external entries. The complete
provider evidence is retained locally at
`.research/rk406-ghidra-function-inventory-20261029.json`, evidence ID
`ev_e876e5567ba8efd58ec92a45baa53059c448afaa2acb93b09cb14ff749cc6501`.

This is an analysis inventory for one binary, **not** a list of decompiled,
understood, reachable, or tested functions. It includes application code and
library code. Ghidra's automatic function boundaries, calling conventions and
names can be incomplete or incorrect; the referenced PDB load state is
unknown. The real number of functions or behavior paths cannot be inferred
from this count, nor does it cover the rest of the installed package or other
RK software versions. Per-function decompilation must be corroborated with
assembly and relevant runtime evidence; exports containing vendor pseudocode
are retained locally rather than copied into the independent replacement.

This inventory provides a reproducible starting point for selecting unexamined
functions and recording coverage, not a claim of completion or a percentage.
No application or keyboard operation was performed for this static inventory.
