# Installed 4.06 brightness observer: profile binding correction

The one-shot brightness observer formerly labeled constructor-scan WORD
`0x61158E` as `profile_code`. This is not the lighting UI's loaded profile.
The observer now reports `loaded_profile_code_hex` from DWORD `0x61175C`
and `constructor_scan_code_hex` separately, checks additional relocated
instruction witnesses, rejects zero/out-of-range loaded scalars before reading
configuration, and rereads both scalars to detect some concurrent changes.
It is still a non-atomic observation and neither scalar proves device identity,
current profile-file contents, endpoint binding, or write eligibility.

## Runtime observations

- A hash-checked vendor process yielded loaded scalar `0000` and constructor
  scalar `023D` (REA evidence `ev_b13dccc9d053a76da7c3abcabf64f1747052a0468571f9b7d06a9c51ae9724fa`).
- A subsequent hash-checked vendor process, with a different PID, yielded
  `01AF` and `023D`, respectively, through the corrected observer (REA evidence
  `ev_8abcd03c458e4a950b8cc9e62e66edb045196c14fb269965a78be2510331f24f`).
  It observed selected ordinal 18 and brightness index 5, with the runtime UI
  and hardware lookup bytes both 20. The script checked 27 instruction
  witnesses, and called no vendor function or device command. The host
  independently checked the image file hash; REA's runtime artifact identity
  is unavailable. The snapshot is not atomic and valid table length is unknown.

The differing processes and timing mean these are separate observations, not a
demonstrated in-process transition. No brightness control was changed. Neither
observation proves a brightness-to-wire offset, verified restoration, or a
safe new hardware write. Historical evidence remains unchanged.
