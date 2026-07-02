# Xbox 360 Black Ops 2 `.ff` Notes

This file documents what the scanner currently knows and what is still unknown.
It is deliberately conservative: any unverified field is labeled as unknown.

## Project layout

Unpacker-related files now live under `ff_unpacker_work/` so the game directory
root can remain mostly source data:

- `xbox360_ff_unpacker.py` - current Python scanner/unpacker scaffold.
- `tools/xmem_lzx_decompress.c` - small LZX/XMem helper source.
- `_tools/xmem_lzx_decompress.exe` - built helper used for `TAffx100` zones.
- `_tools/OpenAssetTools/` - local reference checkout and experimental patches.
- `_tools/go-ff/` - local `twonull/go-ff` reference checkout.
- `*_ff_scan/` - current scanner outputs and reconstructed zone streams.

## Observed clear header layout

Test file: `common_zm.ff`

| Offset | Size | Observed value | Current interpretation |
| --- | ---: | --- | --- |
| `0x0000` | 8 | `54 41 66 66 78 31 30 30` / `TAffx100` | Fastfile magic. Map fastfiles may use `TAff0100`; many support files use `TAffx100`. |
| `0x0008` | 4 | `00 00 00 92` | Version-like field. Big-endian gives `146 / 0x92`; little-endian gives `0x92000000`, so this is treated as big-endian. |
| `0x000C` | 4 | `50 48 45 45` / `PHEE` | Auth/encryption marker, exact meaning unknown. |
| `0x0010` | 4 | `42 73 37 31` / `Bs71` | Build, codec, or auth marker, exact meaning unknown. |
| `0x0014` | 4 | `00 00 00 00` | Reserved or flags, unknown. |
| `0x0018` | 32 | `common_zm\0...` | Null-terminated fastfile name. |
| `0x0038` | 256 | high-entropy bytes | Signature/auth blob. |
| `0x0138` | EOF | high-entropy bytes | OAT-style xchunk stream: big-endian `uint32` chunk size followed by encrypted chunk bytes. |

## Current assumptions

- Xbox 360 BO2 fastfiles are not PC fastfiles. The PC-style `IWff...` path is not used here.
- Multi-byte clear header fields are assumed big-endian where a numeric interpretation is needed.
- OpenAssetTools identifies `TAff0100` as deflate and `TAffx100` as LZX for T6.
- OpenAssetTools identifies Xbox/Xenon T6 as big-endian, 32-bit, signed, encrypted, and using 4 xchunk streams.
- Xchunks use a `0x8000` maximum encrypted chunk size.
- Xchunk descriptors are big-endian `uint32` sizes. A zero size is treated as an EOF/padding marker.
- The Xbox 360 BO2 Salsa20 key and OpenAssetTools IV adaptation are now implemented in the scanner.
- Salsa20 IV setup is per stream. OAT seeds 200 SHA-1-sized hash blocks from the fastfile name, uses the first 8 bytes of the current hash block as IV, decrypts the chunk, SHA-1 hashes decrypted data, advances the stream hash index, and XORs the next hash block with that digest.
- For `TAffx100`, decrypted chunks are XMem/LZX containers.
- XMem/LZX inflate is implemented through `tools/xmem_lzx_decompress.c`, built locally as `_tools/xmem_lzx_decompress.exe`.
- For `TAff0100`, decrypted chunks observed in `zm_transit_dr.ff` are raw deflate streams. They inflate with `zlib.decompress(..., wbits=-15)`.
- The scanner can now reconstruct `zone_decompressed.dat`.
- The scanner parses the first-level T6 `XAssetList`: script strings, dependencies, asset count, asset type counts, and a sample of raw asset entries.
- The scanner has a very small prefix-only asset extractor for simple early asset bodies. This is intentionally marked tentative when it cannot keep parsing the following asset.
- Complete individual asset body extraction still requires emulating OAT's block/pointer-aware zone stream and generated asset loaders.
- Normal scans now write a general extraction frontier:
  - `asset_entries.tsv` / `asset_entries.jsonl` for the full top-level asset table.
  - `asset_stream_trace.json` for the current loader frontier.
  - `assets/_unknown_stream_windows/<offset>_next_unparsed.bin` for the next raw unparsed stream bytes.
- Normal scans now also run an embedded script extractor. It writes:
  - `embedded_scripts.json`
  - `assets/embedded_scripts/<original script path>`
- `script_inventory.py` aggregates every `*_ff_scan/embedded_scripts.json` into:
  - `script_inventory.json`
  - `script_inventory.tsv`
  - `script_inventory_summary.json`
- Slow menu-specific probing is opt-in with `--scan-menus`; the default path stays focused on broad fastfile unpacking.

## Embedded Lua UI extraction

Xbox BO2 UI/LUI payloads in patch UI fastfiles use the same local blob layout as
embedded script payloads:

| Relative layout | Meaning |
| --- | --- |
| `FFFFFFFF` | following-name pointer marker |
| big-endian `uint32` | compiled Lua payload length |
| `FFFFFFFF` | following-buffer pointer marker |
| ASCII path ending in `.lua` plus `00` | Lua UI path/name |
| payload bytes | compiled Lua bytecode payload |

The payloads observed so far start with `1B 4C 75 61` (`\x1bLua`) followed by
Treyarch/Xbox-specific Lua bytecode header bytes. The extractor writes:

- `embedded_lua.json`
- `assets/embedded_lua/<original lua path>`
- `ui_lua/<original lua path>`
- `ui_lua_readable/<original lua path>` as readable Lua decompiled source
- `ui_lua_decompiled/<original lua path>.pseudo.lua` as structural listings
- `ui_lua_hksasm/<original lua path>.hksasm` as editable bytecode assembly

CODResearch's BO2 Lua notes confirm that BO2 uses Lua for game menus, stores it
as rawfile-like data, passes binary payloads to the VM, and uses the `1B 4C 75
61` Lua magic plus a documented Havok/Treyarch opcode table. The current
extractor's local `.lua` blob pattern is still an observed container pattern,
not a fully proven XAsset parser.

Verified counts:

- `patch_ui_zm.ff`: `47` compiled Lua UI payloads extracted.
- `patch_ui_mp.ff`: `139` compiled Lua UI payloads extracted.

Example extracted paths:

- `patch_ui_zm/ui_lua/ui/t6/lobby.lua`
- `patch_ui_zm/ui_lua/ui_mp/t6/zombie/basezombie.lua`
- `patch_ui_mp/ui_lua/ui/t6/buttonlist.lua`
- `patch_ui_mp/ui_lua/ui/t6/cod9button.lua`
- `patch_ui_mp/ui_lua/ui_mp/t6/menus/publicgamelobby.lua`

Lua bytecode tool status:

- Nested-proto descriptor fields are now decoded: big-endian `uint32` at
  descriptor `+0x08` is the upvalue count and `+0x0C` is the parameter count
  (verified against every child of `textfieldbutton.lua`). This gives real
  function signatures instead of empty/`arg0..argN` parameter lists.
- Nested instruction count is a big-endian `uint16` at descriptor `+0x17` (the
  earlier single-byte read at `+0x18` truncated any function with >=256
  instructions and then misparsed code as constants). Fixing this recovered
  ALL nested function bodies: child-proto parse failures across
  `patch_ui_mp` + `patch_ui_zm` dropped from 124 files to 0, and lossless
  bytecode round-trip stays byte-identical (verified incl. `cacclassloadout`,
  whose `new` has 342 instructions).
- Current readable-source quality across the 186-file MP/ZM UI corpus: zero
  `arg0`/`var0`/`slot0`/`local_N`/`fn_N` placeholders, zero unresolved opcodes,
  zero decompile failures, and every file is valid balanced Lua (no open/`end`
  mismatch). Lossless bytecode round-trip is byte-identical (mp 139/139). One
  `-- control flow` comment remains corpus-wide (a break/continue inside a
  numeric `for` in eliteregistrationemailpopup).
- WARNING: `JMP sBx == 0` is a genuine no-op, but `JMP sBx == 1` skips one REAL
  instruction (e.g. the `return` in `if cond then return end`). A regression that
  treated sBx==1 as a no-op silently dropped `if` headers and left stray `end`
  in ~115 files. Only sBx==0 is a no-op. After ANY control-flow change, re-run a
  proper block-balance check (count if/function/for/while/repeat vs end/until —
  NOT `then`/`do`, which elseif inflates) and the lossless round-trip.
- Control-flow recovery now also handles `and`/`or` short-circuits (`TESTSET`,
  including call operands), boolean-valued comparisons
  (`cmp; JMP; LOADBOOL A 0 1; LOADBOOL A 1 0` -> `x = a op b`), call/`not`
  boolean-normalization sequences, no-op `JMP sBx=0`, redundant branch-exit
  jumps before `else`/`end`, and explicit `goto` labels for remaining
  unstructured backward jumps. Total `-- control flow` comments across the corpus
  fell from ~651 to 1 line.
- Generic `for ... in` loops are now located from the TFORLOOP back edge (the
  loop-entry JMP is at back-target - 1), fixing nested loops where an inner
  forward JMP also targets the TFORLOOP (previously produced an empty
  `for ... do end` with the body escaping, e.g. serverlist/cacweaponslot).
- Reassignments from `MOVE` into already-declared locals are now emitted, which
  restores iterator updates such as `child = sibling` in `while child do` loops.
- Open-argument calls are now tracked for `CALL* B=0` after a multireturn
  producer (`CALL* C=0`). This restores method-call arguments that were
  previously dropped, e.g. `text:setText(Engine.Localize(...))`,
  `image:setImage(RegisterMaterial(...))`, and `element:addElement(child)`;
  current MP/ZM verification has zero empty `setText()`/`setImage()`/`addElement()`
  calls.
- Remaining decompiler tail: one observed unstructured back-edge in
  `restrictitems` is preserved as `::loop_169::` / `goto loop_169` in MP and ZM;
  anonymous inline closures are hoisted instead of inline
  `function()...end`; names are inferred from export assignments, event strings,
  returned UI constructors, and distinctive string constants when available.
- `decompile-source` now recovers meaningful parameter names with no generic
  `arg0`/`var0`/`slot0`/`local_N` placeholders in the MP/ZM UI corpus: `self`
  for member methods, `(element, event)` for handlers, setter-derived names
  (`obj:setActionEventName(p)` -> `eventName`), table-field-key names, and
  `string`/`Localize` argument names (`text`).
- Control-flow recovery now emits structured `if`, `if/else`, `while`, numeric
  `for`, generic `for ... in`, and explicit `goto` labels for unstructured
  back-edges. Current MP/ZM verification has zero `-- control flow` comments.
- Root child functions get one consistent name used at both the declaration and
  every upvalue reference. Open-upvalue captures to parent register slots are
  resolved via a whole-root closure pre-scan, so forward-referenced module-level
  local functions bind correctly. Anonymous factory helpers are named from their
  returned constructor (`return X.new(...)` -> `createX`). Parent-side call-site
  and assignment clues are also used now, so captured helpers can be named from
  `registerEventHandler("streamed_image_ready", f)` -> `handleStreamedImageReady`
  and `button.isSelected = f` -> `isSelected`.
- The unpacker also carves `.menu` payloads verbatim (`extract_embedded_menu_blobs`)
  into `menus/` alongside `scripts/` and `ui_lua/`. Most BO2 UI is LUI (`.lua`);
  classic `menuDef_t` assets not stored as contiguous pointer blobs still need
  the zone asset-stream parser.
- Known remaining decompiler gaps: some stripped anonymous nested closures still
  use consistent inferred names because the original local debug symbols are not
  present in the observed bytecode; a few parent-local captures are named only as
  captured values; the `restrictitems` attachment loop still uses an explicit
  `goto` instead of a higher-level loop; and there is still no readable-source ->
  bytecode compiler (recompilation is currently lossless-bytecode / offset-patch
  only). Current MP/ZM readable output still contains 340 explicit
  `inferredFunction`/`inferredCallback`/`capturedValue` markers where no stronger
  naming evidence has been found yet.
- `lua_tool.py` parses the Treyarch Lua type table, root prototype metadata,
  root instruction stream, constants, and observed nested closure bodies.
- `lua_tool.py decompile-source` / `decompile-source-dir` write readable Lua
  decompiled source with recovered top-level assignments, function parameters,
  table constructors, method calls, recovered upvalue bindings, simple branches,
  numeric loops, and generic loops. Current MP/ZM verification has zero
  unresolved-opcode/control-flow comments, zero duplicate function parameter
  names, and zero empty common UI method calls from lost open arguments.
- Current readable-source improvements recover root-exported function names
  such as `CoD.TextFieldButton.new`, captured event-handler locals such as
  `button_over`, simple boolean `TEST` branches, early returns, and root
  closure upvalue bindings. Local variable names remain inferred unless debug
  symbols or original source names are found.
- Additional opcode recovery handles `SETLIST` array table literals,
  `SETTABLE_S_BK` constant-key/constant-value table writes, `_BK` arithmetic
  variants, and common generic `for` loops produced by `ipairs`/`pairs` style
  iterators. The current MP/ZM sample set has no remaining unresolved opcode or
  control-flow comments in `ui_lua_readable`.
- Xbox 360 stores Havok/T6 instruction words big-endian. The decoded fields
  match the known T6 Havok opcode packing after reversing each 4-byte
  instruction word for field extraction.
- Root closure counts are inferred from `CLOSURE` operands, not from the first
  post-constant footer value.
- `lua_tool.py decompile-json` / `decompile-json-dir` write editable bytecode
  workspace JSON files with the original bytecode embedded as base64 plus
  decoded constants/instructions.
- `lua_tool.py decompile-asm` / `decompile-asm-dir` write human-editable
  `.hksasm` files. These expose `.const` and `.inst` lines first, with a
  compressed workspace blob at EOF so unknown bytes can still be preserved.
- `lua_tool.py recompile` can rebuild from one editable JSON workspace.
- `lua_tool.py recompile-json-dir` rebuilds a folder of `.edit.json` workspaces
  back into compiled `.lua` payloads.
- `lua_tool.py recompile-asm` / `recompile-asm-dir` rebuild compiled `.lua`
  payloads from `.hksasm` files through the same validated workspace patcher.
- Current editable JSON rebuild support:
  - same-length string constant edits,
  - boolean/number constant edits,
  - decoded instruction edits through `opname`, `a`, `b`, `c`, `bx`, and `sbx`,
  - raw 4-byte instruction edits through `raw_hex`.
- The JSON compiler patches the original byte array by absolute offsets and
  validates the rebuilt payload by reparsing it. This preserves unknown Havok
  descriptor/footer bytes exactly.
- `lua_tool.py recompile` and `recompile-dir` also perform lossless bytecode
  re-emission for raw bytecode inputs.
- Root prototype header observed so far:
  - source string
  - little-endian line-defined / last-line-defined fields
  - three one-byte metadata fields
  - big-endian 16-bit instruction count
  - one-byte max-stack
  - 4-byte big-endian instructions
- Nested prototypes appear to have an additional/custom preamble or hash/id
  field before their body. Example: `textfieldbutton.lua` child data begins
  with `BD 80 50 A1`.
- Observed nested closure body descriptor:
  - 4-byte function id/hash, algorithm unknown.
  - descriptor bytes preserved as raw hex in JSON.
  - max-stack/register-like byte at descriptor offset `+0x14`.
  - one-byte instruction count at descriptor offset `+0x18`.
  - code starts at `align4(descriptor_start + 0x19)`.
  - constants use the same observed big-endian string-length layout.
- Full opcode semantics, high-level control flow recovery, local/upvalue naming,
  exact source recovery, length-changing rewrites, and readable Lua source
  compilation are still required before true source-level Lua round-tripping.

## Embedded GSC/CSC extraction

Observed Xbox compiled script blobs can be recovered by a local self-describing
pattern, even when the current top-level asset walker has not reached the parent
asset:

| Relative layout | Meaning |
| --- | --- |
| `FFFFFFFF` | following-name pointer marker |
| big-endian `uint32` | compiled payload length |
| `FFFFFFFF` | following-buffer pointer marker |
| ASCII path ending in `.gsc` or `.csc` plus `00` | script path/name |
| payload bytes | compiled script blob |

The extracted payloads currently start with `80 47 53 43` (`.GSC` with a high
platform/version byte). CSC payloads observed so far use the same payload magic.

The scanner labels these extractions high-confidence only when all of these are
true:

- The 12-byte local header is immediately before the path.
- The path ends in `.gsc` or `.csc`.
- The payload length is plausible and in bounds.
- The payload starts with the compiled script magic.

Verified counts:

- `common_zm.ff`: `10` embedded scripts extracted.
- `patch_mp.ff`: `266` embedded scripts extracted.
- `patch_zm.ff`: `199` embedded scripts extracted.
- `zm_transit_dr.ff`: `10` embedded scripts extracted.
- `zm_transit_dr_patch.ff`: `188` embedded scripts extracted.
- `zm_transit_patch.ff`: `95` embedded scripts extracted.
- `zm_highrise_patch.ff`: `136` embedded scripts extracted.
- `zm_nuked_patch.ff`: `35` embedded scripts extracted.
- `zm_prison_patch.ff`: `91` embedded scripts extracted.
- `zm_tomb_patch.ff`: `93` embedded scripts extracted.

Current aggregate inventory:

- `1,123` extracted script payloads across `10` scan directories.
- `822` unique script names.
- `837` unique payload hashes.
- By extension: `864` `.gsc`, `259` `.csc`.
- Inventory paths:
  - `script_inventory.tsv`
  - `script_inventory.json`
  - `script_inventory_summary.json`

Example extracted paths:

- `common_zm_ff_scan/assets/embedded_scripts/maps/mp/zombies/_zm_weap_thundergun.gsc`
- `common_zm_ff_scan/assets/embedded_scripts/clientscripts/mp/zombies/_zm_weap_thundergun.csc`
- `patch_zm_ff_scan/assets/embedded_scripts/maps/mp/animscripts/zm_death.gsc`
- `patch_zm_ff_scan/assets/embedded_scripts/clientscripts/mp/zombies/_zm.csc`
- `zm_transit_dr_ff_scan/assets/embedded_scripts/aitype/zm_ally_cdc.gsc`
- `zm_highrise_patch_ff_scan/assets/embedded_scripts/maps/mp/zm_highrise.gsc`
- `zm_highrise_patch_ff_scan/assets/embedded_scripts/clientscripts/mp/zm_highrise.csc`

## `common_zm.ff` current scan results

- Header magic: `TAffx100`.
- Version: `0x92` / `146`, big-endian.
- Auth magic: `PHEEBs71`.
- Name: `common_zm`.
- Payload begins at `0x0138`.
- Parsed xchunks: `826`.
- First chunk descriptor: size field at `0x0138`, encrypted size `66`, stream `0`.
- First decrypted XMem header: `FF 00 28 00 38`, meaning `dstSize=40`, `srcSize=56`, plus a 5-byte suffix.
- Most following decrypted chunks begin with `FF 7F C0 ...`, meaning `dstSize=0x7FC0`.
- Decrypted xchunks are dumped with `--dump-decrypted-xchunks` as `.xmem` files.
- Reconstructed zone stream: `common_zm_ff_scan/zone_decompressed.dat`.
- Reconstructed zone size: `26,967,772` bytes, SHA-256 `5bad5f135647b3e1078f41b791de596e70cf3cf0cd8f4af735af5f81caaccadc`.
- First-level `XAssetList`: `231` script strings, `0` dependencies, `1283` assets.
- `common_zm.ff` top-level asset types include `XAnimParts`, `XModel`, `Material`, `GfxImage`, `StringTable`, `VehicleDef`, and others; it does not contain top-level `menuDef_t` assets.
- Readable strings are dumped to `common_zm_ff_scan/readable_strings.tsv`; filtered path/menu/script-like strings are dumped to `common_zm_ff_scan/interesting_strings.tsv`.

## `ui_zm.ff` menu lead

- Header magic: `TAffx100`.
- Reconstructed zone stream: `ui_zm_ff_scan/zone_decompressed.dat`.
- Reconstructed zone size: `40,671,762` bytes, SHA-256 `3e23a9846e4b21f72db9c19239e9f62aedf8da55f2206684c44f915bf7713e89`.
- First-level `XAssetList`: `0` script strings, `0` dependencies, `514` assets.
- Top-level asset type counts include `menuDef_t: 3`, `Material: 198`, `WeaponVariantDef: 306`, `StringTable: 1`, and `MemoryBlock: 1`.
- `ui_zm_ff_scan/interesting_strings.tsv` contains many readable menu command/script strings, for example `open`, `exec`, `setdvar`, and `ui_mp/main.menu` references.
- General extraction frontier currently stops at asset index `0`, type `WeaponVariantDef`, decompressed stream offset `0x1050`.
- The raw unknown window at `ui_zm_ff_scan/assets/_unknown_stream_windows/00001050_next_unparsed.bin` contains readable strings such as custom-class/localized UI text. This suggests the next broad loader should handle `WeaponVariantDef` string fields or add a generic string-pointer trace for complex assets.

## `dev_zm.ff` extraction lead

- Header magic: `TAffx100`.
- Reconstructed zone stream: `dev_zm_ff_scan/zone_decompressed.dat`.
- First-level `XAssetList`: `99` assets.
- The asset table labels many early assets as type `42` / `StringTable` by OAT's T6 enum, but the observed Xbox stream body is a `name, len, buffer` raw blob layout.
- The scanner now extracts these observed type-42 blobs into `dev_zm_ff_scan/assets/type42_observed_blob/`.
- Current extracted examples:
  - `devgui_zombie.cfg` (`22,813` bytes)
  - `devgui_zombie_moon.cfg` (`970` bytes)
  - `devgui_zombie_transit.cfg` (`4,225` bytes)
  - `devgui_zombie_highrise.cfg` (`855` bytes)
  - `devgui_zombie_transit_dr.cfg` (`1,168` bytes)
  - `devgui_zombie_buried.cfg` (`4,805` bytes)
- This is the first confirmed broad raw asset extraction from an Xbox fastfile in the current tool.
- Current frontier stops after the observed `MemoryBlock` at decompressed offset `0x9D4C`. The next bytes look like several 12-byte pointer records followed by more readable config content (`overhead.cfg`), so the next blocker is general pointer/alias/MemoryBlock handling.

## Script inventory sweep

- The extractor now continues after experimental top-level asset walker failures. This was needed for `zm_transit_patch.ff`, where the prefix asset extraction hit an unterminated string at decompressed offset `0x269C00`; embedded script carving still succeeds and records parser warnings in metadata.
- Files that completed but currently contain no high-confidence embedded GSC/CSC blobs:
  - `common_patch_mp.ff`
  - `patch_ui_zm.ff`
  - `ui_zm.ff`
- `common_mp.ff` is not fully swept yet. It reconstructs a partial `zone_decompressed.dat`, then the current LZX helper fails at chunk `81`, file offset `0x0010B2BC`, with `lzx_decompress failed with code 2 at input offset 0x5`. This is a decompression/helper edge case, not proof that `common_mp.ff` lacks scripts.
- The current script extraction is deliberately local-pattern based. It recovers compiled payload bytes and path names; it does not yet prove the parent asset boundaries or parse the compiled script header.

## `zm_transit_dr.ff` script lead

- Header magic: `TAff0100`.
- Compression after Salsa20 xchunk decryption: raw deflate, not XMem/LZX.
- Reconstructed zone stream: `zm_transit_dr_ff_scan/zone_decompressed.dat`.
- Reconstructed zone size: `78,732,883` bytes, SHA-256 `6122e60f833a7e341c6aab108f00e93e526e340319fc154e67f687344884910f`.
- Zone prefix currently parsed as:
  - `zone_size`: `78,732,843`
  - `external_size`: `0`
  - xblock sizes: temp `4,780`, runtime virtual `881,424`, runtime physical `8,388,608`, delay virtual `7,585,792`, delay physical `0`, virtual `65,956,913`, physical `4,470,212`, streamer reserve `2,089,488`
- First-level `XAssetList`: `833` script strings, `0` dependencies, `2409` assets.
- Early top-level assets begin with `MemoryBlock`, then several `ScriptParseTree` entries.
- Full top-level asset entries are written to:
  - `zm_transit_dr_ff_scan/asset_entries.tsv`
  - `zm_transit_dr_ff_scan/asset_entries.jsonl`
- Diagnostic `ScriptParseTree` header candidates are written to `zm_transit_dr_ff_scan/scriptparsetree_candidates.tsv`.
- Earlier notes treated `0x00009224` as a `ScriptParseTree` named `TeamAlt`. That is now corrected: those bytes are inside the leading `MemoryBlock` record table.
- Observed `MemoryBlock` layout now parsed:
  - 12-byte header: name pointer, record count, data pointer
  - following name string
  - `record_count * 12` bytes of raw records
  - variable label strings until the next plausible asset header
- For `zm_transit_dr.ff`, the first `MemoryBlock` has `record_count = 7` and labels `0`, `base`, `lowmip`, `code_post_gfx_zm`, `common_zm`.
- After the corrected MemoryBlock parse, the scanner reaches the first `ScriptParseTree` at decompressed offset `0x92A1` and extracts a low-confidence 44-byte stub named `scriptparsetree_0001.bin`. The next script parse still loses sync, so GSC/CSC extraction is not solved yet.
- Script-focused update: type-48 ranges are now carved by next-header boundaries instead of blindly trusting the `len` field. In `zm_transit_dr.ff`, the three ranges currently resolve to embedded strings:
  - `texturelist/zm_transit_transit.csv`
  - `texturelist/zm_transit_town.csv`
  - `texturelist/zm_transit_farm.csv`
- These type-48 ranges are preserved under `assets/scriptparsetree_ranges/`, but they are distinct from the high-confidence embedded GSC/CSC blobs above.

## OpenAssetTools experiment

- OpenAssetTools confirms the useful T6 constants: magic values, Xbox/Xenon version `146`, four encrypted xchunk streams, max xchunk size `0x8000`, signed/encrypted Xbox zones, and `TAff0100` vs `TAffx100` compression selection.
- A local OAT build was patched far enough to attempt Xbox zone loading instead of raw BE dumping.
- Minimal endian fixes were added locally for zone size and xblock allocation reads.
- The x86 build got past the first endian allocation failure but later overflowed a T6 XBlock while loading `ui_zm.ff`.
- The x64 build reached an access violation. The likely cause is that generated asset loaders still use host struct sizes/pointers in places, while Xbox asset structs are 32-bit and big-endian.
- Conclusion: OAT is valuable as a format reference and may be useful later for menu writer logic, but current extraction work should stay in the Python scanner until a proper Xbox-aware stream/struct layer exists.

## Unknowns to investigate

- Meaning of `PHEE`.
- Meaning of `Bs71`.
- Whether bytes at `0x0014` are always zero or can contain flags.
- Whether signature bytes at `0x0038..0x0137` participate in nonce derivation.
- Meaning of xchunk EOF/padding bytes after the final zero marker, beyond the observed all-zero padding.
- Post-decompression zone header layout for Xbox 360 BO2.
- Exact per-asset body parsing for Xbox 360 BO2.
- `menuDef_t` body layout and how its pointers map to readable command strings.
- Whether `ScriptParseTree` buffers are inline in the decompressed stream, separately block-ordered, or require explicit pointer following.
- Full meaning of observed pointer values such as direct low offsets (`0x00012D3C -> "TeamAlt"`) versus OAT-style packed block offset pointers.
- Why Xbox `MemoryBlock` stream layout differs from OAT's generated T6 struct test, which reports `MemoryBlock` as 20 bytes.
- How `ZoneInputStream::PushBlock` maps to the physical decompressed stream. OAT loaders push `XFILE_BLOCK_TEMP` for asset structs and `XFILE_BLOCK_VIRTUAL` for names/buffers, but the decompressed byte order around `0x920A` is not yet fully explained.
- Whether Xbox type `42` should be treated as RawFile-like in some zones, or whether the OAT T6 enum is correct but the asset body is platform/transient data with a different layout.
- Full loader support for common complex assets: `WeaponVariantDef`, `Material`, `GfxImage`, `StringTable`, `SndBank`, and `MemoryBlock`.
- Whether embedded script blobs are nested inside specific complex asset parents or are recoverable as independent logical assets for recompilation.
- Exact compiled GSC/CSC header fields after `80 47 53 43`.
- Why `common_mp.ff` chunk 81 fails the current XMem/LZX helper and whether that chunk uses a different XMem form, reset behavior, or helper bug.

## Suggested next steps

1. Implement a minimal Python `ZoneInputStream` emulator for 32-bit big-endian T6, matching OAT block allocation, following pointers, insert pointers, and offset pointers.
2. Parse the compiled script payload header (`80 47 53 43 ...`) into structured metadata: source path, string/function/import tables, bytecode section offsets, and checksum/hash fields.
3. Run the embedded script extractor across the remaining map `.ff` files and keep updating the global script inventory with duplicate detection.
4. Add per-asset raw dumps with verified boundaries before adding semantic decompilation.
5. Add extraction for RawFile/ScriptParseTree assets after asset entries can be parsed without heuristic-only scans.
6. Compare OAT's T6 asset structures with Xbox 360 pointer/endian handling before attempting recompilation.
7. Investigate `common_mp.ff` chunk 81 by saving decrypted chunk bytes, checking XMem header variants, and comparing OAT's LZX path.
8. Build the next broad loader around the `dev_zm.ff` frontier: resolve the post-`MemoryBlock` pointer records and extract the following `overhead.cfg`-style blobs.
9. Add a generic complex-asset string pointer trace for `WeaponVariantDef` so `ui_zm.ff` can advance past asset index `0`.
10. Use OAT's T6 ZoneCode files for `menuDef_t` later, after script extraction and broad fastfile unpacking are further along.

## GSC/CSC decompile + full recompile round-trip (implemented)

GSC/CSC scripts are now decompiled to editable source on unpack and recompiled
back into a working `.ff` on repack, via the vendored `gsc-tool` (xensik, v1.4.10,
`-g t6 -s xb2`, server=`.gsc` / client=`.csc`; `_tools/gsc-tool/gsc-tool.exe`, not
committed — run `fetch_gsc_tool.py`). Decompiled source lands in `scripts_src/`;
verbatim compiled payloads stay in `scripts/`.

Zone-splice format facts (from OpenAssetTools' generated T6 loaders +
`scriptparsetree_t6_load_db.cpp` / `rawfile_t6_load_db.cpp`, cross-checked by
measuring real zones):

- `ScriptParseTree` (`.gsc`/`.csc`) and `RawFile` (`.lua`) share one stream
  layout: 12-byte struct `{const char* name=-1; int len; byte* buffer=-1;}` then
  the inline name string then the buffer of **`len + 1`** bytes (trailing `\0`).
- Both buffers load into **`XFILE_BLOCK_VIRTUAL`** (index 5). A net buffer-size
  change adjusts that block-size field (offset `8 + 5*4`), conservatively.
- **The zone stream carries no alignment padding** between assets — alignment is
  applied to destination memory pointers only. Measured: adjacent script records
  are separated by exactly 1 byte (the buffer's own `+1` null) and `pos % 16` is
  uniformly random. So a buffer can grow/shrink and the rest of the stream is
  just shifted; no pointer relocation is needed (all pointers are `-1`/`-2`/null).
- `zone_size` (prefix offset 0) `== filesize - 40` and is rewritten on rebuild.

`zone_rebuild.py` implements this: `parse_records` → `splice_zone` (rewrite each
edited buffer + its `len` field, fix the two size fields) → `recompile_and_rebuild`
(recompile only sources whose sha changed vs the manifest baseline). Regression
gate `verify_identity` (identity rebuild reproduces the zone byte-for-byte) passes
on every sample zone incl. the 27 MB `common_zm`. End-to-end verified: editing a
GSC source, repacking, and re-unpacking yields a byte-identical rebuilt zone with
the edit present.

Lua recompile uses the existing lossless `.hksasm`/workspace path
(`lua_tool.compile_source_to_bytecode`, wired via `ui_lua_hksasm` in the manifest);
47/47 UI Lua files round-trip byte-identical. A from-scratch source-level
HavokScript compiler (arbitrary readable-`.lua` edits, add/remove instructions)
still needs a byte-exact full serializer first — parser gaps to close:
child-proto `align4` padding, header bytes `0x0E`–`0x0F`, and unparsed debug tails.
