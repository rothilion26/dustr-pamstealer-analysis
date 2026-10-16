# Hunting notes

## YARA rules (`dustr_pamstealer.yar`)

| Rule | Target | Tested |
|---|---|---|
| `PamStealer_Dustr_Stage3_Agent` | Rust agent (universal or arm64 slice) | ✔ matches both; no hits in Finder.app, `/bin`, `/usr/bin`, `/usr/libexec`, Utilities |
| `PamStealer_Dustr_Stage3_EmbeddedHelperKey` | ChaCha20 key and nonce for `kh_tmp` (build-specific) | ✔ |
| `PamStealer_Dustr_KeychainHelper_kh_tmp` | the decrypted helper | ✔ |
| `PamStealer_Dustr_Stage2_Installer_JXA` | decrypted installer (memory or analyst output) | ✔ |

There is no rule for the Stage 1 loader. Its obfuscated identifiers change per build, so prefer the behavioural hunts below.

## Behavioural hunts (macOS EDR / Unified Log / ESF)

1. **Remote script piped into JXA.** Look for an `osascript` process with `-l JavaScript` and no script path, whose parent is a shell that also spawned `curl -sfL` within about a second. The ClickFix one-liner looks like `curl … | osascript -l JavaScript`.
2. **Fake Finder.**
   - Any process whose executable path matches `*/Finder.app/Contents/MacOS/*` but lies outside `/System/Library/CoreServices/`.
   - Bundles whose `CFBundleIdentifier` starts with `apple.finder.` without the `com.` prefix.
3. **Hex-named executables** (`[0-9A-F]{8}`) inside app bundles under `~/Library/Caches/` or `~/Library/Application Support/`.
4. **Keychain prompt loop.** Repeated `SecKeychainFindGenericPassword` prompts (up to 10) from an ad-hoc-signed binary with identifier `kh_tmp`, usually launched from `/private/tmp` or a cache directory.
5. **Browser launched with DevTools by a non-browser parent.** A Chromium-family browser started through `NSWorkspace` with a remote-debugging argument, followed by loopback connections to `127.0.0.1` from the parent process.
6. **Ethereum RPC from a non-wallet process.** HTTPS to public RPC endpoints (`eth.drpc.org`, `ethereum-rpc.publicnode.com`, `eth.llamarpc.com`, `1rpc.io`) from a process inside a fake `Finder.app`. These are legitimate services, so treat this as a behavioural signal, not a blocklist entry.

## Quick host check

```bash
ls -la ~/Library/Caches/com.apple.finder/Finder.app 2>/dev/null
mdfind "kMDItemCFBundleIdentifier == 'apple.finder.*'"
```
