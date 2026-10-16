# Dustr / PamStealer variant: static analysis

Static analysis of a macOS infostealer campaign that was promoted through X ads for a fake Mac cleaner called **"Dustr"**. The sample is a newer, ClickFix-delivered variant of the family Jamf Threat Labs tracks as **PamStealer** (also called "Fake Maccy Stealer"; operator-internal name "Avenger").

📄 **Full write-up:** [docs/writeup.md](docs/writeup.md) · 🇹🇷 **Türkçe özet:** [docs/ozet-tr.md](docs/ozet-tr.md)

## Highlights

- **Environment-keyed Stage 1 (JXA).** Eight host checks feed the decryption key. On a VM, under a debugger, or on a Mac configured for a CIS country, the key is wrong and nothing decrypts. The real key was rebuilt statically, using the payload's own 16-byte authentication tag as an oracle.
- **Stage 3 config recovered fully statically, with no emulation.** It uses HKDF-SHA256 over an 8-share XOR secret, four of whose shares are decoys that always contribute zero, followed by XChaCha20-Poly1305. Every string authenticates:
  - **`hxxps://gatewaysync[.]pro/api/sync`** (most likely C2)
  - campaign tag `detox`
  - Ethereum config contract `0x33DfCf…693d`
  - a 32-byte key
- **Embedded Keychain helper `kh_tmp`** (ChaCha20-encrypted inside the agent). It reads Keychain generic passwords and re-prompts the user up to 10 times when access is denied.
- **Infrastructure link:** the delivery domain and the C2 got their certificates **4 seconds apart**.

## Repository layout

```
docs/       writeup.md (EN), ozet-tr.md (TR)
iocs/       iocs.csv, iocs.json  (defanged; refang before ingesting)
detection/  dustr_pamstealer.yar, hunting.md
analysis/   reproducible decryption scripts (stage1/, stage3/) + Ghidra script
```

**No malware samples are included.** The scripts expect you to supply the samples yourself; see [analysis/README.md](analysis/README.md).

## Safety

- No stage was executed natively, and the C2 was never contacted.
- The method is described in [docs/writeup.md § Methodology and safety](docs/writeup.md#11-methodology-and-safety).
- This analysis was carried out with the help of an AI assistant (Claude, Anthropic). The author reviewed the findings and is responsible for them.

## Related work

- Jamf Threat Labs: PamStealer (2026-07-02)
- ManageEngine: Fake Maccy Stealer
- [samuelscheit/malware-analysis: dustr_app](https://github.com/samuelscheit/malware-analysis/tree/0462345191260e7389bf5a423fe97153c814381f/dustr_app), an analysis of the 10 October build
