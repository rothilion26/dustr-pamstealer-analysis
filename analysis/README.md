# Reproducing the analysis

These scripts re-implement the malware's crypto in Python and only **read** the samples as data. They never load, evaluate or execute sample code. Outputs are written as `*.inert` files with mode `0444`, so they are not executable.

**No samples are distributed here.** If you obtain them yourself, do it from an isolated machine on a network you are comfortable exposing, and check the hashes before running anything below:

| Sample | SHA-256 |
|---|---|
| Stage 1 JXA loader (`mxgEV2s0Jccp.js`) | `08d9c67ae8f77e1e495606d002b8ada735553c5f01dfd5a927aba3967117848a` |
| Stage 3 universal Mach-O | `094be93a4fdd3ef075959fb4bd3333f66e31abd1254f66ebaa0ce9460dc7b84a` |
| Stage 3 arm64 slice | `02225673558a518658ac12b54591b33a6e459dcc95f25546e839a291c35c146b` |

The constants and addresses in the scripts are **build-specific**. A different build needs the same method applied again (see `docs/writeup.md`).

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r analysis/requirements.txt
```

## Stage 1: victim key and blob decryption

Use the original loader, not restringer output; restringer folds the key derivation into a wrong constant.

```bash
python3 -I analysis/stage1/stage1_decrypt.py <stage1.js> out/stage1
```

Expected output: three `tag OK` lines, followed by the Stage 3 URL, the install directory and `stage2_installer.js.inert`.

## Stage 3: config and embedded helper

```bash
.venv/bin/python -I analysis/stage3/stage3_config.py <stage3.bin> --helper out/stage3
```

The script first checks that all eight decoy K constants evaluate to 0. It then finds the single authenticating global (`0xcd550f10cf1cc109`), prints the four config values, and extracts `kh_tmp.bin.inert`.

## Supporting tools

- **`stage3/derive_k_table.py`** maps share write sites to K constants, working from `otool` disassembly text.
- **`stage3/DecompileTargets.java`** is a Ghidra headless post-script that decompiles a list of functions and their callees to C files. Ghidra only analyses the bytes; it does not run them.

```bash
analyzeHeadless <proj_dir> <proj_name> -import <stage3_arm64.bin> \
  -scriptPath analysis/stage3 -postScript DecompileTargets.java <out_dir> 1 150 0x10005cdc0 0x10005d34c
```
