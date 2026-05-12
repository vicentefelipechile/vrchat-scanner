# vrcstorage-scanner

> Static analysis scanner for Unity/VRChat packages — detects malicious scripts, dangerous DLLs, and suspicious assets **without executing any code**.

[![Rust](https://img.shields.io/badge/rust-1.76%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Release](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/release.yml/badge.svg)](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/release.yml)
[![CI](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/vicentefelipechile/vrchat-scanner/actions/workflows/ci.yml)

---

## What it detects

- 🔴 **Critical** — `Process.Start()`, `Assembly.Load(bytes)`, embedded executables, path traversal
- 🟠 **High** — Polyglot files (PE/ZIP inside textures or audio), unknown `[DllImport]`, hardcoded IPs, shell commands, W+X PE sections
- 🟡 **Medium** — HTTP clients, `BinaryFormatter`, `unsafe` blocks, magic byte mismatches, high-entropy sections, future `.meta` timestamps
- 🟢 **Low** — Missing `.meta` files, obfuscated identifiers, excessive DLL count, malformed audio headers

## Supported formats

`.unitypackage` · `.zip` · `.cs` · `.dll`

---

## Downloads

Grab the latest release from the [Releases page](https://github.com/vicentefelipechile/vrchat-scanner/releases):

| File | Platform | Notes |
|---|---|---|
| `gui-vrcstorage-scanner_*_x64-setup.exe` | Windows 10/11 | **GUI installer** (recommended) |
| `gui-vrcstorage-scanner_*_x64_en-US.msi` | Windows 10/11 | GUI MSI installer |
| `gui-vrcstorage-scanner_*_amd64.AppImage` | Linux x86_64 | **GUI AppImage** (universal) |
| `gui-vrcstorage-scanner_*_amd64.deb` | Ubuntu / Debian | GUI DEB package |
| `gui-vrcstorage-scanner_*_x86_64.rpm` | Fedora / RHEL | GUI RPM package |
| `vrcstorage-scanner-windows-x86_64.exe` | Windows 10/11 | CLI binary only |
| `vrcstorage-scanner-linux-x86_64` | Linux x86_64 | CLI binary only |

> **Verify CLI integrity:** each CLI binary ships with a `.sha256` checksum file.
> ```
> sha256sum -c vrcstorage-scanner-linux-x86_64.sha256
> ```

---

## Quick start (CLI)

```bash
cargo build --release

# Scan a package
./target/release/vrcstorage-scanner scan my_avatar.unitypackage

# JSON output
./target/release/vrcstorage-scanner scan my_avatar.unitypackage --output json

# Sanitize (remove/neutralize threats)
./target/release/vrcstorage-scanner sanitize my_avatar.unitypackage

# Extract package contents
./target/release/vrcstorage-scanner export my_avatar.unitypackage

# Show internal file tree
./target/release/vrcstorage-scanner tree my_avatar.unitypackage
```

**Drag-and-drop:** drop any supported file onto the executable. The scanner runs automatically and waits for you to press Enter before closing.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean / Low / Medium / High |
| `2` | **Critical** — package should be rejected |
| `1` | Fatal error |

---

## Risk levels

| Score | Level | Action |
|---|---|---|
| 0 – 30 | **Clean** | Auto-publish |
| 31 – 60 | **Low** | Publish with audit note |
| 61 – 100 | **Medium** | Manual review recommended |
| 101 – 150 | **High** | Mandatory manual review |
| 151+ | **Critical** | Reject immediately |

---

## Desktop GUI

Install the GUI from the Releases page. It wraps the full scanner engine in a native window with drag-and-drop, an interactive file-tree, sanitize and export panels, and scan history.

To build from source:

```bash
cd tauri
npm install
npm run tauri dev      # development
npm run tauri build    # production installers
```

See [tauri/README.md](tauri/README.md) for prerequisites and details.

---

## Building from source (CLI)

```bash
git clone https://github.com/vicentefelipechile/vrchat-scanner.git
cd vrcstorage-scanner
cargo build --release
# Binary: ./target/release/vrcstorage-scanner
```

**Prerequisites:** Rust 1.76+ — no other system dependencies.

## Running tests

```bash
cargo test           # all tests
cargo clippy         # lint
cargo bench          # benchmarks
```

---

## License

[MIT](LICENSE)

---

> For architecture, coding conventions, and contribution rules → [AGENTS.md](AGENTS.md)
>
> For tuning scanner sensitivity (thresholds, point values, domain whitelist) → [CONFIG.md](CONFIG.md)
