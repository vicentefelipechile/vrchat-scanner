# VRCStorage Scanner Configuration

This document explains the tuneable values in `src/config.rs`. If you are a non-technical contributor, community moderator, or server administrator looking to adjust how the scanner scores or flags content, you are in the right place.

You do **not** need to understand Rust or the inner workings of the scanner to make changes here.

---

## 1. How to Edit the Config

1. Open `src/config.rs` in any text editor.
2. Find the constant you want to change (they are well-documented inside the file).
3. Change the number or add/remove text from a list.
4. If you have Rust installed locally, run `cargo test` to ensure nothing is broken.
5. Submit your change via a Pull Request with a brief explanation of *why* the value needed adjusting (e.g. "Too many false positives on PNG files" or "This domain is safe because it belongs to a verified toolmaker").

---

## 2. Risk Score Bands (`SCORE_*_MAX`)

Every package scanned receives a **total risk score** (a sum of all finding points). That number is compared against the maximums defined here to assign a final level.

* `SCORE_CLEAN_MAX` (Default: 30) — The package is essentially benign and can be auto-published.
* `SCORE_LOW_MAX` (Default: 75) — Some slightly unusual behavior, but usually safe. Published with a note.
* `SCORE_MEDIUM_MAX` (Default: 100) — Noticeable suspicious behavior. Manual review is recommended.
* `SCORE_HIGH_MAX` (Default: 150) — High risk. Package is retained pending mandatory review.
* **Critical** (> 150) — Rejected outright.

**When to change:** If you find the moderation queue is flooded with false positives, you can raise `CLEAN_MAX`/`LOW_MAX`. If dangerous payloads are slipping through, lower `MEDIUM_MAX`/`HIGH_MAX`.

---

## 3. Domain Whitelist (`SAFE_DOMAINS`)

The scanner flags any URL it finds inside scripts or DLLs, *unless* the URL belongs to a domain on the `SAFE_DOMAINS` list.

**When to add a domain:**
Add a domain if it is a commonly used, legitimate endpoint for VRChat tools or Unity (e.g. `github.com`, `vrchat.com`).

**When NOT to add a domain:**
Never add personal websites, discord channels (e.g., `discord.gg` invites), or dynamic DNS providers. Only add domains whose ownership is stable and managed by a trustworthy organization.

---

## 4. Forbidden Extensions (`FORBIDDEN_EXTENSIONS`)

Any file matching these extensions inside a package triggers an immediate `Critical` finding. Legitimate VRChat avatars and worlds do not contain `.exe`, `.bat`, or `.sh` files.

**When to edit:** If a new script or executable format becomes popular for distributing malware, add its extension (lowercase, no dot).

---

## 5. Entropy Thresholds (`ENTROPY_*`)

**Entropy** measures how "random" data looks.
* Normal code has patterns (entropy 5.5—6.5).
* Packed, encrypted, or compressed data looks completely random (entropy 7.2—8.0).

**PE (DLL) Entropy:**
* `ENTROPY_PE_HIGH` (Default: 7.2) — Almost certainly packed/encrypted.
* `ENTROPY_PE_SUSPICIOUS` (Default: 6.8) — Unusually high, but might just be a section with lots of dense string data.

**Media Entropy:**
* `ENTROPY_TEXTURE_HIGH` (Default: 7.5) — Uncompressed image (TGA, BMP) that looks random.
* `ENTROPY_AUDIO_MIN`/`MAX` (Default: 5.0—7.9) — Expected range for an uncompressed WAV.

**When to change:** If legitimate `.dll` files compiled with a new Unity version are suddenly being flagged for entropy, you might need to raise `ENTROPY_PE_SUSPICIOUS` to `6.9` or `7.0`.

---

## 6. Context Score Reductions (`REDUCE_*`)

Sometimes a finding looks dangerous in a vacuum, but is actually fine in a specific context.

* `REDUCE_HTTP_VRC` — Reduces the penalty for HTTP requests if the script uses the VRChat SDK (which needs HTTP to upload avatars).
* `REDUCE_REFLECT_EDITOR` — Reduces penalty for `Reflection.Emit` if the script is an Editor tool.
* `REDUCE_POLYGLOT_NO_LOADER` — Heavily reduces the score of an embedded malicious file (like a ZIP hidden in an image) if there is no C# script capable of actually loading and executing it.

**When to change:** If a context reduction is masking too much risk, increase the `REDUCE_*` value so it leaves more points on the finding.

---

## 7. Per-finding Points (`PTS_*`)

This represents the bulk of the configuration. Every rule identifier (e.g., `CsProcessStart`) has an associated `PTS_*` constant defining its base penalty.

**General Point Tiers:**
* **75–100 pts:** Critical indicators (launching processes, path traversal).
* **45–74 pts:** High indicators (WinInet imports, raw sockets, double extensions).
* **20–44 pts:** Medium indicators (file writes, `unsafe` blocks, excessive DLLs).
* **1–19 pts:** Low indicators (short identifiers, missing generic meta files).
