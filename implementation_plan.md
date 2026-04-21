# Sanitize Subcommand — `vrcstorage-scanner sanitize`

Implementar la capacidad de **neutralizar** entradas maliciosas de un `.unitypackage` reconstruyendo un archivo limpio.
La estrategia es **inteligente por tipo de archivo y por contexto**.

> **Invariante de seguridad:** el archivo original **NUNCA se modifica**. Siempre se escribe una copia nueva.

---

## Matriz de decisión de sanitización

| Tipo de archivo | Condición de eliminación | Acción |
|---|---|---|
| `.cs` Script | Findings >= `min_severity` | **Comentar las líneas exactas** — no se borra el archivo |
| `.dll` binario | Cualquier finding >= `min_severity` | **Eliminar GUID completo** del TAR |
| Texture / Audio | `POLYGLOT_FILE` o `MAGIC_MISMATCH` **y** `context.has_loader_script == true` | **Eliminar GUID completo** |
| Texture / Audio | `POLYGLOT_FILE` o `MAGIC_MISMATCH` **pero** `has_loader_script == false` | **Conservar** — sin activador, el payload es inerte |
| Texture / Audio | `TEXTURE_HIGH_ENTROPY` / `AUDIO_UNUSUAL_ENTROPY` solo | **Conservar siempre** — falso positivo sin loader |
| Prefab con `PREFAB_INLINE_B64` >= `min_severity` | — | **Eliminar GUID completo** |
| Findings package-level (`EXCESSIVE_DLLS`, `CS_NO_META`, `DLL_MANY_DEPENDENTS`) | — | **Ignorar** — no hay un archivo específico que borrar |

> **Fundamento del filtro de assets:** un archivo `.png` o `.wav` con bytes sospechosos solo es peligroso si existe un script que lo cargue y ejecute. `AnalysisContext.has_loader_script` ya es propagado por el pipeline existente y captura exactamente esa condición (`CsAssemblyLoadBytes`, `CsProcessStart`, `CsFileWrite`). Si no hay loader, el asset es sospechoso pero inerte — eliminarlo solo rompería el paquete sin aportar seguridad real.

---

## Propuesta de uso CLI

```
vrcstorage-scanner sanitize <FILE> [OPTIONS]

Options:
  -o, --output <FILE>             Salida [default: <input>-sanitized.unitypackage]
  -s, --min-severity <LEVEL>      Umbral mínimo: low|medium|high|critical [default: high]
  -d, --dry-run                   Simula sin escribir archivo de salida
      --json                      Emitir reporte en JSON
```

---

## Flujo drag-and-drop

Tras imprimir el reporte de scan en modo drag-and-drop, **solo si el archivo es `.unitypackage`**:

```
  Condition: ANY finding.severity >= High  (severidad bruta, no el score reducido por contexto)
```

Si se cumple la condición:

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  Se detectaron amenazas High/Critical en el paquete.             │
  │  ¿Desea crear una copia sanitizada?                              │
  │                                                                  │
  │  · Scripts: se comentarán las líneas maliciosas (no se borran)   │
  │  · DLLs y payloads: se eliminarán del paquete                    │
  │  · Umbral usado: HIGH                                            │
  │                                                                  │
  │  Salida: <nombre>-sanitized.unitypackage                         │
  │                                                                  │
  │  [S] Sí   [N] No (o Enter)                                       │
  └──────────────────────────────────────────────────────────────────┘
```

- Si el usuario responde `S`/`s`/`Y`/`y` → ejecutar sanitize con threshold `High` y mostrar `SanitizeReport`.
- Cualquier otra tecla (incluyendo Enter) → omitir.
- Siempre terminar con `wait_for_keypress()`.

---

## Proposed Changes

---

### Componente 1 — `line_numbers` en `Finding`

Para comentar la línea exacta en scripts, el struct `Finding` debe registrar las posiciones.

#### [MODIFY] [finding.rs](file:///c:/Users/Computador/Documents/github/vrchat-analyzer/src/report/finding.rs)

```rust
pub struct Finding {
    pub id: FindingId,
    pub severity: Severity,
    pub points: u32,
    pub location: String,
    pub detail: String,
    pub context: Option<String>,
    /// 1-indexed line numbers where the pattern was found.
    /// Empty for binary assets, DLLs, and package-level findings.
    pub line_numbers: Vec<u64>,
}
```

Agregar método builder en `impl Finding`:

```rust
pub fn with_line_numbers(mut self, lines: Vec<u64>) -> Self {
    self.line_numbers = lines;
    self
}
```

> El campo también mejora el reporte `scan` normal — el JSON mostrará en qué líneas están los problemas.

---

### Componente 2 — Emisión de `line_numbers` en analizadores de scripts

#### [MODIFY] [pattern_matcher.rs](file:///c:/Users/Computador/Documents/github/vrchat-analyzer/src/analysis/scripts/pattern_matcher.rs)

Agregar helper privado:

```rust
fn matching_lines(pattern: &Regex, source: &str) -> Vec<u64> {
    source.lines().enumerate()
        .filter_map(|(i, line)| {
            if pattern.is_match(line) { Some(i as u64 + 1) } else { None }
        })
        .collect()
}
```

Cada `Finding::new(...)` se encadena con `.with_line_numbers(matching_lines(&CS_PROCESS_START, source))`.

#### [MODIFY] [url_extractor.rs](file:///c:/Users/Computador/Documents/github/vrchat-analyzer/src/analysis/scripts/url_extractor.rs)

El `find_iter()` ya devuelve `Match` con `.start()`. Calcular la línea:

```rust
let line_num = source[..m.start()].bytes().filter(|&b| b == b'\n').count() as u64 + 1;
```

Agregar `.with_line_numbers(vec![line_num])` al finding.

#### [MODIFY] [obfuscation.rs](file:///c:/Users/Computador/Documents/github/vrchat-analyzer/src/analysis/scripts/obfuscation.rs)

Para `CsBase64HighRatio`, `CsXorDecryption`, `CsUnicodeEscapes`: usar la misma función helper `matching_lines()`.

---

### Componente 3 — Módulo `sanitize`

#### [NEW] `src/sanitize/mod.rs`

```rust
pub struct SanitizeReport {
    pub neutralized_scripts: Vec<NeutralizedScript>,
    pub removed_entries: Vec<RemovedEntry>,
    pub skipped_assets: Vec<SkippedAsset>,   // assets sospechosos conservados por falta de loader
    pub kept_entries: usize,
    pub original_score: u32,
    pub residual_score: u32,
    pub output_path: Option<PathBuf>,        // None en dry-run
    pub dry_run: bool,
}

pub struct NeutralizedScript {
    pub guid: String,
    pub original_path: String,
    pub commented_lines: Vec<u64>,
    pub finding_ids: Vec<FindingId>,
}

pub struct RemovedEntry {
    pub guid: String,
    pub original_path: String,
    pub finding_ids: Vec<FindingId>,
}

pub struct SkippedAsset {
    pub guid: String,
    pub original_path: String,
    pub reason: &'static str,   // "no loader script in package"
}
```

**Función pública:**

```rust
pub fn run_sanitize(
    input_path: &Path,
    output_path: &Path,
    min_severity: Severity,
    dry_run: bool,
) -> crate::utils::Result<SanitizeReport>
```

**Lógica de decisión** interna (dentro de `run_sanitize`):

```
1. Ejecutar run_scan(input_path) y obtener (ScanReport, AnalysisContext).
   → Necesita que pipeline exponga la AnalysisContext (ver Componente 6).

2. Para cada GUID en el PackageTree:
   a. Recopilar findings con severity >= min_severity y location == original_path del GUID.
   b. Si no hay findings → kept_entries++, sin cambios.

   c. Si asset_type == Script:
      → Agregar a guid_script_patches con las líneas a comentar.
      → NeutralizedScript.

   d. Si asset_type == Dll:
      → Agregar a guids_to_remove → RemovedEntry.

   e. Si asset_type ∈ {Texture, Audio}:
      → Si context.has_loader_script == true Y finding ∈ {PolyglotFile, MagicMismatch}:
           guids_to_remove → RemovedEntry.
      → Si no hay loader:
           SkippedAsset (conservado, reportado).

   f. Si asset_type ∈ {Prefab, ScriptableObject} Y finding == PrefabInlineB64:
      → guids_to_remove → RemovedEntry.

3. Si NOT dry_run:
   → Llamar a rebuilder::rebuild_unitypackage(original_bytes, guids_to_remove, guid_script_patches)
   → Escribir Vec<u8> en output_path.
```

#### [NEW] `src/sanitize/script_neutralizer.rs`

```rust
/// Comments out the specified 1-indexed lines in a C# source string.
pub fn neutralize_script(source: &str, lines_to_comment: &[u64]) -> String {
    source.lines().enumerate()
        .map(|(i, line)| {
            if lines_to_comment.contains(&(i as u64 + 1)) {
                format!("/* SANITIZED */ // {line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
```

#### [NEW] `src/sanitize/rebuilder.rs`

```rust
pub fn rebuild_unitypackage(
    original_data: &[u8],
    guids_to_remove: &HashSet<String>,
    guid_script_patches: &HashMap<String, Vec<u8>>,  // GUID → nuevos bytes del asset
) -> crate::utils::Result<Vec<u8>>
```

**Algoritmo:**
1. Descomprime gzip si el magic es `0x1f 0x8b`.
2. Itera el TAR entrada por entrada:
   - `guid = path.splitn(2, '/')[0]`
   - Si `guid ∈ guids_to_remove` → skip completo.
   - Si `guid ∈ guid_script_patches` && `filename == "asset"` → escribe los bytes parcheados.
   - Si no → copia la entrada original íntegra (header + bytes).
3. Finaliza el TAR builder, recomprime con gzip nivel 6.
4. Devuelve `Vec<u8>`.

> **Dependencias:** `tar` + `flate2` — ya en `Cargo.toml`, sin nuevas dependencias.

---

### Componente 4 — CLI (`main.rs`)

#### [MODIFY] [main.rs](file:///c:/Users/Computador/Documents/github/vrchat-analyzer/src/main.rs)

**Subcomando `Sanitize`:**

```rust
/// Remove or neutralize malicious entries from a Unity package
Sanitize {
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Output path [default: <input>-sanitized.unitypackage]
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Minimum severity to act on: low|medium|high|critical [default: high]
    #[arg(short = 's', long, default_value = "high")]
    min_severity: String,

    /// Show what would happen without writing any file
    #[arg(short = 'd', long)]
    dry_run: bool,

    /// Emit JSON report
    #[arg(long)]
    json: bool,
},
```

**Extensión del flujo drag-and-drop:**

```rust
// Después de run_scan_command() en el arm drag-and-drop:
if file.extension().map(|e| e == "unitypackage").unwrap_or(false) {
    let has_high = report.findings.iter().any(|f| f.severity >= Severity::High);
    if has_high && prompt_sanitize(caps) {
        let out = default_sanitize_output(&file);  // <stem>-sanitized.unitypackage
        run_sanitize_command(&file, Some(&out), "high", false, false, caps);
    }
}
wait_for_keypress(caps);
```

**Función `prompt_sanitize(caps: TermCaps) -> bool`:** muestra el cuadro de diálogo y lee un carácter de stdin.

**Función `default_sanitize_output(path: &Path) -> PathBuf`:**

```rust
fn default_sanitize_output(path: &Path) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{stem}-sanitized.unitypackage"))
}
```

---

### Componente 5 — Exponer `AnalysisContext` desde el pipeline

Para que `sanitize::run_sanitize()` conozca `has_loader_script`, el pipeline debe devolver el contexto.

#### [MODIFY] [pipeline.rs](file:///c:/Users/Computador/Documents/github/vrchat-analyzer/src/pipeline.rs)

```rust
// Agregar función que devuelve también el contexto + el PackageTree:
pub fn run_scan_full(path: &Path)
  -> crate::utils::Result<(ScanReport, AnalysisContext, PackageTree)>
```

El sanitize reutiliza el pipeline interno sin escanear dos veces:

```rust
// run_sanitize llama internamente a run_scan_full:
let (report, context, tree) = pipeline::run_scan_full(input_path)?;
```

Así el paquete solo se extrae y analiza **una vez**, y el sanitize opera sobre los resultados ya en memoria.

---

### Componente 6 — Output del reporte de sanitización (CLI)

```
  ┌────────────────────── SANITIZE REPORT ──────────────────────────┐

  SCRIPTS NEUTRALIZED (2)
    Assets/Scripts/PlayerController.cs
      Line 47  → /* SANITIZED */ // Process.Start("cmd.exe", args);
      Line 83  → /* SANITIZED */ // Assembly.Load(rawBytes);

  ENTRIES REMOVED (1)
    Assets/Plugins/Evil.dll               DLL_IMPORT_CREATEPROCESS, DLL_IMPORT_SOCKETS

  ASSETS SKIPPED — no loader script in package (1)
    Assets/Textures/suspicious.png        POLYGLOT_FILE (inert without loader)

  ENTRIES KEPT (4)  — below threshold or no findings

  Original score  : 285  →  Residual score : 15
  Threshold used  : HIGH
  Output          : ./EvilPackage-sanitized.unitypackage  (1.2 MB)
  └────────────────────────────────────────────────────────────────┘
```

---

## Archivos afectados

| Archivo | Cambio |
|---|---|
| `src/report/finding.rs` | **[MODIFY]** — agregar `line_numbers: Vec<u64>` + `with_line_numbers()` |
| `src/analysis/scripts/pattern_matcher.rs` | **[MODIFY]** — emitir `with_line_numbers()` |
| `src/analysis/scripts/url_extractor.rs` | **[MODIFY]** — emitir `with_line_numbers()` |
| `src/analysis/scripts/obfuscation.rs` | **[MODIFY]** — emitir `with_line_numbers()` |
| `src/pipeline.rs` | **[MODIFY]** — agregar `run_scan_full()` que devuelve `(ScanReport, AnalysisContext, PackageTree)` |
| `src/sanitize/mod.rs` | **[NEW]** |
| `src/sanitize/script_neutralizer.rs` | **[NEW]** |
| `src/sanitize/rebuilder.rs` | **[NEW]** |
| `src/main.rs` | **[MODIFY]** — subcomando `Sanitize` + `run_sanitize_command()` + flujo drag-and-drop |
| `src/lib.rs` | **[MODIFY]** — `pub mod sanitize;` |

**Sin cambios en:** `analysis/dll/`, `analysis/assets/`, `scoring/`, `ingestion/`, tests.

---

## Plan de verificación

```bash
cargo build

# Dry-run (no escribe archivo)
vrcstorage-scanner sanitize evil.unitypackage --dry-run

# Con threshold custom
vrcstorage-scanner sanitize evil.unitypackage -s medium -o clean.unitypackage

# Verificar que el resultado es un TAR+gzip válido
file clean.unitypackage

# Regresión
cargo test
```
