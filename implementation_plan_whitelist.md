# Whitelist de Archivos Estándar Conocidos

Implementar un sistema de whitelist para archivos C# estándar (ej: Poiyomi) que reduce el análisis a solo obfuscación cuando el archivo es conocido pero no verificado por hash, y lo omite completamente cuando el hash coincide.

> [!IMPORTANT]
> **Separación de responsabilidades:** Los **datos** (entradas de la whitelist, hashes, rangos de líneas) viven en `config.rs` — fuente única de la verdad. La **lógica** (structs, enum de resultado, función `check`) vive en `whitelist.rs`.

## Flujo de Verificación

```
¿La ruta del archivo coincide con alguna entrada de la whitelist?
  │
  NO → full analysis (comportamiento actual)
  │
  SÍ ↓
     ¿El SHA-256 del archivo coincide con algún hash conocido?
       │
       SÍ → FullyTrusted → skip ALL findings → return vec![]
       │
       NO ↓
          Verificar cantidad de líneas (informacional, no bloquea)
          Ejecutar SOLO checks de obfuscación
          Si hay obfuscación → findings con contexto "whitelisted=<name>, line_count_ok=<bool>"
```

> [!IMPORTANT]
> El check de obfuscación **siempre** se ejecuta cuando el SHA-256 no coincide. Esto protege contra atacantes que toman un archivo de la whitelist y le añaden código malicioso.

---

## Proposed Changes

### Datos en `src/config.rs`

#### [MODIFY] config.rs

Se añade al final del archivo la definición de `WhitelistEntry` y el slice `WHITELIST`. Al estar en `config.rs`, es la única ubicación donde hay que editar para añadir, quitar o actualizar archivos whitelisteados.

```rust
// ── Whitelist de archivos estándar conocidos ─────────────────────────────────

/// Una entrada de la whitelist. Ver `src/whitelist.rs` para la lógica de verificación.
pub struct WhitelistEntry {
    /// Nombre legible del archivo/paquete (solo para mensajes de contexto).
    pub name: &'static str,
    /// Todos los substrings deben aparecer en la ruta del asset (case-sensitive, AND logic).
    pub path_patterns: &'static [&'static str],
    /// SHA-256 hex (lowercase) para cada versión conocida. Puede estar vacío
    /// mientras no se tengan hashes registrados — el archivo irá a modo Modified.
    pub sha256_hashes: &'static [&'static str],
    /// Rango de líneas aceptable (inclusive). None = no verificar cantidad de líneas.
    pub expected_line_range: Option<(usize, usize)>,
}

/// Whitelist de archivos C# estándar que no deben ser tratados como maliciosos.
/// Editar SOLO este slice para gestionar la whitelist.
pub static WHITELIST: &[WhitelistEntry] = &[
    // ── Poiyomi Toon Shader ───────────────────────────────────────────────
    WhitelistEntry {
        name: "Poiyomi Toon — PoiExternalToolRegistry",
        path_patterns: &["Poiyomi", "PoiExternalToolRegistry"],
        sha256_hashes: &[
            // Añadir hashes aquí cuando se conozcan. Ejemplo:
            // "e3b0c44298fc1c149afbf4c8996fb924....",
        ],
        expected_line_range: Some((1, 500)),
    },
];
```

---

### Lógica en `src/whitelist.rs`

#### [NEW] whitelist.rs

Importa `WHITELIST` y `WhitelistEntry` desde `crate::config`. Solo contiene el algoritmo:

```rust
use crate::config::WHITELIST;

pub enum WhitelistVerdict {
    NotWhitelisted,
    FullyTrusted { name: &'static str },
    Modified    { name: &'static str, line_count_ok: bool },
}

pub fn check(location: &str, data: &[u8], source: &str) -> WhitelistVerdict { ... }
```

**Invariants clave:**
- Si `sha256_hashes` está vacío, el archivo va a `Modified` directamente (obfuscation check).
- El SHA-256 se computa solo si la entrada tiene hashes registrados.

---

### Integración en el pipeline de scripts

#### [MODIFY] `src/analysis/scripts/mod.rs`

`analyze_script` recibe actualmente `source: &str`. Necesita recibir también `data: &[u8]` para poder computar el SHA-256 dentro del whitelist check.

```rust
// ANTES
pub fn analyze_script(source: &str, location: &str) -> Vec<Finding>

// DESPUÉS
pub fn analyze_script(data: &[u8], source: &str, location: &str) -> Vec<Finding>
```

Lógica nueva al inicio de la función:
```rust
match whitelist::check(location, data, source) {
    WhitelistVerdict::FullyTrusted { .. } => return vec![],
    WhitelistVerdict::Modified { name, line_count_ok } => {
        let mut findings = obfuscation::analyze(source, location);
        for f in &mut findings {
            f.context = Some(format!(
                "whitelisted={name}, sha256_mismatch=true, line_count_ok={line_count_ok}"
            ));
        }
        return findings;
    }
    WhitelistVerdict::NotWhitelisted => { /* fall through */ }
}
```

#### [MODIFY] Todos los call sites de `analyze_script`

La firma cambia, hay que actualizar quién la llama. Según AGENTS.md esto está en `src/analysis/mod.rs` (dentro de `run_all_analyses`).

---

### Registrar el módulo

#### [MODIFY] `src/lib.rs`
```rust
pub mod whitelist;
```

#### [MODIFY] `src/main.rs`
```rust
mod whitelist;
```

---

## Verification Plan

### Automated
```
cargo build --release
```

### Manual
- Crear un `.cs` con ruta que coincida con un entry de la whitelist y SHA-256 correcto → sin findings.
- Mismo archivo con SHA-256 incorrecto → only obfuscation findings (con contexto).
- Archivo que no coincide con la whitelist → análisis completo normal.
