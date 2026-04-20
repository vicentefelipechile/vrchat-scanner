use crate::report::{Finding, FindingId, Severity};
use crate::utils::shannon_entropy;

/// Information extracted from a PE file header
#[derive(Debug, Default)]
pub struct PeInfo {
    pub is_dotnet: bool,
    pub is_native: bool,
    pub is_64bit: bool,
    pub has_tls_callbacks: bool,
    pub subsystem: u16,
    pub compile_timestamp: u32,
}

/// Parse PE header and sections, producing findings for anomalies.
pub fn analyze(data: &[u8], location: &str) -> (PeInfo, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut info = PeInfo::default();

    if !data.starts_with(b"MZ") {
        findings.push(Finding::new(
            FindingId::PeInvalidHeader,
            Severity::Medium,
            15,
            location,
            "File does not start with MZ magic bytes (invalid PE)",
        ));
        return (info, findings);
    }

    match goblin::pe::PE::parse(data) {
        Ok(pe) => {
            info.is_64bit = pe.is_64;
            info.compile_timestamp = pe.header.coff_header.time_date_stamp;

            // Check for .NET CLR header
            if let Some(opt) = &pe.header.optional_header {
                info.subsystem = opt.windows_fields.subsystem;
                // CLR data directory index is 14
                if let Some(dd) = opt.data_directories.get_clr_runtime_header() {
                    info.is_dotnet = dd.virtual_address != 0;
                }
            }
            info.is_native = !info.is_dotnet;

            // Check TLS callbacks
            if pe.header.optional_header
                .as_ref()
                .map(|o| {
                    let dd = &o.data_directories;
                    // TLS directory is index 9
                    dd.get_tls_table().map(|t| t.virtual_address != 0).unwrap_or(false)
                })
                .unwrap_or(false)
            {
                info.has_tls_callbacks = true;
            }

            // Analyze sections
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name)
                    .trim_matches('\0')
                    .to_string();
                let start = section.pointer_to_raw_data as usize;
                let end = (start + section.size_of_raw_data as usize).min(data.len());
                let section_data = if start < data.len() { &data[start..end] } else { &[] };

                let entropy = shannon_entropy(section_data);
                let virtual_size = section.virtual_size as u64;
                let raw_size = section.size_of_raw_data as u64;

                let characteristic_flags = section.characteristics;
                let is_executable = (characteristic_flags & 0x20000000) != 0;
                let is_writable   = (characteristic_flags & 0x80000000) != 0;

                if entropy >= 7.2 {
                    findings.push(
                        Finding::new(
                            FindingId::PeHighEntropySection,
                            Severity::High,
                            55,
                            location,
                            format!("Section '{}' has entropy {:.2} (possible packer/encryption)", name, entropy),
                        )
                        .with_context(format!("Section: {name}")),
                    );
                } else if entropy >= 6.8 {
                    findings.push(
                        Finding::new(
                            FindingId::PeHighEntropySection,
                            Severity::Medium,
                            20,
                            location,
                            format!("Section '{}' has suspicious entropy {:.2}", name, entropy),
                        )
                        .with_context(format!("Section: {name}")),
                    );
                }

                if name.is_empty() {
                    findings.push(Finding::new(
                        FindingId::PeUnnamedSection,
                        Severity::Medium,
                        20,
                        location,
                        "PE section without a name (possible evasion technique)",
                    ));
                }

                if is_executable && is_writable {
                    findings.push(
                        Finding::new(
                            FindingId::PeWriteExecuteSection,
                            Severity::High,
                            40,
                            location,
                            format!("Section '{}' is both writable and executable (W+X)", name),
                        )
                        .with_context(format!("Section: {name}")),
                    );
                }

                if virtual_size > raw_size.saturating_mul(4) && raw_size > 0 {
                    findings.push(
                        Finding::new(
                            FindingId::PeInflatedSection,
                            Severity::Medium,
                            20,
                            location,
                            format!("Section '{}' virtual_size >> raw_size (runtime decompression?)", name),
                        )
                        .with_context(format!("virtual={virtual_size} raw={raw_size}")),
                    );
                }
            }
        }
        Err(e) => {
            findings.push(Finding::new(
                FindingId::PeParseError,
                Severity::Low,
                5,
                location,
                format!("Could not fully parse PE header: {e}"),
            ));
        }
    }

    (info, findings)
}
