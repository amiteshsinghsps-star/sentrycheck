#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]
//! Upper-bound capability candidates. This crate cannot produce a compatibility verdict.
pub mod elf;
pub mod syscalls;

use elf::Elf;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use sentrycheck_core::image::{FileContent, Image};
use sentrycheck_core::model::{Capability, CapabilitySet, Fingerprint, ResolutionConfidence};
use sentrycheck_core::util::{atomic_write, checked_join, read_bounded, sha256, validate_digest};
use sentrycheck_core::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_CAPABILITIES: usize = 100_000;
const MAX_DECODE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
struct BinaryAnalysis {
    capabilities: Vec<Capability>,
    fingerprints: Vec<Fingerprint>,
    warnings: Vec<String>,
}

fn capability(
    path: &str,
    digest: &str,
    arch: &str,
    number: Option<u64>,
    offset: usize,
    note: &str,
) -> Capability {
    let name = number
        .and_then(|number| syscalls::name(arch, number))
        .map(String::from);
    Capability {
        subsystem: name
            .as_deref()
            .and_then(syscalls::subsystem)
            .map(String::from),
        syscall: name,
        syscall_number: number,
        architecture: arch.into(),
        resolution_confidence: if number.is_some() {
            ResolutionConfidence::StaticCertain
        } else {
            ResolutionConfidence::Unresolvable
        },
        source_binary: path.into(),
        source_digest: digest.into(),
        source_offset: Some(format!("0x{offset:x}")),
        note: note.into(),
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn x86(elf: &Elf<'_>, path: &str, digest: &str, analysis: &mut BinaryAnalysis) {
    let mut decoded = 0usize;
    for (offset, size, address) in elf.code_regions() {
        if size > MAX_DECODE_BYTES - decoded {
            analysis.warnings.push(format!(
                "{path}: executable regions exceed the cumulative 64 MiB decoding limit"
            ));
            break;
        }
        decoded += size;
        let bytes = &elf.data[offset..offset + size];
        let mut targets = BTreeSet::new();
        for instruction in Decoder::with_ip(elf.bits, bytes, address, DecoderOptions::NONE) {
            if matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                targets.insert(instruction.near_branch_target());
            }
            if targets.len() > 1_000_000 {
                analysis
                    .warnings
                    .push(format!("{path}: branch target limit exceeded"));
                return;
            }
        }
        let mut constants = BTreeMap::new();
        let mut info_factory = InstructionInfoFactory::new();
        let mut invalid = 0;
        for instruction in Decoder::with_ip(elf.bits, bytes, address, DecoderOptions::NONE) {
            if instruction.is_invalid() {
                constants.clear();
                invalid += 1;
                continue;
            }
            if targets.contains(&instruction.ip()) {
                constants.clear();
            }
            let is_int80 =
                instruction.mnemonic() == Mnemonic::Int && instruction.immediate8() == 0x80;
            if instruction.mnemonic() == Mnemonic::Syscall
                || instruction.mnemonic() == Mnemonic::Sysenter
                || is_int80
            {
                let arch = if is_int80 || instruction.mnemonic() == Mnemonic::Sysenter {
                    "386"
                } else {
                    elf.architecture()
                };
                let number = constants.get(&Register::RAX).copied();
                analysis.capabilities.push(capability(path, digest, arch, number, offset + (instruction.ip() - address) as usize,
                    "Number resolved only within a decoded straight-line block; reachability, arguments, and fallback behavior are not established."));
                constants.clear();
                if analysis.capabilities.len() >= MAX_CAPABILITIES {
                    analysis
                        .warnings
                        .push(format!("{path}: capability limit reached"));
                    return;
                }
                continue;
            }
            let dest = instruction.op0_register();
            let full_dest = dest.full_register();
            let full_write = matches!(
                dest,
                Register::EAX
                    | Register::ECX
                    | Register::EDX
                    | Register::EBX
                    | Register::ESP
                    | Register::EBP
                    | Register::ESI
                    | Register::EDI
                    | Register::RAX
                    | Register::RCX
                    | Register::RDX
                    | Register::RBX
                    | Register::RSP
                    | Register::RBP
                    | Register::RSI
                    | Register::RDI
                    | Register::R8
                    | Register::R9
                    | Register::R10
                    | Register::R11
                    | Register::R12
                    | Register::R13
                    | Register::R14
                    | Register::R15
                    | Register::R8D
                    | Register::R9D
                    | Register::R10D
                    | Register::R11D
                    | Register::R12D
                    | Register::R13D
                    | Register::R14D
                    | Register::R15D
            );
            let mut value = None;
            if instruction.op0_kind() == OpKind::Register && full_write {
                if instruction.mnemonic() == Mnemonic::Mov {
                    if is_immediate(instruction.op1_kind()) {
                        value = Some(instruction.immediate(1));
                    } else if instruction.op1_kind() == OpKind::Register {
                        value = constants
                            .get(&instruction.op1_register().full_register())
                            .copied();
                    }
                } else if matches!(instruction.mnemonic(), Mnemonic::Xor | Mnemonic::Sub)
                    && instruction.op1_kind() == OpKind::Register
                    && dest == instruction.op1_register()
                {
                    value = Some(0);
                }
                // 32-bit register writes zero-extend, including MOV EAX, ECX.
                if dest.size() == 4 {
                    value = value.map(|v| v & 0xffff_ffff);
                }
            }
            for used in info_factory.info(&instruction).used_registers() {
                if matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    constants.remove(&used.register().full_register());
                }
            }
            if let Some(value) = value {
                constants.insert(full_dest, value);
            }
            if instruction.flow_control() != FlowControl::Next {
                constants.clear();
            }
        }
        if invalid > 0 {
            analysis.warnings.push(format!("{path}: {invalid} invalid x86 instructions during linear sweep; packed/embedded data may reduce coverage"));
        }
    }
}

fn arm64(elf: &Elf<'_>, path: &str, digest: &str, analysis: &mut BinaryAnalysis) {
    let mut decoded = 0usize;
    for (offset, size, _) in elf.code_regions() {
        if size > MAX_DECODE_BYTES - decoded {
            analysis.warnings.push(format!(
                "{path}: executable regions exceed the cumulative 64 MiB decoding limit"
            ));
            break;
        }
        decoded += size;
        let mut x8 = None;
        for (index, chunk) in elf.data[offset..offset + size].chunks_exact(4).enumerate() {
            let insn = u32::from_le_bytes(chunk.try_into().unwrap());
            let movz = insn & 0x7f80_001f == 0x5280_0008;
            let movk = insn & 0x7f80_001f == 0x7280_0008;
            let shift = ((insn >> 21) & 3) * 16;
            let immediate = u64::from((insn >> 5) & 0xffff) << shift;
            if movz {
                x8 = Some(immediate);
            } else if movk {
                x8 = x8.map(|n| (n & !(0xffffu64 << shift)) | immediate);
            } else if insn == 0xd400_0001 {
                analysis.capabilities.push(capability(path, digest, "arm64", x8, offset + index * 4,
                    "Only adjacent MOVZ/MOVK into x8/w8 is resolved; general ARM64 data flow remains unknown."));
                x8 = None;
                if analysis.capabilities.len() >= MAX_CAPABILITIES {
                    analysis
                        .warnings
                        .push(format!("{path}: capability limit reached"));
                    return;
                }
            } else {
                x8 = None;
            }
            if insn & (1 << 31) == 0 && (movz || movk) {
                x8 = x8.map(|n| n & 0xffff_ffff);
            }
        }
    }
}

fn metadata(elf: &Elf<'_>, path: &str, digest: &str, analysis: &mut BinaryAnalysis) {
    if let Some(interpreter) = &elf.interpreter {
        analysis.fingerprints.push(Fingerprint { source_binary: path.into(), kind: "elf-interpreter".into(), value: interpreter.clone(), note: "Interpreter path indicates a libc family; it does not establish the installed libc version.".into() });
    }
    let (symbols, symbols_truncated) = elf.symbols();
    let (needed, needed_truncated) = elf.needed();
    if symbols_truncated || needed_truncated {
        analysis.warnings.push(format!(
            "{path}: ELF metadata enumeration exceeded its record/string budget; coverage is incomplete"
        ));
    }
    for library in &needed {
        analysis.fingerprints.push(Fingerprint {
            source_binary: path.into(),
            kind: "needed-library".into(),
            value: library.clone(),
            note: "DT_NEEDED dependency; not proof that a code path is exercised.".into(),
        });
    }
    let mut seen = BTreeSet::new();
    for (symbol, offset) in symbols
        .iter()
        .map(|(name, offset)| (name.as_str(), Some(*offset)))
        .chain(needed.iter().map(|name| (name.as_str(), None)))
    {
        if let Some(subsystem) = syscalls::subsystem(symbol) {
            if !seen.insert((symbol.to_string(), subsystem)) {
                continue;
            }
            analysis.capabilities.push(Capability {
                syscall: if symbol == "bpf" || symbol.starts_with("io_uring_") {
                    Some(symbol.into())
                } else {
                    None
                },
                syscall_number: None,
                subsystem: Some(subsystem.into()),
                architecture: elf.architecture().into(),
                resolution_confidence: ResolutionConfidence::StaticProbable,
                source_binary: path.into(),
                source_digest: digest.into(),
                source_offset: offset.map(|offset| format!("0x{offset:x}")),
                note: format!(
                    "ELF symbol/library reference {symbol:?}; execution and fallback are unknown."
                ),
            });
        }
    }
    // Metadata strings are weak markers and are always labelled as such. In particular,
    // GLIBC_2.x is a symbol-version requirement, not an installed glibc fingerprint.
    let markers = [
        ("GLIBC_", "glibc-symbol-version"),
        ("go1.", "go-build-string"),
        ("musl libc", "musl-marker"),
        ("github.com/cilium/ebpf", "go-module-marker"),
        ("/sys/fs/cgroup", "cgroup-path-marker"),
    ];
    for (prefix, kind) in markers {
        let mut values = BTreeSet::new();
        for (offset, window) in elf.data.windows(prefix.len()).enumerate() {
            if window != prefix.as_bytes() {
                continue;
            }
            let value: String = elf.data[offset..]
                .iter()
                .take(100)
                .take_while(|c| c.is_ascii_graphic())
                .map(|c| *c as char)
                .collect();
            if !values.insert(value.clone()) {
                continue;
            }
            analysis.fingerprints.push(Fingerprint {
                source_binary: path.into(),
                kind: kind.into(),
                value: value.clone(),
                note: "String metadata, not proof of runtime behavior or a fallback guarantee."
                    .into(),
            });
            if prefix.contains("cgroup") || prefix.contains("ebpf") {
                analysis.capabilities.push(Capability {
                    syscall: None,
                    syscall_number: None,
                    subsystem: Some(
                        if prefix.contains("cgroup") {
                            "cgroup"
                        } else {
                            "ebpf"
                        }
                        .into(),
                    ),
                    architecture: elf.architecture().into(),
                    resolution_confidence: ResolutionConfidence::StaticProbable,
                    source_binary: path.into(),
                    source_digest: digest.into(),
                    source_offset: Some(format!("0x{offset:x}")),
                    note: format!("Weak string marker: {value}"),
                });
            }
            if values.len() >= 128 {
                break;
            }
        }
    }
}

fn analyze_binary(data: &[u8], path: &str, digest: &str) -> Result<BinaryAnalysis> {
    let elf = Elf::parse(data)?;
    let mut result = BinaryAnalysis::default();
    if elf.sections.is_empty() {
        result.warnings.push(format!("{path}: no section table; executable-segment sweep may miss code before the entry point or embedded data boundaries"));
    }
    match elf.architecture() {
        "amd64" | "386" => x86(&elf, path, digest, &mut result),
        "arm64" => arm64(&elf, path, digest, &mut result),
        _ => result.warnings.push(format!(
            "{path}: unsupported ELF machine {} / {} bits",
            elf.machine, elf.bits
        )),
    }
    if elf.code_regions().is_empty() {
        result
            .warnings
            .push(format!("{path}: no executable regions"));
    }
    metadata(&elf, path, digest, &mut result);
    Ok(result)
}

pub fn scan(image: &Image, cache: Option<&Path>) -> CapabilitySet {
    let mut set = CapabilitySet {
        interpretation: "Upper-bound capability candidates for analyzed code only. This is not an exhaustive syscall set or a compatibility verdict; indirect/dynamic dispatch and untested paths remain unknown.".into(),
        warnings: image.warnings.clone(), ..CapabilitySet::default()
    };
    for (name, file) in &image.files {
        let FileContent::Regular(data) = &file.content else {
            continue;
        };
        if !data.starts_with(b"\x7fELF") {
            continue;
        }
        set.elf_files += 1;
        let path = format!("/{name}");
        let digest = sha256(data);
        let cache_file = cache.and_then(|root| {
            checked_join(
                root,
                &format!("elf-v3/{}.json", validate_digest(&digest).ok()?),
            )
            .ok()
        });
        let cached = cache_file
            .as_ref()
            .and_then(|file| read_bounded(file, 16 * 1024 * 1024).ok())
            .and_then(|bytes| serde_json::from_slice::<BinaryAnalysis>(&bytes).ok());
        let analysis = match cached {
            Some(mut cached)
                if cached
                    .capabilities
                    .iter()
                    .all(|cap| cap.source_digest == digest) =>
            {
                set.cache_hits += 1;
                for cap in &mut cached.capabilities {
                    cap.source_binary = path.clone();
                }
                for fp in &mut cached.fingerprints {
                    fp.source_binary = path.clone();
                }
                cached
            }
            _ => match analyze_binary(data, &path, &digest) {
                Ok(result) => {
                    if let Some(file) = cache_file {
                        if let Ok(bytes) = serde_json::to_vec(&result) {
                            if let Err(error) = atomic_write(&file, &bytes) {
                                set.warnings.push(format!("cache write: {error}"));
                            }
                        }
                    }
                    result
                }
                Err(error) => {
                    set.warnings.push(format!("{path}: {error}"));
                    continue;
                }
            },
        };
        set.capabilities.extend(analysis.capabilities);
        set.fingerprints.extend(analysis.fingerprints);
        set.warnings.extend(analysis.warnings);
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn fixture(machine: u16, code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&(code.len() as u64).to_le_bytes());
        bytes.extend_from_slice(code);
        bytes
    }
    fn analyze(code: &[u8]) -> BinaryAnalysis {
        analyze_binary(&fixture(62, code), "/fixture", "digest").unwrap()
    }
    #[test]
    fn resolves_io_uring_but_does_not_guess_dynamic_numbers() {
        let result = analyze(&[
            0xb8, 0xa9, 1, 0, 0, 0x0f, 0x05, 0x48, 0x89, 0xf8, 0x0f, 0x05,
        ]);
        assert_eq!(result.capabilities.len(), 2);
        assert_eq!(
            result.capabilities[0].syscall.as_deref(),
            Some("io_uring_setup")
        );
        assert_eq!(
            result.capabilities[1].resolution_confidence,
            ResolutionConfidence::Unresolvable
        );
    }
    #[test]
    fn embedded_opcode_bytes_are_not_syscalls() {
        assert!(analyze(&[0xb8, 0x0f, 0x05, 0, 0, 0xc3])
            .capabilities
            .is_empty());
    }
    #[test]
    fn branch_targets_and_partial_writes_invalidate_constants() {
        assert_eq!(
            analyze(&[0xb8, 0xa9, 1, 0, 0, 0xb0, 0x01, 0x0f, 0x05]).capabilities[0].syscall_number,
            None
        );
        assert_eq!(
            analyze(&[0xeb, 0x05, 0xb8, 0xa9, 1, 0, 0, 0x0f, 0x05]).capabilities[0].syscall_number,
            None
        );
    }
    #[test]
    fn int80_uses_i386_numbering() {
        assert_eq!(
            analyze(&[0xb8, 4, 0, 0, 0, 0xcd, 0x80]).capabilities[0]
                .syscall
                .as_deref(),
            Some("write")
        );
    }
    #[test]
    fn resolves_arm64_movz_svc() {
        let mut code = (0xd2800008u32 | (425 << 5)).to_le_bytes().to_vec();
        code.extend(0xd4000001u32.to_le_bytes());
        assert_eq!(
            analyze_binary(&fixture(183, &code), "/arm", "hash")
                .unwrap()
                .capabilities[0]
                .syscall
                .as_deref(),
            Some("io_uring_setup")
        );
    }
    #[test]
    fn malformed_elf_never_panics() {
        let good = fixture(62, &[0x0f, 0x05]);
        for len in 0..good.len() {
            let _ = Elf::parse(&good[..len]);
        }
        for offset in 0..good.len() {
            let mut input = good.clone();
            input[offset] = 0xff;
            let _ = analyze_binary(&input, "/bad", "hash");
        }
    }

    #[test]
    fn overflowing_virtual_addresses_are_rejected_before_decoding() {
        let mut bytes = fixture(62, &[0x90, 0x90, 0x0f, 0x05]);
        bytes[80..88].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        assert!(analyze_binary(&bytes, "/overflow", "hash").is_err());
    }

    #[test]
    fn metadata_strings_require_a_terminator_within_the_bound() {
        let mut data = vec![b'a'; 8192];
        data[8191] = 0;
        assert!(elf::cstring(&data, 0).is_none());
        data[4096] = 0;
        assert_eq!(elf::cstring(&data, 0).unwrap().len(), 4096);
        assert!(elf::cstring(&data, usize::MAX).is_none());
    }
}
