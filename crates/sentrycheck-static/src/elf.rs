use sentrycheck_core::Result;

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub kind: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: usize,
    pub size: usize,
    pub link: usize,
    pub entsize: usize,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub bits: u32,
    pub machine: u16,
    pub entry: u64,
    pub sections: Vec<Section>,
    pub executable_segments: Vec<(usize, usize, u64)>,
    pub interpreter: Option<String>,
}

pub fn range(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset.checked_add(size).ok_or("ELF offset overflow")?;
    if end > data.len() as u64 {
        return Err("ELF structure extends beyond end of file".into());
    }
    Ok(&data[offset as usize..end as usize])
}

fn word(data: &[u8], offset: u64, bytes: u64) -> Result<u64> {
    let mut value = 0u64;
    for (i, byte) in range(data, offset, bytes)?.iter().enumerate() {
        value |= u64::from(*byte) << (i * 8);
    }
    Ok(value)
}

pub fn cstring(table: &[u8], offset: usize) -> Option<String> {
    let bytes = table.get(offset..)?;
    let end = bytes.iter().take(4097).position(|c| *c == 0)?;
    if end > 4096 {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(String::from)
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 52 || &data[..4] != b"\x7fELF" {
            return Err("not a complete ELF header".into());
        }
        if data[5] != 1 {
            return Err("big-endian ELF is not supported".into());
        }
        if data[6] != 1 {
            return Err("unsupported ELF version".into());
        }
        let bits = match data[4] {
            1 => 32,
            2 => 64,
            _ => return Err("unknown ELF class".into()),
        };
        let typ = word(data, 16, 2)?;
        if typ != 2 && typ != 3 {
            return Err("ELF is not executable or a shared object".into());
        }
        let machine = word(data, 18, 2)? as u16;
        let is64 = bits == 64;
        let entry = word(data, 24, if is64 { 8 } else { 4 })?;
        let phoff = word(data, if is64 { 32 } else { 28 }, if is64 { 8 } else { 4 })?;
        let shoff = word(data, if is64 { 40 } else { 32 }, if is64 { 8 } else { 4 })?;
        let phsize = word(data, if is64 { 54 } else { 42 }, 2)?;
        let phcount = word(data, if is64 { 56 } else { 44 }, 2)?;
        let shsize = word(data, if is64 { 58 } else { 46 }, 2)?;
        let shcount = word(data, if is64 { 60 } else { 48 }, 2)?;
        let shnames = word(data, if is64 { 62 } else { 50 }, 2)?;
        if phcount == 0xffff || shnames == 0xffff || (shcount == 0 && shoff != 0) {
            return Err("extended ELF table numbering is unsupported".into());
        }
        if phcount > 4096 || (phcount > 0 && phsize < if is64 { 56 } else { 32 }) {
            return Err("invalid program-header table".into());
        }
        if shcount > 8192 || (shcount > 0 && shsize < if is64 { 64 } else { 40 }) {
            return Err("invalid section-header table".into());
        }
        range(
            data,
            phoff,
            phsize.checked_mul(phcount).ok_or("ELF table overflow")?,
        )?;
        range(
            data,
            shoff,
            shsize.checked_mul(shcount).ok_or("ELF table overflow")?,
        )?;
        let mut sections = Vec::new();
        let mut names = Vec::new();
        for index in 0..shcount {
            let pos = shoff + index * shsize;
            names.push(word(data, pos, 4)? as usize);
            let kind = word(data, pos + 4, 4)? as u32;
            let flags = word(data, pos + 8, if is64 { 8 } else { 4 })?;
            let address = word(
                data,
                pos + if is64 { 16 } else { 12 },
                if is64 { 8 } else { 4 },
            )?;
            let offset = word(
                data,
                pos + if is64 { 24 } else { 16 },
                if is64 { 8 } else { 4 },
            )?;
            let size = word(
                data,
                pos + if is64 { 32 } else { 20 },
                if is64 { 8 } else { 4 },
            )?;
            if kind != 8 {
                range(data, offset, size)?;
            }
            if flags & 4 != 0 && address.checked_add(size).is_none() {
                return Err("executable section virtual address overflows".into());
            }
            let link = word(data, pos + if is64 { 40 } else { 24 }, 4)? as usize;
            let entsize = word(
                data,
                pos + if is64 { 56 } else { 36 },
                if is64 { 8 } else { 4 },
            )? as usize;
            sections.push(Section {
                name: String::new(),
                kind,
                flags,
                address,
                offset: offset as usize,
                size: size as usize,
                link,
                entsize,
            });
        }
        if !sections.is_empty() {
            let names_section = sections
                .get(shnames as usize)
                .ok_or("invalid section name index")?;
            let table = range(data, names_section.offset as u64, names_section.size as u64)?;
            for (section, name) in sections.iter_mut().zip(names) {
                section.name = cstring(table, name).unwrap_or_default();
            }
        }
        let mut executable_segments = Vec::new();
        let mut interpreter = None;
        for index in 0..phcount {
            let pos = phoff + index * phsize;
            let kind = word(data, pos, 4)?;
            let flags = word(data, pos + if is64 { 4 } else { 24 }, 4)?;
            let offset = word(
                data,
                pos + if is64 { 8 } else { 4 },
                if is64 { 8 } else { 4 },
            )?;
            let address = word(
                data,
                pos + if is64 { 16 } else { 8 },
                if is64 { 8 } else { 4 },
            )?;
            let size = word(
                data,
                pos + if is64 { 32 } else { 16 },
                if is64 { 8 } else { 4 },
            )?;
            range(data, offset, size)?;
            if kind == 1 && flags & 1 != 0 {
                if address.checked_add(size).is_none() {
                    return Err("executable segment virtual address overflows".into());
                }
                executable_segments.push((offset as usize, size as usize, address));
            }
            if kind == 3 {
                interpreter = cstring(range(data, offset, size)?, 0);
            }
        }
        Ok(Self {
            data,
            bits,
            machine,
            entry,
            sections,
            executable_segments,
            interpreter,
        })
    }

    pub fn architecture(&self) -> &str {
        match (self.machine, self.bits) {
            (62, 64) => "amd64",
            (3, 32) => "386",
            (183, 64) => "arm64",
            _ => "unsupported",
        }
    }

    pub fn code_regions(&self) -> Vec<(usize, usize, u64)> {
        let sections: Vec<_> = self
            .sections
            .iter()
            .filter(|s| s.kind == 1 && s.flags & 4 != 0)
            .map(|s| (s.offset, s.size, s.address))
            .collect();
        if sections.is_empty() {
            self.executable_segments
                .iter()
                .map(|&(offset, size, address)| {
                    // A segment that includes the ELF header has no reliable linear-sweep
                    // alignment. Start at the validated entry point rather than decoding
                    // ELF metadata as instructions. Earlier code remains a coverage gap.
                    if offset == 0 && self.entry >= address && self.entry - address < size as u64 {
                        let skip = (self.entry - address) as usize;
                        (offset + skip, size - skip, self.entry)
                    } else {
                        (offset, size, address)
                    }
                })
                .collect()
        } else {
            sections
        }
    }

    pub fn symbols(&self) -> (Vec<(String, usize)>, bool) {
        let mut result = Vec::new();
        let mut records = 0;
        let mut string_bytes = 0;
        for section in self.sections.iter().filter(|s| s.kind == 2 || s.kind == 11) {
            let min = if self.bits == 64 { 24 } else { 16 };
            if section.entsize < min
                || section.entsize == 0
                || section.size / section.entsize > 2_000_000
            {
                continue;
            }
            let Some(strings) = self.sections.get(section.link) else {
                continue;
            };
            let Ok(table) = range(self.data, strings.offset as u64, strings.size as u64) else {
                continue;
            };
            for offset in (section.offset..section.offset + section.size).step_by(section.entsize) {
                if offset + min > section.offset + section.size {
                    break;
                }
                records += 1;
                if records > 2_000_000 || result.len() >= 100_000 {
                    return (result, true);
                }
                let Ok(index) = word(self.data, offset as u64, 4) else {
                    continue;
                };
                if let Some(name) = cstring(table, index as usize) {
                    if !name.is_empty() {
                        string_bytes += name.len();
                        if string_bytes > 16 * 1024 * 1024 {
                            return (result, true);
                        }
                        result.push((name, offset));
                    }
                }
            }
        }
        (result, false)
    }

    pub fn needed(&self) -> (Vec<String>, bool) {
        let mut result = Vec::new();
        let mut records = 0;
        for section in self.sections.iter().filter(|s| s.kind == 6) {
            let Some(strings) = self.sections.get(section.link) else {
                continue;
            };
            let Ok(table) = range(self.data, strings.offset as u64, strings.size as u64) else {
                continue;
            };
            let width = if self.bits == 64 { 8 } else { 4 };
            for offset in (section.offset..section.offset + section.size).step_by(width * 2) {
                if offset + width * 2 > section.offset + section.size {
                    break;
                }
                records += 1;
                if records > 100_000 || result.len() >= 4096 {
                    return (result, true);
                }
                let tag = word(self.data, offset as u64, width as u64).ok();
                if tag == Some(0) {
                    break;
                }
                if tag == Some(1) {
                    if let Ok(index) = word(self.data, (offset + width) as u64, width as u64) {
                        if let Some(name) = cstring(table, index as usize) {
                            result.push(name);
                        }
                    }
                }
            }
        }
        (result, false)
    }
}
