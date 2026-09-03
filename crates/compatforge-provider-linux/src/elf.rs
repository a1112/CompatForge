const ELF64_HEADER_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElfError {
    Invalid,
    Architecture,
}

pub(crate) fn parse_x86_64(bytes: &[u8]) -> Result<(), ElfError> {
    let header = bytes.get(..ELF64_HEADER_LEN).ok_or(ElfError::Invalid)?;
    if header[..4] != *b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        || u32::from_le_bytes([header[20], header[21], header[22], header[23]]) != 1
        || u16::from_le_bytes([header[52], header[53]]) != ELF64_HEADER_LEN as u16
    {
        return Err(ElfError::Invalid);
    }
    if u16::from_le_bytes([header[18], header[19]]) != 62 {
        return Err(ElfError::Architecture);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_x86_64, ElfError};

    #[derive(Clone, Copy, Debug)]
    enum Mutant {
        Magic,
        Class32,
        BigEndian,
        IdentVersion,
        MachineArm64,
        Relocatable,
        HeaderVersion,
        HeaderSize,
        Truncated,
    }

    fn elf64_x86_64(object_type: u16) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&object_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // ELF64 e_ehsize
        bytes
    }

    fn mutated_elf(mutation: Mutant) -> Vec<u8> {
        let mut bytes = elf64_x86_64(2).to_vec();
        match mutation {
            Mutant::Magic => bytes[0] = 0,
            Mutant::Class32 => bytes[4] = 1,
            Mutant::BigEndian => bytes[5] = 2,
            Mutant::IdentVersion => bytes[6] = 0,
            Mutant::MachineArm64 => bytes[18..20].copy_from_slice(&183_u16.to_le_bytes()),
            Mutant::Relocatable => bytes[16..18].copy_from_slice(&1_u16.to_le_bytes()),
            Mutant::HeaderVersion => bytes[20..24].copy_from_slice(&0_u32.to_le_bytes()),
            Mutant::HeaderSize => bytes[52..54].copy_from_slice(&63_u16.to_le_bytes()),
            Mutant::Truncated => bytes.truncate(63),
        }
        bytes
    }

    #[test]
    fn accepts_only_little_endian_x86_64_exec_or_dyn_elf() {
        assert!(parse_x86_64(&elf64_x86_64(2)).is_ok());
        assert!(parse_x86_64(&elf64_x86_64(3)).is_ok());
        for mutation in [
            Mutant::Magic,
            Mutant::Class32,
            Mutant::BigEndian,
            Mutant::IdentVersion,
            Mutant::MachineArm64,
            Mutant::Relocatable,
            Mutant::HeaderVersion,
            Mutant::HeaderSize,
            Mutant::Truncated,
        ] {
            assert!(parse_x86_64(&mutated_elf(mutation)).is_err(), "{mutation:?}");
        }
        assert_eq!(
            parse_x86_64(&mutated_elf(Mutant::MachineArm64)),
            Err(ElfError::Architecture)
        );
    }
}
