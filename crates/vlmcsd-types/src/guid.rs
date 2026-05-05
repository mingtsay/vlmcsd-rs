use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const ZERO: Guid = Guid {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    pub fn from_le_bytes(bytes: &[u8; 16]) -> Self {
        Guid {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ],
        }
    }

    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
    }

    pub fn from_str_ms(s: &str) -> Option<Self> {
        let s = s.trim_start_matches('{').trim_end_matches('}');
        if s.len() != 36 {
            return None;
        }
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return None;
        }

        let data1 = u32::from_str_radix(parts[0], 16).ok()?;
        let data2 = u16::from_str_radix(parts[1], 16).ok()?;
        let data3 = u16::from_str_radix(parts[2], 16).ok()?;

        let hi = u16::from_str_radix(parts[3], 16).ok()?;
        let lo = u64::from_str_radix(parts[4], 16).ok()?;

        let mut data4 = [0u8; 8];
        data4[0..2].copy_from_slice(&hi.to_be_bytes());
        data4[2..8].copy_from_slice(&lo.to_be_bytes()[2..8]);

        Some(Guid {
            data1,
            data2,
            data3,
            data4,
        })
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes() {
        let bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let guid = Guid::from_le_bytes(&bytes);
        assert_eq!(guid.to_le_bytes(), bytes);
    }

    #[test]
    fn parse_display_roundtrip() {
        let s = "12345678-abcd-ef01-2345-67890abcdef0";
        let guid = Guid::from_str_ms(s).unwrap();
        assert_eq!(guid.to_string(), s);
    }
}
