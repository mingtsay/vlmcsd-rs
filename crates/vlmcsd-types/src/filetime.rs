use core::fmt;

const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
const TICKS_PER_SEC: u64 = 10_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

impl FileTime {
    pub const ZERO: FileTime = FileTime { low: 0, high: 0 };

    pub fn from_le_bytes(bytes: &[u8; 8]) -> Self {
        FileTime {
            low: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            high: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    pub fn to_le_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.low.to_le_bytes());
        out[4..8].copy_from_slice(&self.high.to_le_bytes());
        out
    }

    pub fn as_u64(self) -> u64 {
        (self.high as u64) << 32 | self.low as u64
    }

    pub fn from_u64(v: u64) -> Self {
        FileTime {
            low: v as u32,
            high: (v >> 32) as u32,
        }
    }

    pub fn from_unix_secs(secs: i64) -> Self {
        let ticks = (secs as u64) * TICKS_PER_SEC + EPOCH_DIFF;
        Self::from_u64(ticks)
    }

    pub fn to_unix_secs(self) -> i64 {
        let ticks = self.as_u64();
        ((ticks - EPOCH_DIFF) / TICKS_PER_SEC) as i64
    }

    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Self::from_unix_secs(secs)
    }
}

impl fmt::Debug for FileTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileTime(0x{:016x})", self.as_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_roundtrip() {
        let ts = 1_700_000_000i64;
        let ft = FileTime::from_unix_secs(ts);
        assert_eq!(ft.to_unix_secs(), ts);
    }

    #[test]
    fn byte_roundtrip() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let ft = FileTime::from_le_bytes(&bytes);
        assert_eq!(ft.to_le_bytes(), bytes);
    }
}
