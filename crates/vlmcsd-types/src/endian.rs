#[inline]
pub fn u16_from_le_bytes(b: [u8; 2]) -> u16 {
    u16::from_le_bytes(b)
}

#[inline]
pub fn u32_from_le_bytes(b: [u8; 4]) -> u32 {
    u32::from_le_bytes(b)
}

#[inline]
pub fn u64_from_le_bytes(b: [u8; 8]) -> u64 {
    u64::from_le_bytes(b)
}

#[inline]
pub fn u16_to_le_bytes(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

#[inline]
pub fn u32_to_le_bytes(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[inline]
pub fn u64_to_le_bytes(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
