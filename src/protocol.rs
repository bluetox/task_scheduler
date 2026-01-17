#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketSize(u16);

impl PacketSize {
    pub fn from_slice(slice: &[u8]) -> Self {
        assert!(slice.len() >= 2, "slice too small to read PacketSize");
        let bytes = [slice[0], slice[1]];
        PacketSize(u16::from_be_bytes(bytes))
    }
    #[inline]
    fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl From<PacketSize> for usize {
    fn from(ps: PacketSize) -> Self {
        ps.0 as usize
    }
}
