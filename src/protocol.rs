use crate::network::ProtocolError;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketSize(u32);

impl PacketSize {
    pub fn from_slice(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < 4 {
            return Err(ProtocolError::PacketTooShort);
        }

        let bytes = [slice[0], slice[1], slice[2], slice[3]];
        let len = u32::from_be_bytes(bytes);

        Ok(PacketSize(len))
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl From<PacketSize> for usize {
    fn from(ps: PacketSize) -> Self {
        ps.0 as usize
    }
}

impl From<u32> for PacketSize {
    fn from(val: u32) -> Self {
        PacketSize(val)
    }
}