/// Maximum sized allowed for the packets of the protocol
/// 
/// This constant defines the max size a packet should have.
/// This is because the normal packets remain pretty small and without
/// a check any attacker could send any amount of data causing memory issues.
pub const MAX_PACKET_SIZE: usize = 1024 * 1024;

/// Minimum size allowed for the packets of the protocol
/// 
/// This constant defines the minimum size a packet should have.
/// 4 bytes is the size of the header therefor no packet shorter
/// can be processed properly. It is used in [`PacketSize::from_slice`]
pub const MIN_PACKET_SIZE: usize = 4;