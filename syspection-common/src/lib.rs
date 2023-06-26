#![no_std]

pub const ARG_COUNT: usize = 4;
pub const ARG_SIZE: usize = 8;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ExecveCalls {
    pub caller: [u8; 16],
    pub command: [u8; 32],
    pub args: [[u8; ARG_SIZE]; ARG_COUNT],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveCalls {}