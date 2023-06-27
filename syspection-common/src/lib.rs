#![no_std]

pub const ARG_COUNT: usize = 8;
pub const ARG_SIZE: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IpRecord {
    pub src_ip: u32,
    pub dst_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpRecord {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExecveCalls {
    pub caller: [u8; 16],
    pub command: [u8; 42],
    pub args: [[u8; ARG_SIZE]; ARG_COUNT],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveCalls {}