#![no_std]
#![no_main]

use aya_bpf::{
    helpers::*,
    bindings::*,
    maps::PerfEventArray,
    macros::{map, tracepoint, xdp}, 
    programs::{TracePointContext, XdpContext},
};
use aya_log_ebpf::info;
use syspection_common::{ExecveCalls, IpRecord, ARG_COUNT, ARG_SIZE};

use core::{mem,
    str::from_utf8_unchecked};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto}, udp::UdpHdr, tcp::TcpHdr,
};

#[map(name = "EXECVE_EVENTS")]
static mut EXECVE_EVENTS: PerfEventArray<ExecveCalls> = PerfEventArray::<ExecveCalls>::with_max_entries(1024, 0);

#[map(name = "IP_RECORDS")]
static mut IP_RECORDS: PerfEventArray<IpRecord> = PerfEventArray::<IpRecord>::with_max_entries(1024, 0);

#[xdp(name = "ip_scanner")]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[tracepoint(name = "syspection")]
pub fn syspection(ctx: TracePointContext) -> i32 {
    match unsafe {try_syspection(&ctx)} {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

unsafe fn try_syspection(ctx: &TracePointContext) -> Result<i32, i64> {

    // Get the process that is executing the command
    let mut exec_buf = [0u8; 42];
    let exec = bpf_get_current_comm().unwrap_or_default();

    // Get the command that is being executed and stores it in exec_comm
    let exec_comm = ctx.read_at::<*const u8>(16)?;
    _ = bpf_probe_read_user_str_bytes(exec_comm, &mut exec_buf);

    // Create a buffer for the arguments of the command
    let mut arg_buf = [[0u8; ARG_SIZE]; ARG_COUNT];
    
    // Get the arguments of the command
    let argv = ctx.read_at::<*const *const u8>(24)?;
    for i in 0..ARG_COUNT {
        let arg_ptr = bpf_probe_read_user(argv.offset(i as isize))?;

        if arg_ptr.is_null() {
            break;
        }

        bpf_probe_read_user_str_bytes(arg_ptr, &mut arg_buf[i as usize]).unwrap_or_default();
    }

    let execve_calls = ExecveCalls {
        caller: exec,
        command: exec_buf,
        args: arg_buf,
    };

    EXECVE_EVENTS.output(ctx, &execve_calls, 0);

    info!(
        ctx, "curr_comm: {}, exec_comm: {}", from_utf8_unchecked(&execve_calls.caller), from_utf8_unchecked(&execve_calls.command)
    );

    Ok(0)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, dest_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
                (u16::from_be(unsafe { (*tcphdr).source }), u16::from_be(unsafe { (*tcphdr).dest }))
            }
            IpProto::Udp => {
                let udphdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
                (u16::from_be(unsafe { (*udphdr).source }), u16::from_be(unsafe { (*udphdr).dest }))
                // u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    let ip_record = IpRecord {
        src_ip: source.to_le_bytes(),
        dst_port: dest_port,
    };

    unsafe { IP_RECORDS.output(&ctx, &ip_record, 0) };

    info!(
        &ctx, "SRC: {:i} SRC_Port: {} DST: {:i} DST_Port: {}", source, source_port, destination, dest_port
    );

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
