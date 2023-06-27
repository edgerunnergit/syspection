use aya::maps::AsyncPerfEventArray;
use aya::programs::{TracePoint, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;

use clap::Parser;
use anyhow::Context;
use serde::Serialize;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,
}

#[derive(Debug, Serialize)]
struct Execve {
    exec: String,
    exec_comm: String,
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syspection"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/syspection"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let execve_trace: &mut TracePoint = bpf.program_mut("syspection").unwrap().try_into()?;
    execve_trace.load()?;
    execve_trace.attach("syscalls", "sys_enter_execve")?;
    let mut _execve_events = AsyncPerfEventArray::try_from(bpf.take_map("EXECVE_EVENTS").unwrap())?;

    let ingress_ip: &mut Xdp = bpf.program_mut("ip_scanner").unwrap().try_into()?;
    ingress_ip.load()?;
    ingress_ip.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    let mut _ip_records = AsyncPerfEventArray::try_from(bpf.take_map("IP_RECORDS").unwrap())?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
