use aya::maps::AsyncPerfEventArray;
use aya::programs::{TracePoint, Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;

use syspection_common::{ExecveCalls, IpRecord, ARG_COUNT, ARG_SIZE};

use std::ffi::CStr;
use std::net::Ipv4Addr;

use clap::Parser;
use bytes::BytesMut;
use serde::Serialize;
use log::{info, warn};
use tokio::{signal, task, sync::mpsc};

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

#[derive(Debug, Serialize)]
struct IngressIp {
    src_ip: Ipv4Addr,
    dst_port: u16,
}

macro_rules! cstr_to_rstr {
    ($var: expr) => {
        CStr::from_bytes_until_nul(&$var[..])
            .unwrap()
            .to_string_lossy()
            .to_string()
    };
}

fn get_args(args: &[[u8; ARG_SIZE]; ARG_COUNT]) -> Vec<String> {
    let mut args_vec = Vec::new();
    for arg in args.iter() {
        let arg_str = cstr_to_rstr!(arg);
        if arg_str.is_empty() {
            break;
        }
        args_vec.push(arg_str);
    }
    args_vec
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
    let mut execve_events = AsyncPerfEventArray::try_from(bpf.take_map("EXECVE_EVENTS").unwrap())?;

    let ingress_ip: &mut Xdp = bpf.program_mut("ip_scanner").unwrap().try_into()?;
    ingress_ip.load()?;
    ingress_ip.attach(&opt.iface, XdpFlags::SKB_MODE)?;
    let mut ip_records = AsyncPerfEventArray::try_from(bpf.take_map("IP_RECORDS").unwrap())?;

    info!("Spawning eBPF Event Processor...");
    let (execve_tx, mut execve_rx) = mpsc::channel::<Execve>(1000);
    let (ip_tx, mut ip_rx) = mpsc::channel::<IngressIp>(1000);

    task::spawn(async move {
        loop {
            tokio::select! {
                Some(execve) = execve_rx.recv() => {
                    println!("{:?}", execve);
                }
                Some(ip) = ip_rx.recv() => {
                    println!("{:?}", ip);
                }
                else => {
                    warn!("No more events to process!");
                    break;
                }
            }
        }
    });

    info!("Spawning eBPF Event Listener...");
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    for cpu in cpus {
        let mut ip_buf = ip_records.open(cpu, None)?;
        let mut execve_buf = execve_events.open(cpu, None)?;

        let (ip_tx, execve_tx) = (ip_tx.clone(), execve_tx.clone());

        task::spawn(async move {
            let mut ip_buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(1000))
                .collect::<Vec<_>>();

            loop {
                let records = ip_buf.read_events(&mut ip_buffers).await.unwrap();
                let mut res = Vec::new();

                for recs in ip_buffers.iter_mut().take(records.read) {
                    let ptr = recs.as_ptr() as *const IpRecord;
                    let rec = unsafe { ptr.read_unaligned() };
                    let ipv4 = Ipv4Addr::from(rec.src_ip);

                    let ip = IngressIp {
                        src_ip: ipv4,
                        dst_port: rec.dst_port,
                    };

                    res.push(ip);
                }

                for ip in res {
                    ip_tx.send(ip).await.unwrap();
                }
            }
        });

        task::spawn(async move {
            let mut execve_buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(1000))
                .collect::<Vec<_>>();

            loop {
                let records = execve_buf.read_events(&mut execve_buffers).await.unwrap();
                let mut res = Vec::new();

                for recs in execve_buffers.iter_mut().take(records.read) {
                    let ptr = recs.as_ptr() as *const ExecveCalls;
                    let rec = unsafe { ptr.read_unaligned() };

                    let execve = Execve {
                        exec: cstr_to_rstr!(rec.caller),
                        exec_comm: cstr_to_rstr!(rec.command),
                        args: get_args(&rec.args),
                    };

                    res.push(execve);
                }

                for execve in res {
                    execve_tx.send(execve).await.unwrap();
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
