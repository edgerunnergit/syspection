use aya::maps::AsyncPerfEventArray;
use aya::programs::{TracePoint, Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;

use crate::model::{send_logs, get_auth};
use syspection_common::{ExecveCalls, IpRecord, ARG_COUNT, ARG_SIZE};

use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use serde::Serialize;
use tokio::{
    signal,
    sync::{mpsc, Mutex},
    task,
};

pub mod model;

const BUFFER_TIME: u64 = 2;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,

    // Take the duration for whitelisting IP addresses
    #[clap(short, long)]
    duration: Option<u64>,
}

enum Events {
    Execve(Execve),
    IngressIp(IngressIp),
}

#[derive(Debug, Serialize)]
struct Execve {
    exec: String,
    exec_comm: String,
    args: Vec<String>,
}

#[derive(Serialize)]
struct IngressIp {
    dst_port: u16,
    src_ip: Ipv4Addr,
    ts: SystemTime,
}

impl Debug for IngressIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressIp")
            .field("dst_port", &self.dst_port)
            .field("src_ip", &self.src_ip)
            .finish()
    }
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

    // get the timestamp of when the program starts running
    let start_time = SystemTime::now();
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
    let (sshd_tx, mut sshd_rx) = mpsc::channel::<bool>(1);

    let ip_logs: Arc<Mutex<HashMap<Ipv4Addr, SystemTime>>> = Arc::new(Mutex::new(HashMap::new()));
    let ip_logs_clone = Arc::clone(&ip_logs);
    let frequently_seen: Arc<Mutex<HashMap<Ipv4Addr, u64>>> = Arc::new(Mutex::new(HashMap::new()));

    let (auth, mut auth_gen_ts) = get_auth(std::env::var("SUBCOM_TOKEN").unwrap()).await.unwrap();
    let mut auth_clone = Arc::clone(&auth);

    task::spawn(async move {
        loop {
            let event: Events = tokio::select! {
                Some(execve) = execve_rx.recv() => {
                    // println!("{:?}", execve);
                    Events::Execve(execve)
                }
                Some(ip) = ip_rx.recv() => {
                    // println!("{:?}", ip);
                    Events::IngressIp(ip)
                }
                else => {
                    warn!("No more events to process!");
                    break;
                }
            };

            match event {
                Events::IngressIp(ip) => match ip.dst_port {
                    22 => {
                        println!("SSH: {:?}", ip);
                        let mut ip_lock = ip_logs.lock().await;
                        ip_lock.insert(ip.src_ip, ip.ts);
                    }
                    _ => {
                        println!("{:?}", ip);
                    }
                },
                Events::Execve(execve) => {
                    println!("{:?}", execve);
                    if execve.exec.contains("sshd") {
                        sshd_tx.send(true).await.unwrap();
                    }
                }
            }
        }
    });

    task::spawn(async move {
        loop {
            if let Some(true) = sshd_rx.recv().await {
                if let Some(duration) = opt.duration {
                    let now = SystemTime::now();
                    let mut ip_lock = ip_logs_clone.lock().await;
                    let mut to_remove = Vec::new();
                    for (ip, time) in ip_lock.iter() {
                        if now.duration_since(*time).unwrap().as_secs() > BUFFER_TIME {
                            to_remove.push(*ip);
                        }
                    }
                    for ip in to_remove {
                        ip_lock.remove(&ip);
                    }
                    println!("Hashmap: {:?}", ip_lock);

                    if now.duration_since(start_time).unwrap().as_secs() > duration {
                        let mut values: Vec<[String; 2]> = Vec::new();
                        for (ip, ts) in ip_lock.iter() {
                            let value = [
                                ts.duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_nanos()
                                    .to_string(),
                                ip.to_string(),
                            ];
                            values.push(value);
                        }
                        // if auth_gen_ts is more than 25 minutes old, get a new auth token and reset auth_gen_ts
                        if auth_gen_ts.duration_since(UNIX_EPOCH).unwrap().as_secs() > 1500 {
                            let (new_auth, new_auth_gen_ts) =
                                get_auth(std::env::var("SUBCOM_TOKEN").unwrap())
                                    .await
                                    .unwrap();
                            auth_clone = new_auth;
                            auth_gen_ts = new_auth_gen_ts;
                        }
                        send_logs(auth_clone.as_ref(), values)
                            .await
                            .unwrap();
                    } else {
                        let mut frequently_seen_lock = frequently_seen.lock().await;
                        for (ip, _) in ip_lock.iter() {
                            if frequently_seen_lock.contains_key(ip) {
                                *frequently_seen_lock.get_mut(ip).unwrap() += 1;
                            } else {
                                frequently_seen_lock.insert(*ip, 1);
                            }
                        }
                    }
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
                        ts: SystemTime::now(),
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
