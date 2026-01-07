use clap::{ArgAction, Parser, ValueEnum};
use lazy_static::lazy_static;
use serde::Serialize;

use retina_core::{
    CoreId, FiveTuple, Runtime,
    config::{default_config, load_config},
    conntrack::pdu::L4Context,
    filter::flow_drop::{install_drop_flow, uninstall_drop_flow},
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    port::PortId,
};

use retina_core::dpdk::rte_flow;

use retina_datatypes::{ConnRecord, TlsHandshake, ZcFrame};
use retina_filtergen::{filter, retina_main};

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

#[derive(Clone)]
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    expires_at: Instant,
}

lazy_static! {
    static ref PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
    static ref TARGET_FLOWS: Mutex<HashMap<FiveTuple, Instant>> = Mutex::new(HashMap::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new());
}

// Dispatching
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();

#[derive(Clone, Serialize)]
enum FlowEvent {
    /// Minimal payload to keep cloning cheap
    TlsSeen { tuple: FiveTuple, rx_core: CoreId },
}

const GRACE_PERIOD: u64 = 0;
// Simple counter
static GLOBAL_TLS_COUNTER: AtomicU64 = AtomicU64::new(0);

// ===== CLI =====
#[derive(Copy, Clone, Debug, ValueEnum)]
enum ChannelModeArg {
    PerCore,
    Shared,
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_parser, value_name = "FILE")]
    config: Option<PathBuf>,

    #[clap(
        short,
        long,
        value_parser,
        value_name = "FILE",
        default_value = "ports.jsonl"
    )]
    outfile: PathBuf,

    #[clap(long, value_name = "SIZE", default_value = "32768")]
    flow_channel_size: usize,

    #[clap(
        long,
        value_delimiter = ',',
        value_name = "CORES",
        default_value = "40"
    )]
    worker_cores: Vec<u32>,

    #[clap(long, value_name = "SIZE", default_value = "16")]
    batch_size: usize,

    #[clap(long, value_enum, default_value = "per-core")]
    channel_mode: ChannelModeArg,

    #[clap(long, value_parser, value_name = "PATH")]
    flush_channels: Option<PathBuf>,

    #[clap(long, action = ArgAction::SetTrue)]
    show_stats: bool,

    #[clap(long, action = ArgAction::SetTrue)]
    show_args: bool,

    #[clap(long, value_name = "TIMEOUT_SECS", default_value = "5")]
    timeout_secs: u64,

    #[clap(long, value_name = "NUM_FLOWS", default_value = "1000")]
    num_flows: usize,
}

// ===== Helpers =====

/// Expire and uninstall any rules whose deadlines have passed.
fn expire_flows_now() {
    let mut queue = FLOW_QUEUE.lock().unwrap();
    let now = Instant::now();

    while let Some(entry) = queue.front() {
        if entry.expires_at > now {
            break;
        }
        println!("expiring flows\n");
        // pop first (to drop the borrow) then uninstall
        let expired = queue.pop_front().unwrap();
        let raw_ptrs: Vec<*mut rte_flow> = expired.flow_ptrs.iter().map(|fp| fp.0).collect();
        if let Err(e) = uninstall_drop_flow(expired.ports.clone(), raw_ptrs) {
            eprintln!("Failed to uninstall drop flow: {:?}", e);
        }
        // Optionally also remove from TARGET_FLOWS when it expires:
        TARGET_FLOWS.lock().unwrap().remove(&expired.tuple);
    }
}

// ===== Filters =====

/// On each TLS handshake, just dispatch the tuple to worker threads.
/// Note: we include &CoreId to preserve per-RX-core affinity when ChannelMode::PerCore.
#[filter("tls")]
fn tls_cb(_tls: &TlsHandshake, five_tuple: &FiveTuple, rx_core: &CoreId) {
    // println!("inside tls\n");
    let tuple = five_tuple.clone();
    // GLOBAL_TLS_COUNTER.fetch_add(1, Ordering::Relaxed);
    if let Some(dispatcher) = FLOW_DISPATCHER.get() {
        let _ = dispatcher.dispatch(
            FlowEvent::TlsSeen {
                tuple,
                rx_core: *rx_core,
            },
            Some(rx_core), // preserve affinity when in PerCore mode
        );
    }
}

// #[filter("tcp")]
// fn tcp_checker_cb(zc: &ZcFrame, _core_id: &CoreId) {
//     // println!("inside tcp\n");
//     if let Ok(ctxt) = L4Context::new(zc) {
//         let five_tuple = FiveTuple::from_ctxt(ctxt);
//         let targets = TARGET_FLOWS.lock().unwrap();
//
//         if let Some(&inserted_at) = targets.get(&five_tuple) {
//             // Only complain if the flow has been in the drop set longer than GRACE_PERIOD
//             if Instant::now().duration_since(inserted_at) > Duration::from_secs(GRACE_PERIOD) {
//                 println!("Unexpected TCP packet after drop: {:?}", five_tuple);
//             }
//         }
//     }
// }

// ===== Main =====

#[retina_main(1)]
fn main() {
    // Parse CLI args
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }
    let timeout_secs: u64 = args.timeout_secs;
    let num_flows: usize = args.num_flows;

    let config = if let Some(path) = args.config.clone() {
        load_config(path)
    } else {
        default_config()
    };

    // Build ChannelMode
    let rx_cores = config.get_all_rx_core_ids();
    let channel_mode = match args.channel_mode {
        ChannelModeArg::PerCore => ChannelMode::PerCore(rx_cores),
        ChannelModeArg::Shared => ChannelMode::Shared,
    };

    // Create and publish the dispatcher
    let flow_dispatcher = Arc::new(ChannelDispatcher::new(
        channel_mode.clone(),
        args.flow_channel_size,
        "flow_dispatcher".to_string(),
    ));
    FLOW_DISPATCHER
        .set(flow_dispatcher.clone())
        .map_err(|_| "Failed to set FLOW dispatcher")
        .unwrap();

    // Map provided worker cores
    let worker_core_ids: Vec<CoreId> = args.worker_cores.iter().map(|&c| CoreId(c)).collect();

    // Spawn workers and attach the handler
    let worker_handle = SharedWorkerThreadSpawner::new()
        .set_cores(worker_core_ids)
        .set_batch_size(args.batch_size)
        .add_dispatcher(flow_dispatcher.clone(), move |event: FlowEvent| {
            // Lightweight periodic maintenance
            expire_flows_now();

            match event {
                FlowEvent::TlsSeen { tuple, .. } => {
                    // Respect NUM_FLOWS cap first
                    if num_flows == 0 {
                        return;
                    }

                    // Deduplicate and cap
                    {
                        let mut targets = TARGET_FLOWS.lock().unwrap();
                        if targets.contains_key(&tuple) || targets.len() >= num_flows {
                            println!("Not more flow available\n");
                            return;
                        }
                        // Record when we installed the drop rule for this tuple
                        targets.insert(tuple.clone(), Instant::now());
                    }

                    // Install, if we have ports
                    let maybe_ports = PORT_IDS.read().unwrap().clone();
                    if let Some(ports) = maybe_ports {
                        match install_drop_flow(ports.clone(), &tuple) {
                            Ok(raw_flows) => {
                                let entry = FlowEntry {
                                    tuple: tuple.clone(),
                                    ports: ports.clone(),
                                    flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                                    expires_at: Instant::now() + Duration::from_secs(timeout_secs),
                                };
                                FLOW_QUEUE.lock().unwrap().push_back(entry);
                            }
                            Err(e) => eprintln!("Failed to install drop flow: {:?}", e),
                        }
                    } else {
                        eprintln!("PORT_IDS is None when trying to install drop flow!");
                    }
                }
            }
        })
        .run();

    // Build runtime
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // Extract and store PortIds
    if let Some(online) = &config.online {
        let port_ids: Vec<PortId> = online
            .ports
            .iter()
            .map(|port| {
                println!("Device: {}", port.device);
                PortId::new_from_device(port.device.clone())
            })
            .collect();

        for pid in &port_ids {
            println!("Port ID: {:?}", pid);
        }

        *PORT_IDS.write().unwrap() = Some(port_ids);
    }

    println!("EVENT dut_ready\n");

    // Run packet processing
    runtime.run();

    // Graceful shutdown
    let final_stats = worker_handle.shutdown(args.flush_channels.as_ref());
    println!(
        "Number of TLS callbacks : {}",
        GLOBAL_TLS_COUNTER.load(Ordering::Relaxed)
    );

    if args.show_stats {
        if let Some(flow_stats) = final_stats.get(0) {
            println!("=== FLOW Stats ===");
            println!("{flow_stats}");
        }
    }
}
