/*
use clap::Parser;
use lazy_static::lazy_static;

use retina_core::{
    config::{default_config, load_config},
    filter::flow_drop::{install_drop_flow, uninstall_drop_flow},
    port::PortId,
    rte_flow,
    CoreId,
    FiveTuple,
    Runtime,
};
use retina_datatypes::{ConnRecord, TlsHandshake};
use retina_filtergen::{filter, retina_main};

use std::{
    collections::{VecDeque, HashSet},
    path::PathBuf,
    sync::{Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};

// Wrapper for raw flow pointer to implement Send + Sync
#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);

// Need to ensure proper synchronization and thread-safe usage externally
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

// Represent a flow entry with expiration time
#[derive(Clone)]
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    expires_at: Instant,
}

// Argument parsing
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: Option<PathBuf>,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "ports.jsonl"
    )]
    outfile: PathBuf,
}

// Global port IDs
lazy_static! {
    static ref PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
}

// Target flow to be blocked, and all blocked flow pointers
lazy_static! {
    static ref TARGET_FLOWS: Mutex<HashSet<FiveTuple>> = Mutex::new(HashSet::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new()); 
}

// Timeout in seconds for installed flow rules
const TIMEOUT_SECS: u64 = 5;

// Number of flows to block
const NUM_FLOWS: usize = 0;

// Get NUM_FLOWS amount of five_tuple from TLS handshake, block flow with that five_tuple
// Timeout flow after TIMEOUT_SECS seconds
#[filter("tls")]
fn tls_cb(_tls: &TlsHandshake, conn_record: &ConnRecord) {
    let tuple = &conn_record.five_tuple;

    let mut targets = TARGET_FLOWS.lock().unwrap();

    // Check if tuple is already blocked or we have reached limit of 3
    
    if targets.contains(tuple) || targets.len() >= NUM_FLOWS {
        // Already blocking this tuple, or max flows reached, do nothing
        return;
    } else {
        // insert into the set (no duplicates)
        targets.insert(tuple.clone());
    }
    

    //drop(targets); // unlock before potentially long operation ?
    if FLOW_QUEUE.lock().unwrap().len() < NUM_FLOWS {
        
        if let Some(ports) = PORT_IDS.read().unwrap().as_ref() {
            match install_drop_flow(ports.clone(), tuple) {
                Ok(raw_flows) => {
                    // Create FlowEntry with expiration time and push into FLOW_QUEUE
                    let entry = FlowEntry {
                        tuple: tuple.clone(),
                        ports: ports.clone(),
                        flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                        expires_at: Instant::now() + Duration::from_secs(TIMEOUT_SECS),
                    };

                    // Add to FLOW_QUEUE for expiration management
                    FLOW_QUEUE.lock().unwrap().push_back(entry);
                }
                Err(e) => eprintln!("Failed to install drop flow: {:?}", e),
            }
        } else {
            eprintln!("PORT_IDS is None when trying to install drop flow!");
        }
        
    }
}

// Expire flows and uninstall them
fn flow_expirer() {
    loop {
        thread::sleep(Duration::from_secs(1));

        let mut queue = FLOW_QUEUE.lock().unwrap();
        let now = Instant::now();

        
        // Pop and uninstall flows that have expired
        while let Some(entry) = queue.front() {
            if entry.expires_at <= now {
                let raw_ptrs: Vec<*mut rte_flow> =
                    entry.flow_ptrs.iter().map(|fp| fp.0).collect();

                if let Err(e) = uninstall_drop_flow(entry.ports.clone(), raw_ptrs) {
                    eprintln!("Failed to uninstall drop flow: {:?}", e);
                }
                // can remove from the set after expiry
                // TARGET_FLOWS.lock().unwrap().remove(&entry.tuple);

                queue.pop_front();
            } else {
                break; // front not expired, stop checking
            }
        }
            
    }
}


// Check if any five_tuples coming in match previously blocked flows
#[filter("tcp")]
fn tcp_checker_cb(five_tuple: &FiveTuple, _core_id: &CoreId) {
    //println!("hi");
    let targets = TARGET_FLOWS.lock().unwrap();
    if targets.contains(five_tuple) {
        //println!("Unexpected TCP packet after drop: {:?}", five_tuple);
    }
}


#[retina_main(2)]
fn main() {
    // Take in arguments and config file
    let args = Args::parse();

    let config = if let Some(path) = args.config {
        load_config(path)
    } else {
        default_config()
    };

    // Create runtime
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // Extract port IDs from config
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

        // Store port IDs
        *PORT_IDS.write().unwrap() = Some(port_ids);
    }

    // Spawn the background expiration thread here
    //thread::spawn(flow_expirer);

    runtime.run();
}
*/

use clap::{ArgAction::SetTrue, Parser};
use lazy_static::lazy_static;
use serde::Serialize;

use retina_core::{
    config::{default_config, load_config},
    filter::flow_drop::{install_drop_flow, uninstall_drop_flow},
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    port::PortId,
    rte_flow,
    CoreId,
    FiveTuple,
    Runtime,
};
use retina_datatypes::{ConnRecord, TlsHandshake};
use retina_filtergen::{filter, retina_main};

use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, Instant},
};

// ===== Globals you already had =====

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
    static ref TARGET_FLOWS: Mutex<HashSet<FiveTuple>> = Mutex::new(HashSet::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new());
}

// ===== Dispatching infra (new) =====

static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();

#[derive(Clone, Serialize)]
enum FlowEvent {
    /// Minimal payload to keep cloning cheap
    TlsSeen { tuple: FiveTuple, rx_core: CoreId },
}

// ===== Tunables =====

const TIMEOUT_SECS: u64 = 5;
// Number of flows to block (<= 0 means "disabled")
const NUM_FLOWS: usize = 0;

// ===== CLI =====

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum ChannelModeArg {
    PerCore,
    Shared,
}

#[derive(Parser, Debug)]
struct Args {
    /// Config file; if omitted falls back to default_config()
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: Option<PathBuf>,

    /// (Kept from your original; currently unused—retain if you plan to write ports/rules)
    #[clap(short, long, parse(from_os_str), value_name = "FILE", default_value = "ports.jsonl")]
    outfile: PathBuf,

    /// Channel size for the flow dispatcher
    #[clap(long, value_name = "SIZE", default_value = "32768")]
    flow_channel_size: usize,

    /// Worker cores where the **processing** happens (not the RX cores)
    #[clap(
        long,
        value_delimiter = ',',
        value_name = "CORES",
        // adjust to your machine; example: one worker on core 40
        default_value = "40"
    )]
    worker_cores: Vec<u32>,

    /// How many events each worker pops per loop
    #[clap(long, value_name = "SIZE", default_value = "16")]
    batch_size: usize,

    /// Per-core lanes (affinity) vs one shared lane
    #[clap(long, value_enum, default_value = "per-core")]
    channel_mode: ChannelModeArg,

    /// Optionally dump channels on shutdown (for debugging)
    #[clap(long, value_name = "PATH", parse(from_os_str))]
    flush_channels: Option<PathBuf>,

    #[clap(long, action = SetTrue)]
    show_stats: bool,

    #[clap(long, action = SetTrue)]
    show_args: bool,
}

// ===== Helpers =====

/// Expire and uninstall any rules whose deadlines have passed.
/// Runs cheaply at the start of each worker handler invocation.
fn expire_flows_now() {
    let mut queue = FLOW_QUEUE.lock().unwrap();
    let now = Instant::now();

    while let Some(entry) = queue.front() {
        if entry.expires_at > now {
            break;
        }
        // pop first (to drop the borrow) then uninstall
        let expired = queue.pop_front().unwrap();
        let raw_ptrs: Vec<*mut rte_flow> = expired.flow_ptrs.iter().map(|fp| fp.0).collect();
        if let Err(e) = uninstall_drop_flow(expired.ports.clone(), raw_ptrs) {
            eprintln!("Failed to uninstall drop flow: {:?}", e);
        }
        // Optionally also remove from TARGET_FLOWS when it expires:
        // TARGET_FLOWS.lock().unwrap().remove(&expired.tuple);
    }
}

// ===== Filters =====

/// On each TLS handshake, just dispatch the tuple to worker threads.
/// Note: we include &CoreId to preserve per-RX-core affinity when ChannelMode::PerCore.
#[filter("tls")]
fn tls_cb(_tls: &TlsHandshake, conn_record: &ConnRecord, rx_core: &CoreId) {
    let tuple = conn_record.five_tuple.clone();

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

/// Keep your TCP checker as-is; it's light-weight and just reads the shared set.
#[filter("tcp")]
fn tcp_checker_cb(five_tuple: &FiveTuple, _core_id: &CoreId) {
    let targets = TARGET_FLOWS.lock().unwrap();
    if targets.contains(five_tuple) {
        // println!("Unexpected TCP packet after drop: {:?}", five_tuple);
    }
}

// ===== Main =====

#[retina_main(2)]
fn main() {
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }

    // Load config (yours: fallback to default_config() if no --config)
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
        .add_dispatcher(flow_dispatcher.clone(), |event: FlowEvent| {
            // Lightweight periodic maintenance
            expire_flows_now();

            match event {
                FlowEvent::TlsSeen { tuple, .. } => {
                    // Respect NUM_FLOWS cap first
                    if NUM_FLOWS == 0 {
                        return;
                    }

                    // Deduplicate and cap
                    {
                        let mut targets = TARGET_FLOWS.lock().unwrap();
                        if targets.contains(&tuple) || targets.len() >= NUM_FLOWS {
                            return;
                        }
                        targets.insert(tuple.clone());
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
                                    expires_at: Instant::now() + Duration::from_secs(TIMEOUT_SECS),
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

    // Extract and store PortIds (unchanged from your code)
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

    // NOTE: We no longer need a separate expirer thread; workers call `expire_flows_now()`.
    // If you want a dedicated expirer thread anyway, you can still spawn one safely.

    // Run packet processing
    runtime.run();

    // Graceful shutdown
    let final_stats = worker_handle.shutdown(args.flush_channels.as_ref());

    if args.show_stats {
        if let Some(flow_stats) = final_stats.get(0) {
            println!("=== FLOW Stats ===");
            println!("{flow_stats}");
        }
    }
}
