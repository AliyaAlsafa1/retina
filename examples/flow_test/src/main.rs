use clap::Parser;
use lazy_static::lazy_static;

use retina_core::{
    config::{default_config, load_config},
    filter::flow_drop::{install_drop_flow, uninstall_drop_flow},
    conntrack::pdu::L4Context,
    port::PortId,
    rte_flow,
    FiveTuple,
    Runtime,
};
use retina_datatypes::{ZcFrame};
use retina_filtergen::{filter, retina_main};

use std::{
    collections::{VecDeque, HashMap},
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

#[derive(Clone, Copy)]
struct Blocked {
    inserted_at: Instant,
    warned: bool,            // control for warning once per flow
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
    static ref TARGET_FLOWS: Mutex<HashMap<FiveTuple, Blocked>> = Mutex::new(HashMap::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new()); 
}

// Grace window for rule propagation / in-flight packets
const GRACE_MS: u64 = 3000;

// Timeout in seconds for installed flow rules
const TIMEOUT_SECS: u64 = 60;

// Number of flows to block
const NUM_FLOWS: usize = 1000000;

fn reverse_tuple(t: &FiveTuple) -> FiveTuple {
    // NOTE: FiveTuple in Retina carries {orig, resp, protocol}. Swap orig/resp.
    FiveTuple {
        orig: t.resp,   // swap endpoints
        resp: t.orig,
        proto: t.proto,
    }
}

// Get NUM_FLOWS amount of five_tuple from TLS handshake, block flow with that five_tuple
// Timeout flow after TIMEOUT_SECS seconds
#[filter("tls")]
fn tls_cb(tuple: &FiveTuple) {
    // own the key for HashMap / queue storage
    let tuple: FiveTuple = tuple.clone();

    // Check if tuple is already blocked or we have reached limit
    {
        let targets = TARGET_FLOWS.lock().unwrap();
        if targets.len() >= NUM_FLOWS || targets.contains_key(&tuple) {
            // Already blocking this tuple, or max flows reached, do nothing
            return;
        }
    } // drop(targets); // unlock before potentially long operation ?

    // Read ports (if not present, we can't install)
    let ports = if let Some(ports) = PORT_IDS.read().unwrap().as_ref() {
        ports.clone()
    } else {
        eprintln!("PORT_IDS is None when trying to install drop flow!");
        return;
    };

    // Install the drop rule first; only record as blocked on success
    let now = Instant::now();
    match install_drop_flow(ports.clone(), &tuple) {
        Ok(raw_flows) => {
            // Create FlowEntry with expiration time and push into FLOW_QUEUE
            let entry = FlowEntry {
                tuple: tuple.clone(),
                ports: ports.clone(),
                flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                expires_at: now + Duration::from_secs(TIMEOUT_SECS),
            };

            // Add to FLOW_QUEUE for expiration management
            FLOW_QUEUE.lock().unwrap().push_back(entry);

            // insert into the set (no duplicates) AFTER success
            let mut targets = TARGET_FLOWS.lock().unwrap();
            targets.insert(tuple.clone(), Blocked { inserted_at: now, warned: false });

            // also block the reverse direction so tcp_checker_cb matches either side
            let rev = reverse_tuple(&tuple);
            targets.insert(rev, Blocked { inserted_at: now, warned: false });
        }
        Err(e) => eprintln!("Failed to install drop flow: {:?}", e),
    }
}

// Expire flows and uninstall them
fn flow_expirer() {
    loop {
        thread::sleep(Duration::from_secs(1));
        let now = Instant::now();

        // Pop expired entries first while holding only the queue lock
        let mut expired: Vec<FlowEntry> = Vec::new();
        {
            let mut queue = FLOW_QUEUE.lock().unwrap();

            // Pop and uninstall flows that have expired
            while let Some(front) = queue.front() {
                if front.expires_at <= now {
                    let entry = queue.pop_front().unwrap();
                    expired.push(entry);
                } else {
                    break; // front not expired, stop checking
                }
            }
        } // drop queue lock before touching TARGET_FLOWS

        // Uninstall and then remove from TARGET_FLOWS (avoid lock inversion)
        for entry in expired {
            let raw_ptrs: Vec<*mut rte_flow> =
                entry.flow_ptrs.iter().map(|fp| fp.0).collect();

            if let Err(e) = uninstall_drop_flow(entry.ports.clone(), raw_ptrs) {
                eprintln!("Failed to uninstall drop flow: {:?}", e);
            }
            // can remove from the set after expiry
            TARGET_FLOWS.lock().unwrap().remove(&entry.tuple);
        }
    }
}


// Check if any five_tuples coming in match previously blocked flows
#[filter("tcp")]
fn tcp_checker_cb(zcframe: &ZcFrame) {
    if let Ok(ctxt) = L4Context::new(zcframe) {
        let now = Instant::now();
        let five_tuple = FiveTuple::from_ctxt(ctxt);

        let mut targets = TARGET_FLOWS.lock().unwrap();

        // Only warn if we've passed the grace window, and only once per flow
        if let Some(meta) = targets.get_mut(&five_tuple) {
            if now.duration_since(meta.inserted_at) >= Duration::from_millis(GRACE_MS) && !meta.warned {
                eprintln!(
                    "Unexpected TCP packet after drop (>={}ms since install): {:?}",
                    GRACE_MS, five_tuple
                );
                meta.warned = true;
            }
        }
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
    thread::spawn(flow_expirer);

    runtime.run();
}