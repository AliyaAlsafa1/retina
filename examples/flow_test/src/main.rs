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
    //static ref TARGET_FLOWS: Mutex<HashSet<FiveTuple>> = Mutex::new(HashSet::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new()); 
}

// Timeout in seconds for installed flow rules
const TIMEOUT_SECS: u64 = 5;

// Number of flows to block
const NUM_FLOWS: usize = 10000000;

// Get NUM_FLOWS amount of five_tuple from TLS handshake, block flow with that five_tuple
// Timeout flow after TIMEOUT_SECS seconds
#[filter("tls")]
fn tls_cb(_tls: &TlsHandshake, conn_record: &ConnRecord) {
    let tuple = &conn_record.five_tuple;

    //let mut targets = TARGET_FLOWS.lock().unwrap();

    // Check if tuple is already blocked or we have reached limit of 3
    /*
    if targets.contains(tuple) || targets.len() >= NUM_FLOWS {
        // Already blocking this tuple, or max flows reached, do nothing
        return;
    } else {
        // insert into the set (no duplicates)
        targets.insert(tuple.clone());
    }
    */

    //drop(targets); // unlock before potentially long operation ?
    if FLOW_QUEUE.lock().unwrap().len() < NUM_FLOWS {
        /*
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
        */
    }
}

// Expire flows and uninstall them
fn flow_expirer() {
    loop {
        //thread::sleep(Duration::from_secs(1));

        let mut queue = FLOW_QUEUE.lock().unwrap();
        let now = Instant::now();

        /*
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
            */
    }
}


// Check if any five_tuples coming in match previously blocked flows
#[filter("tcp")]
fn tcp_checker_cb(five_tuple: &FiveTuple, _core_id: &CoreId) {
    //println!("hi");
    //let targets = TARGET_FLOWS.lock().unwrap();
    //if targets.contains(five_tuple) {
        //println!("Unexpected TCP packet after drop: {:?}", five_tuple);
    //}
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