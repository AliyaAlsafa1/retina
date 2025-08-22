use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::net::{IpAddr};

use anyhow::{bail, Result};
use crate::FiveTuple;
use crate::port::PortId;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;

use crate::dpdk;
use crate::dpdk::{rte_flow, rte_flow_item, rte_flow_attr, rte_flow_error, rte_flow_create, 
    rte_flow_destroy, rte_flow_action, rte_flow_item_ipv4, rte_flow_item_ipv6, 
    rte_flow_item_tcp, rte_flow_item_udp};

// OLD VERSION
/*
fn find_table(five_tuple: &FiveTuple, num_tables: u32) -> u32 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    five_tuple.hash(&mut hasher);        // hash the five-tuple directly
    let h = hasher.finish();
    ((h % num_tables as u64) as u32) + 2 // map to a table index, skipping 0 and 1
}
*/


/// Tables installed by the dynamic redirect:
const BASE_GROUP: u32 = 2;        // groups 2..=14 installed
const LAST_GROUP_EXCL: u32 = 15;  // exclusive upper bound (2..15)
const L4_LSB_MASK: u16 = 0x000F;  // low 4 bits of dst port

/// Return the hw group (table) this 5-tuple maps to, or 0 if no jump rule applies.
/// Matches the rule: (dst_port & 0xF) == group - 1, groups in [2, 15].
fn find_table(tuple: &FiveTuple) -> u32 {
    // 6 = TCP, 17 = UDP; others don't have redirect rules → stay in table 0.
    let dst_port: u16 = match tuple.proto {
        6 | 17 => tuple.resp.port(),   // destination port
        _ => return 0,
    };

    let nibble = (dst_port & L4_LSB_MASK) as u32; // 0..14
    let group = nibble + 1;                       // because hw matches nibble == group - 1

    if (BASE_GROUP..LAST_GROUP_EXCL).contains(&group) {
        group                       // groups 2..=14
    } else {
        0                           // no jump rule → table 0
    }
}

// Take in vector of PortIds, FiveTuple to block, and returns a vector of flow pointers
pub fn install_drop_flow(port_ids: Vec<PortId>, tuple: &FiveTuple) -> Result<Vec<*mut rte_flow>> {
    let mut flows = Vec::with_capacity(port_ids.len());

    // Set ingress attribute
    let mut attr: rte_flow_attr = unsafe { mem::zeroed() };
    attr.set_ingress(1);
    attr.group = find_table(tuple);
    //attr.group = 0;
    println!("Installing rule for tuple {:?} in group {}", tuple, attr.group);
    attr.priority = 0;

    // Recommended to declare headers and masks here so they're not dropped prematurely
    let mut ipv4_spec: rte_flow_item_ipv4 = unsafe { mem::zeroed() };
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { mem::zeroed() };
    let mut ipv6_spec: rte_flow_item_ipv6 = unsafe { mem::zeroed() };
    let mut ipv6_mask: rte_flow_item_ipv6 = unsafe { mem::zeroed() };
    let mut tcp_spec: rte_flow_item_tcp = unsafe { mem::zeroed() };
    let mut tcp_mask: rte_flow_item_tcp = unsafe { mem::zeroed() };
    let mut udp_spec: rte_flow_item_udp = unsafe { mem::zeroed() };
    let mut udp_mask: rte_flow_item_udp = unsafe { mem::zeroed() };

    let (src_ip, dst_ip) = (tuple.orig.ip(), tuple.resp.ip());
    let (src_port, dst_port) = (tuple.orig.port(), tuple.resp.port());

    // Pattern buffer structure is ETH + [IP] + [L4] + END
    let mut pattern: [rte_flow_item; 5] = unsafe { mem::zeroed() };
    let mut i = 0;

    // ETH
    pattern[i] = rte_flow_item {
        type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH,
        spec: ptr::null(),
        mask: ptr::null(),
        last: ptr::null(),
    };
    i += 1;

    // Check IP version
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ipv4_spec.hdr.src_addr = u32::from_ne_bytes(src.octets());
            ipv4_spec.hdr.dst_addr = u32::from_ne_bytes(dst.octets());
            ipv4_spec.hdr.next_proto_id = tuple.proto as u8;

            ipv4_mask.hdr.src_addr = u32::MAX;
            ipv4_mask.hdr.dst_addr = u32::MAX;
            ipv4_mask.hdr.next_proto_id = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4,
                spec: &ipv4_spec as *const _ as *const _,
                mask: &ipv4_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ipv6_spec.hdr.src_addr = dpdk::rte_ipv6_addr { a: src.octets() };
            ipv6_spec.hdr.dst_addr = dpdk::rte_ipv6_addr { a: dst.octets() };
            ipv6_spec.hdr.proto = tuple.proto as u8;

            ipv6_mask.hdr.src_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            ipv6_mask.hdr.dst_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            ipv6_mask.hdr.proto = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6,
                spec: &ipv6_spec as *const _ as *const _,
                mask: &ipv6_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Mismatched IP versions"),
    }

    // Check TCP vs UDP
    match tuple.proto {
        TCP_PROTOCOL => {
            tcp_spec.hdr.src_port = src_port.to_be();
            tcp_spec.hdr.dst_port = dst_port.to_be();

            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP,
                spec: &tcp_spec as *const _ as *const _,
                mask: &tcp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        UDP_PROTOCOL => {
            udp_spec.hdr.src_port = src_port.to_be();
            udp_spec.hdr.dst_port = dst_port.to_be();

            udp_mask.hdr.src_port = 0xFFFF;
            udp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP,
                spec: &udp_spec as *const _ as *const _,
                mask: &udp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Unsupported protocol {}", tuple.proto),
    }

    // END
    pattern[i] = rte_flow_item {
        type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END,
        spec: ptr::null(),
        mask: ptr::null(),
        last: ptr::null(),
    };

    // Actions
    let actions = [
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP,
            conf: ptr::null(),
        },
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf: ptr::null(),
        },
    ];

    // Create flow rule using pattern
       for port_id in port_ids.iter() {
        let mut error: rte_flow_error = unsafe { mem::zeroed() };
        
        let start = unsafe { dpdk::rte_rdtsc() };
        let flow = unsafe {
            rte_flow_create(
                port_id.raw(),
                &attr,
                pattern.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };
        let duration = unsafe { dpdk::rte_rdtsc() } - start;
        println!("Latency (cycles): {}", duration);
        
        if flow.is_null() {
            let msg = unsafe {
                CStr::from_ptr(error.message)
                    .to_string_lossy()
                    .into_owned()
            };
            anyhow::bail!(
                "Failed to install flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        println!("Installed DROP rule on port {}", port_id.raw());
        flows.push(flow);
    }

    Ok(flows)
}

/// Uninstall DROP flow rules previously installed with `install_drop_flow`
pub fn uninstall_drop_flow(port_ids: Vec<PortId>, flows: Vec<*mut rte_flow>) -> Result<()> {
    if port_ids.len() != flows.len() {
        bail!(
            "Mismatched lengths: {} ports but {} flows",
            port_ids.len(),
            flows.len()
        );
    }

    for (port_id, flow) in port_ids.iter().zip(flows.iter()) {
        if flow.is_null() {
            println!("No DROP flow to uninstall on port {}", port_id.raw());
            continue;
        }

        let mut error: rte_flow_error = unsafe { mem::zeroed() };
        let start = unsafe { dpdk::rte_rdtsc() };
        let ret = unsafe { rte_flow_destroy(port_id.raw(), *flow, &mut error) };
        let duration = unsafe { dpdk::rte_rdtsc() } - start;
        println!("Uninstall latency (cycles): {}", duration);

        if ret != 0 {
            let msg = unsafe {
                CStr::from_ptr(error.message).to_string_lossy().into_owned()
            };
            bail!(
                "Failed to uninstall DROP flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        println!("Uninstalled DROP rule on port {}", port_id.raw());
    }

    Ok(())
}

/*
// OLD VERSION
pub fn uninstall_drop_flow(port_ids: Vec<PortId>, flows: Vec<*mut rte_flow>) -> Result<()> {
    if port_ids.len() != flows.len() {
        anyhow::bail!(
            "Mismatched lengths: {} ports but {} flows",
            port_ids.len(),
            flows.len()
        );
    }

    for (port_id, flow) in port_ids.iter().zip(flows.iter()) {
        if flow.is_null() {
            println!("No flow to uninstall on port {}", port_id.raw());
            continue;
        }

        let mut error: rte_flow_error = unsafe { std::mem::zeroed() };
        let start = unsafe { dpdk::rte_rdtsc() };
        let ret = unsafe { rte_flow_destroy(port_id.raw(), *flow, &mut error) };
        let duration = unsafe { dpdk::rte_rdtsc() } - start;
        println!("Latency (cycles): {}", duration);

        if ret != 0 {
            let msg = unsafe {
                CStr::from_ptr(error.message)
                    .to_string_lossy()
                    .into_owned()
            };
            anyhow::bail!(
                "Failed to uninstall flow on port {}: {}",
                port_id.raw(),
                msg
            );
        }

        println!("Uninstalled DROP rule on port {}", port_id.raw());
    }

    Ok(())
}
*/