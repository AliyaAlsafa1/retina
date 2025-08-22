mod flow_action;
mod flow_attr;
mod flow_item;

use self::flow_action::*;
use self::flow_attr::*;
use self::flow_item::*;

use super::ast::*;
use super::pattern::*;
use super::ptree_flat::FlatPTree;
use super::Filter;

use crate::dpdk;
use crate::port::*;

use std::ffi::{c_void, CStr};
use std::fmt;
use std::mem;

use anyhow::{bail, Result};
use log::{debug, error, info, warn};
use thiserror::Error;

// priority levels for ingress rules
const HIGH_PRIORITY: u32 = 0;
const LOW_PRIORITY: u32 = 3;

#[derive(Debug)]
pub(crate) struct HardwareFilter<'a> {
    // Patterns that will retain traffic, as layered patterns,
    // with only predicates supported by the NIC retained.
    // Any traffic not matching a pattern will be dropped
    // by the NIC.
    patterns: Vec<LayeredPattern>,
    // Port to install filter on.
    // We expect each port to install the HW filter at startup.
    port: &'a Port,
}

impl<'a> HardwareFilter<'a> {
    // Creates a new HardwareFilter for port given a filter.
    // Prunes all predicates not supported by the device.
    pub(crate) fn new(filter: &Filter, port: &'a Port) -> Self {
        let hw_patterns = filter
            .get_patterns_flat()
            .iter()
            .map(|p| p.retain_hardware_predicates(port))
            .collect::<Vec<_>>();

        // Prune some redundant patterns.
        // \note This does not do the parent-child sorting of the SW filter;
        // this seems to be ok for Retina's current scale
        // (applying NIC rules is fast and we're not hitting NIC limits)
        let mut hw_ptree = FlatPTree::new(&hw_patterns);
        hw_ptree.prune_branches();
        let mut hw_patterns = hw_ptree.to_flat_patterns();

        let mut layered = vec![];
        for pattern in hw_patterns.iter_mut() {
            // Only retaining hardware filterable predicates may make
            // a pattern no-longer fully qualified. Therefore, we must
            // broaden pattern until hardware filterable again
            while !pattern.is_fully_qualified() {
                pattern.predicates.pop();
            }
            // converts to LayeredPattern
            layered.extend(pattern.to_fully_qualified().expect("fully qualified"));
        }

        // Remove identical patterns
        layered.sort();
        layered.dedup();

        
        HardwareFilter {
            patterns: layered,
            port,
        }
    }

    // Installs the hardware filter to the port.
    pub(crate) fn install(&self) -> Result<()> {
        debug!("{}", self);
        if self.patterns.iter().all(|p| p.is_empty()) {
            info!("Empty filter, skipping.");
            return Ok(());
        }

        info!("Applying hardware filter rules on Port {}...", self.port.id);
        for pattern in self.patterns.iter() {
            // Traffic matching installed patterns will be redirected
            // to a core via RSS.

            // @ALIYA - MODIFY CODE IN INSTALL_PATTERN
            // --> Goal is to change the result of this pattern to "redirect"

            install_pattern(pattern, self.port, 0, HIGH_PRIORITY)?;
        }

        // @ALIYA - add logic here to install a default (low priority)
        // RSS rule on each table (except table 1, which we're
        // using to drop traffic)

        //let _ = add_masked_redirects(self.port, 0);

        // Non-matching traffic will be dropped by default on table 1
        // Redirect is faster than using a default DROP rule
                // Pattern matches all Ethernet traffic
        let mut pattern_rules: PatternRules = vec![];
        flow_item::append_eth(&mut pattern_rules);
        flow_item::append_end(&mut pattern_rules);
        add_redirect(self.port, 0, 1, LOW_PRIORITY, &pattern_rules)?;
        // drop_eth_traffic(self.port, 0, LOW_PRIORITY)?;

        Ok(())
    }
}

impl fmt::Display for HardwareFilter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "[HardwareFilter]: ")?;
        for pattern in self.patterns.iter() {
            writeln!(f, "{}", pattern.to_flat_pattern())?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub(crate) enum HardwareFilterError {
    #[error("Rule validation for {lpattern} failed on creation attempt. Reason: {reason}")]
    Validation {
        lpattern: LayeredPattern,
        reason: String,
    },

    #[error("Rule for {lpattern} validated but failed creation. Reason: {reason}")]
    Creation {
        lpattern: LayeredPattern,
        reason: String,
    },

    #[error("Hardware flow rule invalid: {0}")]
    InvalidRule(LayeredPattern),
}

pub(crate) fn device_supported(pred: &Predicate, port: &Port) -> bool {
    // Device supported protocols
    let hw_filterable_protos = hashset! {
        protocol!("ipv4"),
        protocol!("ipv6"),
        protocol!("tcp"),
        protocol!("udp"),
    };
    let proto_supported = hw_filterable_protos.contains(pred.get_protocol());
    if !proto_supported {
        info!("Hardware filter does not support protocol for: [{}]", pred);
        return false;
    }

    // Only allow equality predicates
    // MLX5 only supports equality or masked IP address
    let op_supported = match pred {
        Predicate::Unary { .. } => true,
        Predicate::Binary {
            protocol,
            field: _,
            op,
            value: _,
        } => {
            matches!(op, BinOp::Eq)
                || protocol == &protocol!("ipv4") && matches!(op, BinOp::In)
                || protocol == &protocol!("ipv6") && matches!(op, BinOp::In)
        }
    };
    if !op_supported {
        info!(
            "Hardware filter does not support binary comparison operator for: [{}]",
            pred
        );
        return false;
    }

    // The only way to truly tell if predicate on a field is supported is to
    // fully-qualify it and test if all fully-qualified patterns validate successfully.
    // This still does not guarantee the flow rule will create successfully.
    // For example, a collision detected or device resource limitations.
    // Hardware Rules are created on table 0 (group 0) with high priority
    // matching.
    let pred_supported = predicate_supported(pred, port, 0, HIGH_PRIORITY);
    if !pred_supported {
        info!("Hardware filter does not support predicate: [{}]", pred);
        return false;
    }
    true
}

fn predicate_supported(predicate: &Predicate, port: &Port, group: u32, priority: u32) -> bool {
    let pattern = FlatPattern {
        predicates: vec![predicate.to_owned()],
    };
    let fq_patterns = pattern.to_fully_qualified().expect("fully qualified");
    fq_patterns
        .iter()
        .all(|p| pattern_supported(p, port, group, priority))
}

fn pattern_supported(lpattern: &LayeredPattern, port: &Port, group: u32, priority: u32) -> bool {
    let attr = FlowAttribute::new(group, priority);
    let pattern = FlowPattern::from_layered_pattern(lpattern);
    // debug!("lpattern: {}", lpattern);
    match pattern {
        Ok(mut pattern) => {
            let mut action = FlowAction::new(port.id);

            action.append_rss();
            action.finish();

            validate_rule(port, attr, &mut pattern, &mut action)
        }
        Err(error) => {
            warn!("{}", error);
            false
        }
    }
}

fn validate_rule(
    port: &Port,
    attr: FlowAttribute,
    pattern: &mut FlowPattern,
    action: &mut FlowAction,
) -> bool {
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    for item in pattern.items.iter() {
        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec = item.spec();
        p_item.mask = item.mask();
        pattern_rules.push(p_item);
    }
    flow_item::append_end(&mut pattern_rules);

    // Need to update flow_action_rss here
    // reta_raw needs to stay in scope until after rte_flow_validate() succeeds
    let reta_raw = port.reta.iter().map(|q| q.raw()).collect::<Vec<_>>();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS = a.type_ {
            action.rss[0].queue_num = port.queue_map.len() as u32;
            action.rss[0].queue = reta_raw.as_ptr();
            a.conf = &action.rss[0] as *const _ as *const c_void;
        }
    }

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        ret == 0
    }
}

/*
// ORIGINAL

fn install_pattern(
    lpattern: &LayeredPattern,
    port: &Port,
    group: u32,
    priority: u32,
) -> Result<()> {
    let attr = FlowAttribute::new(group, priority);
    if let Ok(mut pattern) = FlowPattern::from_layered_pattern(lpattern) {
        let mut action = FlowAction::new(port.id);
        // action.append_mark(tag as u32);

        action.append_rss();
        action.finish();

        create_rule(lpattern, port, attr, &mut pattern, &mut action)
    } else {
        bail!(HardwareFilterError::InvalidRule(lpattern.to_owned()));
    }
}
*/

// Changed this to install jump rule to Table >= 2, use same logic in Table 2 now.
fn install_pattern(
    lpattern: &LayeredPattern,
    port: &Port,
    group: u32,
    priority: u32,
) -> Result<()> {
    // Pick the table this pattern should land in
    //let target_table = choose_table(lpattern, NUM_TABLES);

    let attr = FlowAttribute::new(group, priority);

    // First: install redirect for this pattern (pattern match → jump to chosen table)
    //let _ = add_redirect_for_pattern(port, lpattern, 0, target_table, LOW_PRIORITY);

    if let Ok(mut pattern) = FlowPattern::from_layered_pattern(lpattern) {
        let mut action = FlowAction::new(port.id);

        action.append_rss();
        action.finish();

        create_rule(lpattern, port, attr, &mut pattern, &mut action)
    } else {
        bail!(HardwareFilterError::InvalidRule(lpattern.to_owned()));
    } 
}

/*
// ADDED
fn add_masked_redirects(port: &Port, from_group: u32) -> Result<()> {
    let mask: u16 = 0x000F; // low 4 bits
    for bitval in 0..16 {
        let value = bitval as u16;
        let to_group = 2 + (bitval % 13); // maps to 2..=14
        add_masked_redirect(port, from_group, to_group, HIGH_PRIORITY, mask, value)?;
    }
    Ok(())
}


fn add_masked_redirect(
    port: &Port,
    from_group: u32,
    to_group: u32,
    priority: u32,
    _mask: u16,
    value: u16,
) -> Result<()> {
    println!(
        "[masked redirect] from_group={} → to_group={} (value=0x{:04x}, priority={})",
        from_group, to_group, value, priority
    );

    let attr = FlowAttribute::new(from_group, priority);

    // Start building pattern
    let mut pattern = FlowPattern::default();
    pattern.append_eth()?;
    pattern.append_ipv4()?; // If needed

    // Add custom TCP predicate based on src_port low 4 bits
    let predicate = Predicate::Binary {
        protocol: Protocol::Tcp,
        field: Field::with_name("src_port"),
        op: Operator::Eq,
        value: Value::Int(value as i64),
    };

    pattern.append_masked_tcp(&[predicate])?;
    pattern.append_end()?;

    // Set action to redirect
    let mut action = FlowAction::new(port.id);
    action.append_jump(to_group);
    action.finish();

    for a in action.rules.iter_mut() {
        if a.type_ == dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP {
            a.conf = &action.jump[0] as *const _ as *const c_void;
        }
    }

    info!(
        "Setting port {} to redirect from group {} to {}...",
        port.id, from_group, to_group
    );

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };

    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern.as_ptr(),
            action.rules.as_ptr(),
            &mut error,
        );
        if ret != 0 {
            let msg = CStr::from_ptr(error.message).to_string_lossy().to_string();
            error!("Redirect rule failed validation: {}", msg);
            bail!(HardwareFilterError::Validation {
                lpattern: LayeredPattern::new(),
                reason: msg,
            });
        }

        let flow = dpdk::rte_flow_create(
            port.id.raw(),
            attr.raw() as *const _,
            pattern.as_ptr(),
            action.rules.as_ptr(),
            &mut error,
        );

        if flow.is_null() {
            let msg = CStr::from_ptr(error.message).to_string_lossy().to_string();
            error!("Redirect rule failed creation: {}", msg);
            bail!(HardwareFilterError::Creation {
                lpattern: LayeredPattern::new(),
                reason: msg,
            });
        } else {
            info!("Created hardware flow rule for redirect.");
        }
    }

    Ok(())
}
*/

fn create_rule(
    lpattern: &LayeredPattern,
    port: &Port,
    attr: FlowAttribute,
    pattern: &mut FlowPattern,
    action: &mut FlowAction,
) -> Result<()> {
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    for item in pattern.items.iter() {
        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec = item.spec();
        p_item.mask = item.mask();
        pattern_rules.push(p_item);
    }
    flow_item::append_end(&mut pattern_rules);

    // Need to update flow_action_rss here
    // reta_raw needs to stay in scope until after rte_flow_create() succeeds
    let reta_raw = port.reta.iter().map(|q| q.raw()).collect::<Vec<_>>();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS = a.type_ {
            action.rss[0].queue_num = port.queue_map.len() as u32;
            action.rss[0].queue = reta_raw.as_ptr();
            a.conf = &action.rss[0] as *const _ as *const c_void;
        }
    }

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            let msg: &CStr = CStr::from_ptr(error.message);
            bail!(HardwareFilterError::Validation {
                lpattern: lpattern.to_owned(),
                reason: msg.to_str().unwrap().to_string()
            });
        } else {
            let ret = dpdk::rte_flow_create(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret.is_null() {
                let msg: &CStr = CStr::from_ptr(error.message);
                bail!(HardwareFilterError::Creation {
                    lpattern: lpattern.to_owned(),
                    reason: msg.to_str().unwrap().to_string()
                });
            } else {
                info!("Hardware flow rule created: {}", lpattern);
                Ok(())
            }
        }
    }
}

// ADDED
/*
fn add_redirect_for_pattern(
    port: &Port,
    lpattern: &LayeredPattern,
    from_group: u32,
    to_group: u32,
    priority: u32,
) -> Result<()> {
    let attr = FlowAttribute::new(from_group, priority);

    // convert LayeredPattern -> FlowPattern -> rte_flow_item
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    let pattern = FlowPattern::from_layered_pattern(lpattern)?;
    for item in pattern.items.iter() {
        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec = item.spec();
        p_item.mask = item.mask();
        pattern_rules.push(p_item);
    }
    flow_item::append_end(&mut pattern_rules);

    let mut action = FlowAction::new(port.id);
    action.append_jump(to_group);
    action.finish();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP = a.type_ {
            a.conf = &action.jump[0] as *const _ as *const c_void;
        }
    }

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            let msg = CStr::from_ptr(error.message).to_string_lossy();
            bail!("Redirect validation failed: {}", msg);
        }
        let ret = dpdk::rte_flow_create(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret.is_null() {
            let msg = CStr::from_ptr(error.message).to_string_lossy();
            bail!("Redirect creation failed: {}", msg);
        }
    }

    Ok(())
}
*/

fn add_redirect(
    port: &Port,
    from_group: u32,
    to_group: u32,
    priority: u32,
    pattern_rules: &PatternRules,
) -> Result<()> {
    let attr = FlowAttribute::new(from_group, priority);

    // @ALIYA - changed this so that the pattern is specified by the caller,
    // vs. redirecting ALL traffic.

    // Set action to redirect
    let mut action = FlowAction::new(port.id);
    action.append_jump(to_group);
    action.finish();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP = a.type_ {
            a.conf = &action.jump[0] as *const _ as *const c_void;
        }
    }

    info!(
        "Setting port {} to redirect from group {} to {}...",
        port.id, from_group, to_group
    );

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            let msg: &CStr = CStr::from_ptr(error.message);
            error!("Redirect rule failed validation: {}", msg.to_str().unwrap());
            bail!(HardwareFilterError::Validation {
                lpattern: LayeredPattern::new(),
                reason: msg.to_str().unwrap().to_string()
            });
        } else {
            let ret = dpdk::rte_flow_create(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret.is_null() {
                error!("Redirect rule failed creation.");
                let msg: &CStr = CStr::from_ptr(error.message);
                bail!(HardwareFilterError::Creation {
                    lpattern: LayeredPattern::new(),
                    reason: msg.to_str().unwrap().to_string()
                });
            } else {
                info!("Created hardware flow rule for redirect.");
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn drop_eth_traffic(port: &Port, group: u32, priority: u32) -> Result<()> {
    let attr = FlowAttribute::new(group, priority);

    // Pattern matches all Ethernet traffic
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    flow_item::append_end(&mut pattern_rules);

    // Set action to DROP
    let mut action = FlowAction::new(port.id);
    action.append_drop();
    action.finish();

    info!(
        "Setting port {} to drop all ethernet traffic by default...",
        port.id
    );

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            error!("Default drop rule failed validation.");
            let msg: &CStr = CStr::from_ptr(error.message);
            bail!(HardwareFilterError::Validation {
                lpattern: LayeredPattern::new(),
                reason: msg.to_str().unwrap().to_string()
            });
        } else {
            let ret = dpdk::rte_flow_create(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret.is_null() {
                error!("Default drop rule failed creation.");
                let msg: &CStr = CStr::from_ptr(error.message);
                bail!(HardwareFilterError::Creation {
                    lpattern: LayeredPattern::new(),
                    reason: msg.to_str().unwrap().to_string()
                });
            } else {
                info!("Created hardware flow rule to drop ethernet traffic by default.");
            }
        }
    }
    Ok(())
}

// Flush all flow rules associated with port
pub(crate) fn flush_rules(port: &Port) {
    info!("Flushing flow rules on Port {}", port.id);
    unsafe {
        let mut error: dpdk::rte_flow_error = mem::zeroed();
        let ret = dpdk::rte_flow_flush(port.id.raw(), &mut error as &mut _);
        if ret != 0 {
            let msg: &CStr = CStr::from_ptr(error.message);
            panic!(
                "Flush rules failed. Port in inconsistent state, please restart: {}",
                msg.to_str().unwrap()
            );
        }
    }
}


// This uses the port mask approach, which is a bit hacky --
// if we could pipe in an RSS result, that would be better, but it's
// less likely to be supported by all NICs, and it's hard to figure out.
pub(crate) fn install_dyn_hardware_rules(port: &Port) -> Result<()> {
    const BASE_GROUP: u32 = 2;
    const LAST_GROUP: u32 = 14;
    const NUM_GROUPS: u32 = LAST_GROUP - BASE_GROUP + 1; // 13

    for nibble in 0u16..=15 {
        // Match packets whose dest L4 port has this low nibble
        let item = flow_item::build_tcp_port_mask(nibble, 0x000F);

        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec  = item.spec();
        p_item.mask  = item.mask();

        let mut pattern = Vec::new();
        flow_item::append_eth(&mut pattern);
        // (append IPv4/IPv6 if your PMD requires it)
        pattern.push(p_item);
        flow_item::append_end(&mut pattern);

        // Compute destination group via modulo, exactly like find_table
        let group = BASE_GROUP + ((nibble as u32) % NUM_GROUPS);

        add_redirect(port, 0, group, HIGH_PRIORITY, &pattern)?;

        // Repeat for UDP with build_udp_port_mask(nibble, 0x000F)
    }

    // 1. Install redirects in tables 2..16
    // Redirects only to groups 2..=14
    /*
    for group in 2..15 // 2..=14
    {
        // Make group 2 map to nibble 0, group 14 -> nibble 12
        let nibble = (group - 2) as u16;      // 0..12
        let item = flow_item::build_tcp_port_mask(nibble, 0x000F);

        // All tcp packets with LSBs == `group - 1`
        // (Not sure if this is the right bit math)
        //let item = flow_item::build_tcp_port_mask(group - 1, 0x000F);

        // Have to build the pattern here so that pointers to fields in `item`
        // are still in scope when rule is installed.
        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec = item.spec();
        p_item.mask = item.mask();

        // In DPDK-land
        let mut pattern = vec![];
        flow_item::append_eth(&mut pattern);
        pattern.push(p_item);
        flow_item::append_end(&mut pattern);

        let _ = add_redirect(port, 0, group as u32, HIGH_PRIORITY, &pattern);

        // Repeat for UDP
    }
    */

    // 2. Install RSS with LOW_PRIORITY on all other tables
    for group in 2..16
    /* replace with NUM_TABLES */
    {
        // Low priority on table N
        let attr = FlowAttribute::new(group, LOW_PRIORITY);
        // Action: RSS
        let mut action = FlowAction::new(port.id);
        action.append_rss();
        action.finish();
        // All Ethernet traffic
        let mut pattern_rules: PatternRules = vec![];
        flow_item::append_eth(&mut pattern_rules);
        flow_item::append_end(&mut pattern_rules);

        // Everything below is copy-pasted from `create_rule` (obviously could be decomposed)
        let reta_raw = port.reta.iter().map(|q| q.raw()).collect::<Vec<_>>();
        for a in action.rules.iter_mut() {
            if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS = a.type_ {
                action.rss[0].queue_num = port.queue_map.len() as u32;
                action.rss[0].queue = reta_raw.as_ptr();
                a.conf = &action.rss[0] as *const _ as *const c_void;
            }
        }

        let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
        unsafe {
            let ret = dpdk::rte_flow_validate(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret != 0 {
                let _msg: &CStr = CStr::from_ptr(error.message);
                // bail
            } else {
                let ret = dpdk::rte_flow_create(
                    port.id.raw(),
                    attr.raw() as *const _,
                    pattern_rules.as_ptr(),
                    action.rules.as_ptr(),
                    &mut error as *mut _,
                );
                if ret.is_null() {
                    let _msg: &CStr = CStr::from_ptr(error.message);
                    // bail
                }
            }
        }
    }
    Ok(())
}