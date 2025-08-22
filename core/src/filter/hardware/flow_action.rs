use crate::dpdk;
use crate::port::{PortId, SYMMETRIC_RSS_KEY};

use std::mem;

pub(super) type ActionRules = Vec<dpdk::rte_flow_action>;

// Builds a vector of rte_flow_action
// #[derive(Debug, Clone)]
pub(super) struct FlowAction {
    pub(super) rules: ActionRules,
    port_id: PortId,

    // The following vectors contain configurations [conf] for special action
    pub(super) rss: Vec<dpdk::rte_flow_action_rss>,
    pub(super) jump: Vec<dpdk::rte_flow_action_jump>,
    pub(super) mark: Vec<dpdk::rte_flow_action_mark>,
    // drop has no config
}

impl FlowAction {
    pub(super) fn new(port_id: PortId) -> FlowAction {
        FlowAction {
            rules: ActionRules::new(),
            port_id,
            rss: Vec::<dpdk::rte_flow_action_rss>::new(),
            jump: Vec::<dpdk::rte_flow_action_jump>::new(),
            #[allow(dead_code)]
            mark: Vec::<dpdk::rte_flow_action_mark>::new(),
        }
    }

    pub(super) fn finish(&mut self) {
        // Add END terminator
        let mut a_end: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_end.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END;
        self.rules.push(a_end);
    }

    pub(super) fn append_jump(&mut self, group: u32) {
        let mut a_jump: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_jump.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP;
        self.rules.push(a_jump);

        let mut jump_conf: dpdk::rte_flow_action_jump = unsafe { mem::zeroed() };
        jump_conf.group = group;

        self.jump.push(jump_conf);
    }

    #[allow(dead_code)]
    pub(super) fn append_mark(&mut self, mark: u32) {
        let mut a_mark: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_mark.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_MARK;
        self.rules.push(a_mark);

        let mut mark_conf: dpdk::rte_flow_action_mark = unsafe { mem::zeroed() };
        mark_conf.id = mark;

        self.mark.push(mark_conf);
    }

    pub(super) fn append_rss(&mut self) {
        let mut a_rss: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_rss.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS;
        self.rules.push(a_rss);

        let mut rss_conf: dpdk::rte_eth_rss_conf = unsafe { mem::zeroed() };
        let ret = unsafe { dpdk::rte_eth_dev_rss_hash_conf_get(self.port_id.raw(), &mut rss_conf) };
        assert_eq!(ret, 0);

        let mut a_rss_conf: dpdk::rte_flow_action_rss = unsafe { mem::zeroed() };
        a_rss_conf.func = dpdk::rte_eth_hash_function_RTE_ETH_HASH_FUNCTION_TOEPLITZ;
        // Innermost encapsulation level PMD can handle
        a_rss_conf.level = 0;
        a_rss_conf.types = rss_conf.rss_hf;
        a_rss_conf.key_len = rss_conf.rss_key_len as u32;

        // Since the RSS key needs to outlive this method, we use the static
        // SYMMETRIC_RSS_KEY instead of the key queried from the existing rss_conf
        a_rss_conf.key = SYMMETRIC_RSS_KEY.as_ptr();

        self.rss.push(a_rss_conf);
    }

    #[allow(dead_code)]
    pub(super) fn append_drop(&mut self) {
        let mut a_drop: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_drop.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP;
        self.rules.push(a_drop);
    }



    /*
    // @ALIYA - pseudocode for masked redirects
    #[allow(dead_code)]
    pub(super) fn append_masked_redirects(&mut self) {
        // We conceptually create 16 buckets for the LS 4 bits (0x0..0xF) of src port.
        // Each bucket jumps to a static table. We map them across tables 2..15, then wrap to 2..3.
        
        const FIRST_TABLE: u32 = 2;   // first jump group/table to use
        const NUM_TABLES: u32 = 14;   // tables 2..15 inclusive

        for bucket in 0..16u32 {
            // Compute the group (table) to jump to for this bucket.
            // 0 -> 2, 1 -> 3, ..., 13 -> 15, 14 -> 2, 15 -> 3
            let group = FIRST_TABLE + (bucket % NUM_TABLES);

            // Action: JUMP
            let mut a_jump: dpdk::rte_flow_action = unsafe { mem::zeroed() };
            a_jump.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP;
            self.rules.push(a_jump);

            // Config for the JUMP action
            let mut jump_conf: dpdk::rte_flow_action_jump = unsafe { mem::zeroed() };
            jump_conf.group = group;
            self.jump.push(jump_conf);
        }

        // Note: This only appends the actions/configs. The *pattern* side that matches
        // (src port & 0x0F) == bucket must be built separately (e.g., in your FlowPattern).
        // Also remember to call `finish()` to add the END terminator after composing actions.

         
        // Option 1 (preferred) would be to figure out how to do an RSS key
        // and chain that into a jump rule.

        // A simpler approach would be to create multiple jump rules
        // that match on bits on the IP addresses or ports. We can't directly
        // use a dynamic key in the jump rule, so we need something static that
        // will still have some entropy.

        // For example: mask on LS 4 bits of the src port = 4 bits = 16 values
        // (14 tables (16 - table 0 - table 1) => wrap last two around)
        // You'll append 16 rules here:
        // - value: src port, mask: 0x0F, matches: [0x0000, 0x0001, ..., 0x000F]
        // - action: jump to table [2, 3, ..., 15, 2, 3]

        // Note - this won't be symmetric, so in software to pick a table
        // we'll need to install each rule on two different tables.
    }
        */
}
