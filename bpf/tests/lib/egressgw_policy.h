/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_EGRESS_GATEWAY
static __always_inline void add_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr,
						      __be32 gateway_ip, __be32 egress_ip,
						      __u32 egress_ifindex)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V4(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	struct egress_gw_policy_entry_v2 in_val = {
		.egress_ip  = egress_ip,
		.gateway_ip = gateway_ip,
		.egress_ifindex = egress_ifindex,
	};

	map_update_elem(&cilium_egress_gw_policy_v4_v2, &in_key, &in_val, 0);
}

/* Blockcast: the same entry, flagged as a multicast policy -- i.e. one whose
 * CiliumEgressGatewayPolicy destinationCIDR is itself inside 224.0.0.0/4, which
 * is what the control plane stamps into the entry (BLO-27931).
 *
 * Deliberately a separate helper rather than a flags parameter on
 * add_egressgw_policy_entry(): that one has ~50 call sites across the upstream
 * tc_egressgw tests, all of which install unicast policies, and the default an
 * unflagged entry carries -- "not a multicast policy" -- is the correct one for
 * every single one of them.
 */
static __always_inline void add_egressgw_mcast_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr,
							    __be32 gateway_ip, __be32 egress_ip,
							    __u32 egress_ifindex)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V4(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	struct egress_gw_policy_entry_v2 in_val = {
		.egress_ip  = egress_ip,
		.gateway_ip = gateway_ip,
		.egress_ifindex = egress_ifindex,
		.flags = EGRESS_GW_POLICY_F_MULTICAST,
	};

	map_update_elem(&cilium_egress_gw_policy_v4_v2, &in_key, &in_val, 0);
}

static __always_inline void del_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V4(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	map_delete_elem(&cilium_egress_gw_policy_v4_v2, &in_key);
}

#ifdef ENABLE_IPV6
static __always_inline void add_egressgw_policy_entry_v6(const union v6addr *saddr,
							 const union v6addr *daddr,
							 __u8 cidr,
							 __be32 gateway_ip,
							 const union v6addr *egress_ip,
							 __u32 egress_ifindex)
{
	struct egress_gw_policy_key6 in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V6(cidr), {} },
		.saddr   = *saddr,
		.daddr   = *daddr,
	};

	struct egress_gw_policy_entry6 in_val = {
		.egress_ip  = *egress_ip,
		.gateway_ip = gateway_ip,
		.egress_ifindex = egress_ifindex,
	};

	map_update_elem(&cilium_egress_gw_policy_v6, &in_key, &in_val, 0);
}

static __always_inline void del_egressgw_policy_entry_v6(const union v6addr *saddr,
							 const union v6addr *daddr,
							 __u8 cidr)
{
	struct egress_gw_policy_key6 in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V6(cidr), {} },
		.saddr   = *saddr,
		.daddr   = *daddr,
	};

	map_delete_elem(&cilium_egress_gw_policy_v6, &in_key);
}
#endif /* ENABLE_IPV6 */
#endif /* ENABLE_EGRESS_GATEWAY */
