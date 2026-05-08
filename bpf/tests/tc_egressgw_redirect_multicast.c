// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Multicast egress via CiliumEgressGatewayPolicy.
 *
 * Tests that the userspace + datapath path accepts multicast CIDRs in
 * `destinationCIDRs` and produces TC_ACT_REDIRECT for packets matching the
 * policy. Exercises the full from-overlay flow: VXLAN decap →
 * egress_gw_snat_needed_hook (LPM lookup against a 232.0.0.0/4 entry) →
 * ipv4_l3 → set_identity_mark(MARK_MAGIC_EGW_DONE) → egress_gw_fib_lookup_and_redirect.
 *
 * This is a regression test, not a behavioral discriminator: both the new
 * IN_MULTICAST bypass branch and the legacy fib_lookup path produce
 * TC_ACT_REDIRECT (the BPF redirect helper returns the action code
 * regardless of which ifindex was passed). Performance differences (FIB
 * lookup overhead, identity-resolution defense) are not visible to BPF unit
 * tests and need profiling / runtime tooling.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_MASQUERADE_IPV6		1
#define ENCAP_IFINDEX	42
#define IFACE_IFINDEX	44

/* Provide the egress interface to the IPv4 datapath via the compile-time
 * constant (the IPv4 path reads EGRESS_IFINDEX from a #define rather than
 * from the policy struct).
 */
#define EGRESS_IFINDEX	IFACE_IFINDEX

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#define skb_get_tunnel_key mock_skb_get_tunnel_key
static int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
				   struct bpf_tunnel_key *to,
				   __maybe_unused __u32 size,
				   __maybe_unused __u32 flags)
{
	to->remote_ipv4 = v4_node_one;
	/* 0xfffff is the default SECLABEL */
	to->tunnel_id = 0xfffff;
	return 0;
}

#include "lib/bpf_overlay.h"

#include "lib/egressgw.h"
#include "lib/ipcache.h"

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	params->ifindex = IFACE_IFINDEX;
	return 0;
}

#define MCAST_GROUP		IPV4(232, 1, 1, 50)
#define MCAST_PORT		__bpf_htons(8000)
#define MCAST_PUB_PORT		__bpf_htons(58764)

static __always_inline int
multicast_pktgen_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = CLIENT_IP;
	l3->daddr = MCAST_GROUP;
	l3->protocol = IPPROTO_UDP;

	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = MCAST_PUB_PORT;
	l4->dest   = MCAST_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

#define MCAST_GROUP_V6 \
	{ .addr = { 0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34 } }

static __always_inline int
multicast_pktgen_v6(struct __ctx_buff *ctx)
{
	const union v6addr client_v6 = CLIENT_IP_V6;
	const union v6addr mcast_v6  = MCAST_GROUP_V6;
	struct pktgen builder;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;
	memcpy(&l3->saddr, &client_v6, sizeof(l3->saddr));
	memcpy(&l3->daddr, &mcast_v6, sizeof(l3->daddr));
	l3->nexthdr = IPPROTO_UDP;

	l4 = pktgen__push_default_udphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = MCAST_PUB_PORT;
	l4->dest   = MCAST_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* IPv4: a multicast packet matching a CEGP policy installed with
 * destinationCIDRs containing 232.0.0.0/4 produces TC_ACT_REDIRECT.
 */
PKTGEN("tc", "tc_egressgw_redirect_multicast")
int multicast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return multicast_pktgen_v4(ctx);
}

SETUP("tc", "tc_egressgw_redirect_multicast")
int multicast_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, IPV4(232, 0, 0, 0), 4,
				  GATEWAY_NODE_IP, EGRESS_IP);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_redirect_multicast")
int multicast_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_policy_entry(CLIENT_IP, IPV4(232, 0, 0, 0), 4);

	return ret;
}

/* IPv6: a multicast packet matching a CEGP policy installed with
 * destinationCIDRs containing FF00::/8 produces TC_ACT_REDIRECT.
 */
PKTGEN("tc", "tc_egressgw_redirect_multicast_v6")
int multicast_redirect_pktgen_v6(struct __ctx_buff *ctx)
{
	return multicast_pktgen_v6(ctx);
}

SETUP("tc", "tc_egressgw_redirect_multicast_v6")
int multicast_redirect_setup_v6(struct __ctx_buff *ctx)
{
	const union v6addr client_v6   = CLIENT_IP_V6;
	const union v6addr mcast_v6_pfx = { .addr = { 0xff } };
	const union v6addr egress_v6    = EGRESS_IP_V6;

	add_egressgw_policy_entry_v6(&client_v6, &mcast_v6_pfx, 8,
				     GATEWAY_NODE_IP, &egress_v6, IFACE_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_redirect_multicast_v6")
int multicast_redirect_check_v6(const struct __ctx_buff *ctx)
{
	const union v6addr client_v6   = CLIENT_IP_V6;
	const union v6addr mcast_v6_pfx = { .addr = { 0xff } };

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_policy_entry_v6(&client_v6, &mcast_v6_pfx, 8);

	return ret;
}
