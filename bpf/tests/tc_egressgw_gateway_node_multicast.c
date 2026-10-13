// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Blockcast: gateway-node ordering between the cluster-internal multicast
 * subscriber fast path and multicast egress via CiliumEgressGatewayPolicy
 * (BLO-27475).
 *
 * This is the from-overlay counterpart to tc_egressgw_origin_node_multicast.c.
 * The origin node encapsulates a multicast CEGP hit to the gateway node; this
 * program is what SNATs it there and emits it out the egress interface. The
 * ENABLE_MULTICAST subscriber short-circuit in handle_ipv4() runs *before* that
 * EGW block, and tail_call_internal() never returns, so without a classifier
 * the packet was consumed by local delivery -- and the policy silently stopped
 * emitting -- whenever the gateway node happened to hold a local subscriber for
 * the group.
 *
 * tc_egressgw_redirect_multicast.c covers the same program with multicast
 * compiled out, so the short-circuit is not in the binary there and it cannot
 * see this ordering at all. Hence a separate object with ENABLE_MULTICAST on.
 *
 * The two cases below are a matched pair, and both are load-bearing:
 *
 *   mcast_policy_beats_subscriber - a *flagged* policy must win over a present
 *     subscriber. Fails if the classifier is dropped from bpf_overlay.c.
 *   unflagged_policy_stays_local  - a multicast destination covered by a policy
 *     the control plane did NOT classify as multicast must still take local
 *     delivery. Fails if the classifier is weakened back to the packet test
 *     egw_ipv4_is_mcast(daddr), which is the regression this PR has already
 *     shipped twice.
 *
 * mcast_egress_ip_policy_no_ifindex (BLO-45582) - an egressIP policy carries
 * no egress_ifindex, and the remote-origin path used to drop it with
 * DROP_NO_FIB. It must emit on the direct-routing device with the device's
 * source MAC and the group's destination MAC.
 *
 * mcast_egress_ip_policy_secondary_nic (BLO-45655) - the agent now writes the
 * ifindex of the NIC owning the egressIP into a multicast entry. When that NIC
 * is not the direct-routing device, emission must use it and its MAC.
 *
 * mcast_no_device_state (BLO-45655) - an egress device outside cilium_devices
 * still emits (fail-open) but must count REASON_EGW_MCAST_NO_DEVICE.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MULTICAST		1
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_MASQUERADE_IPV6		1
#define ENCAP_IFINDEX	42
#define IFACE_IFINDEX	44
#define SECONDARY_IFINDEX	46

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

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

/* cilium_mcast_group_outer_v4_map is a BPF_MAP_TYPE_HASH_OF_MAPS, and a BPF
 * program cannot install an inner map into one -- that is a userspace-only
 * operation, which is why no test in this tree populates it. So "this node has
 * a local subscriber for the group" is injected at the call site instead.
 *
 * mcast.h is pulled in here, before the #define below renames the call sites,
 * so the real definition lands under its own name and only bpf_overlay.c's use
 * is redirected. bpf_overlay.c's own `#include "lib/mcast.h"` is then a no-op
 * (#pragma once), so it sees the mock.
 */
#include <bpf/config/node.h>
#include "../lib/mcast.h"

static __u32 mock_subscriber_sentinel;

static __always_inline __maybe_unused void *
mock_mcast_lookup_subscriber_map(__be32 *group __maybe_unused)
{
	return &mock_subscriber_sentinel;
}

#define mcast_lookup_subscriber_map mock_mcast_lookup_subscriber_map

#include "lib/bpf_overlay.h"

#include "lib/clear.h"
#include "lib/egressgw.h"
#include "lib/ipcache.h"
#include "lib/network_device.h"

/* An egressIP policy carries no egress_ifindex; see egw_mcast_redirect(). */
ASSIGN_CONFIG(__u32, direct_routing_dev_ifindex, IFACE_IFINDEX)

static volatile __u32 redirect_ifindex;

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	if ((ifindex == IFACE_IFINDEX || ifindex == SECONDARY_IFINDEX) && flags == 0)
		return TC_ACT_REDIRECT;

	return CTX_ACT_OK;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	params->ifindex = IFACE_IFINDEX;
	return 0;
}

#define MCAST_GROUP		IPV4(232, 1, 1, 50)
#define MCAST_PREFIX		IPV4(232, 0, 0, 0)
#define MCAST_PREFIX_LEN	4
#define MCAST_PORT		__bpf_htons(8000)
#define MCAST_PUB_PORT		__bpf_htons(58764)

static __always_inline int mcast_gateway_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, MCAST_GROUP,
					  MCAST_PUB_PORT, MCAST_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* A multicast CEGP hit must be SNATed and redirected out the egress interface
 * even though this gateway node also has a local subscriber for the group.
 */
PKTGEN("tc", "tc_egressgw_gw_node_mcast_policy_beats_subscriber")
int mcast_policy_beats_subscriber_pktgen(struct __ctx_buff *ctx)
{
	return mcast_gateway_pktgen(ctx);
}

SETUP("tc", "tc_egressgw_gw_node_mcast_policy_beats_subscriber")
int mcast_policy_beats_subscriber_setup(struct __ctx_buff *ctx)
{
	add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN,
					GATEWAY_NODE_IP, EGRESS_IP, IFACE_IFINDEX);

	return overlay_receive_packet(ctx);
}

static __always_inline int mcast_policy_beats_subscriber_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct udphdr *l4;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* The whole point: the subscriber fast path did not consume it. */
	if (*(__u32 *)data != TC_ACT_REDIRECT)
		test_fatal("multicast CEGP hit was not redirected out the egress interface");

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != EGRESS_IP)
		test_fatal("multicast source was not rewritten to egress IP");
	if (l3->daddr != MCAST_GROUP)
		test_fatal("multicast destination changed");
	if (l4->source != MCAST_PUB_PORT || l4->dest != MCAST_PORT)
		test_fatal("multicast UDP ports changed");
	if (csum_fold(csum_diff(NULL, 0, l3, sizeof(*l3), 0)) != 0)
		test_fatal("IPv4 checksum invalid after multicast source rewrite");

	test_finish();
}

CHECK("tc", "tc_egressgw_gw_node_mcast_policy_beats_subscriber")
int mcast_policy_beats_subscriber_check(const struct __ctx_buff *ctx)
{
	int ret = mcast_policy_beats_subscriber_v4_check(ctx);

	del_egressgw_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN);

	return ret;
}

/* Same packet and the same present subscriber, but the policy covering it is
 * one the control plane did NOT classify as multicast. The question the
 * classifier asks is about the *policy*, not the packet, so this must keep the
 * pre-existing local-delivery behaviour: no redirect.
 *
 * Asserted on the status code alone, deliberately. The subscriber branch
 * tail-calls CILIUM_CALL_MULTICAST_EP_DELIVERY, which is not loaded in this
 * object, so the exact drop code is an artifact of the harness rather than of
 * the behaviour under test -- "did not take the egress path" is the claim.
 */
PKTGEN("tc", "tc_egressgw_gw_node_mcast_unflagged_policy_stays_local")
int mcast_unflagged_stays_local_pktgen(struct __ctx_buff *ctx)
{
	return mcast_gateway_pktgen(ctx);
}

SETUP("tc", "tc_egressgw_gw_node_mcast_unflagged_policy_stays_local")
int mcast_unflagged_stays_local_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN,
				  GATEWAY_NODE_IP, EGRESS_IP, IFACE_IFINDEX);

	return overlay_receive_packet(ctx);
}

static __always_inline int mcast_unflagged_stays_local_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	if (*(__u32 *)data == TC_ACT_REDIRECT)
		test_fatal("unflagged policy diverted a multicast packet to egress");

	test_finish();
}

CHECK("tc", "tc_egressgw_gw_node_mcast_unflagged_policy_stays_local")
int mcast_unflagged_stays_local_check(const struct __ctx_buff *ctx)
{
	int ret = mcast_unflagged_stays_local_v4_check(ctx);

	del_egressgw_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN);

	return ret;
}

/* BLO-45582: an egressIP-configured policy (egress_ifindex == 0) must still be
 * emitted, on the direct-routing device, with L2 rewritten for the wire.
 */
#define EGRESS_DEV_MAC	{ 0x02, 0x00, 0x00, 0x00, 0x45, 0x82 }

PKTGEN("tc", "tc_egressgw_gw_node_mcast_egress_ip_policy_no_ifindex")
int mcast_no_ifindex_pktgen(struct __ctx_buff *ctx)
{
	return mcast_gateway_pktgen(ctx);
}

SETUP("tc", "tc_egressgw_gw_node_mcast_egress_ip_policy_no_ifindex")
int mcast_no_ifindex_setup(struct __ctx_buff *ctx)
{
	__u8 dev_mac[ETH_ALEN] = EGRESS_DEV_MAC;

	cilium_device_add_entry(IFACE_IFINDEX, dev_mac, 0);
	add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN,
					GATEWAY_NODE_IP, EGRESS_IP, 0);

	return overlay_receive_packet(ctx);
}

static __always_inline int mcast_emit_v4_check(const struct __ctx_buff *ctx,
					       __u32 want_ifindex, const __u8 *want_smac)
{
	/* 232.1.1.50 -> 01:00:5e:01:01:32 */
	__u8 group_mac[ETH_ALEN] = { 0x01, 0x00, 0x5e, 0x01, 0x01, 0x32 };
	void *data, *data_end;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	if (*(__u32 *)data != TC_ACT_REDIRECT)
		test_fatal("egressIP multicast policy was not redirected (status %u)",
			   *(__u32 *)data);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	if (redirect_ifindex != want_ifindex)
		test_fatal("redirected to ifindex %u, want %u", redirect_ifindex, want_ifindex);
	if (memcmp(l2->h_source, want_smac, ETH_ALEN) != 0)
		test_fatal("source MAC is not the egress device MAC");
	if (memcmp(l2->h_dest, group_mac, ETH_ALEN) != 0)
		test_fatal("destination MAC is not the group MAC");
	if (l3->saddr != EGRESS_IP)
		test_fatal("multicast source was not rewritten to egress IP");

	test_finish();
}

CHECK("tc", "tc_egressgw_gw_node_mcast_egress_ip_policy_no_ifindex")
int mcast_no_ifindex_check(const struct __ctx_buff *ctx)
{
	__u8 dev_mac[ETH_ALEN] = EGRESS_DEV_MAC;
	int ret = mcast_emit_v4_check(ctx, IFACE_IFINDEX, dev_mac);

	del_egressgw_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN);
	cilium_device_del_entry(IFACE_IFINDEX);

	return ret;
}

/* BLO-45655: the egressIP lives on a secondary NIC, so the agent writes that
 * NIC's ifindex into the multicast entry. It must win over the direct-routing
 * device, and the frame must carry the secondary NIC's MAC.
 */
#define SECONDARY_DEV_MAC	{ 0x02, 0x00, 0x00, 0x04, 0x56, 0x55 }

PKTGEN("tc", "tc_egressgw_gw_node_mcast_egress_ip_policy_secondary_nic")
int mcast_secondary_nic_pktgen(struct __ctx_buff *ctx)
{
	return mcast_gateway_pktgen(ctx);
}

SETUP("tc", "tc_egressgw_gw_node_mcast_egress_ip_policy_secondary_nic")
int mcast_secondary_nic_setup(struct __ctx_buff *ctx)
{
	__u8 dev_mac[ETH_ALEN] = EGRESS_DEV_MAC;
	__u8 sec_mac[ETH_ALEN] = SECONDARY_DEV_MAC;

	clear_map(&cilium_metrics);
	cilium_device_add_entry(IFACE_IFINDEX, dev_mac, 0);
	cilium_device_add_entry(SECONDARY_IFINDEX, sec_mac, 0);
	add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN,
					GATEWAY_NODE_IP, EGRESS_IP, SECONDARY_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_gw_node_mcast_egress_ip_policy_secondary_nic")
int mcast_secondary_nic_check(const struct __ctx_buff *ctx)
{
	__u8 sec_mac[ETH_ALEN] = SECONDARY_DEV_MAC;
	struct metrics_key key = {
		.reason = REASON_EGW_MCAST_NO_DEVICE,
		.dir = METRIC_EGRESS,
	};
	int ret = mcast_emit_v4_check(ctx, SECONDARY_IFINDEX, sec_mac);

	del_egressgw_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN);
	cilium_device_del_entry(IFACE_IFINDEX);
	cilium_device_del_entry(SECONDARY_IFINDEX);
	if (ret != TEST_PASS)
		return ret;

	/* Negative control: a device with device_state must not be counted. */
	test_init();
	assert_metrics_count(key, 0);
	test_finish();
}

/* BLO-45655: the egress device has no device_state (not in cilium_devices).
 * Emission stays fail-open with the pod's source MAC, but is counted.
 */
PKTGEN("tc", "tc_egressgw_gw_node_mcast_no_device_state")
int mcast_no_device_state_pktgen(struct __ctx_buff *ctx)
{
	return mcast_gateway_pktgen(ctx);
}

SETUP("tc", "tc_egressgw_gw_node_mcast_no_device_state")
int mcast_no_device_state_setup(struct __ctx_buff *ctx)
{
	clear_map(&cilium_metrics);
	add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN,
					GATEWAY_NODE_IP, EGRESS_IP, SECONDARY_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_gw_node_mcast_no_device_state")
int mcast_no_device_state_check(const struct __ctx_buff *ctx)
{
	__u8 pod_mac[ETH_ALEN] = mac_one_addr;
	struct metrics_key key = {
		.reason = REASON_EGW_MCAST_NO_DEVICE,
		.dir = METRIC_EGRESS,
	};
	int ret = mcast_emit_v4_check(ctx, SECONDARY_IFINDEX, pod_mac);

	del_egressgw_policy_entry(CLIENT_IP, MCAST_PREFIX, MCAST_PREFIX_LEN);
	if (ret != TEST_PASS)
		return ret;

	test_init();
	assert_metrics_count(key, 1);
	test_finish();
}
