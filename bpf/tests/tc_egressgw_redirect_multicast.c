// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Multicast egress via CiliumEgressGatewayPolicy: regression test that
 * multicast destinations matched by `destinationCIDRs` produce
 * TC_ACT_REDIRECT through the from-overlay path. Both the new IN_MULTICAST
 * bypass and the legacy fib_lookup path return the same action code at the
 * BPF level, so this is a regression guard, not a behavioral discriminator
 * between them.
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

#include "lib/bpf_overlay.h"

#include "lib/egressgw.h"
#include "lib/ipcache.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == IFACE_IFINDEX && flags == 0)
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
#define MCAST_PORT		__bpf_htons(8000)
#define MCAST_PUB_PORT		__bpf_htons(58764)

static __always_inline int multicast_redirect_v4_check(const struct __ctx_buff *ctx,
						      __u32 status_code)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct udphdr *l4;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	assert(*(__u32 *)data == status_code);

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

	tuple.nexthdr = IPPROTO_UDP;
	tuple.saddr = CLIENT_IP;
	tuple.daddr = MCAST_GROUP;
	tuple.sport = MCAST_PUB_PORT;
	tuple.dport = MCAST_PORT;
	__ipv4_ct_tuple_reverse(&tuple);
	if (map_lookup_elem(get_ct_map4(&tuple), &tuple))
		test_fatal("multicast CEGP packet allocated CT state");

	test_finish();
}

/* IPv4: a multicast packet matching a CEGP policy installed with
 * destinationCIDRs containing 232.0.0.0/4 produces TC_ACT_REDIRECT.
 */
PKTGEN("tc", "tc_egressgw_redirect_multicast")
int multicast_redirect_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "tc_egressgw_redirect_multicast")
int multicast_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, IPV4(232, 0, 0, 0), 4,
				  GATEWAY_NODE_IP, EGRESS_IP, IFACE_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_redirect_multicast")
int multicast_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = multicast_redirect_v4_check(ctx, TC_ACT_REDIRECT);

	del_egressgw_policy_entry(CLIENT_IP, IPV4(232, 0, 0, 0), 4);

	return ret;
}

/* There is deliberately no IPv6 counterpart here. ParseCEGP rejects every
 * IPv6 multicast destinationCIDR outright (pkg/egressgateway/policy.go,
 * "only IPv4 multicast egress gateway policies are supported"), and the
 * datapath bypass is gated on egw_ipv4_is_mcast(), so no IPv6 multicast
 * policy can ever reach these programs. The previous v6 triple installed
 * an ff00::/8 policy by writing the map directly and asserted
 * TC_ACT_REDIRECT for it -- a behaviour the control plane forbids, pinned
 * by a status-code-only assertion that would also have passed with the
 * wrong SNAT source. The rejection it should have been guarding is
 * asserted where it actually lives, in
 * TestParseCEGPMulticastDestinationCIDRs/reject_IPv6_multicast_prefix.
 */
