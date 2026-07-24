// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Origin-node multicast EGW classification (BLO-8007).
 *
 * The from-container datapath (bpf_lxc.c::__tail_handle_ipv4) short-circuits
 * IN_MULTICAST destinations into the cluster-internal subscriber-map fast path
 * BEFORE any egress-gateway lookup. For pod-originated multicast that an
 * operator has placed under a multicast CiliumEgressGatewayPolicy, that local
 * emission must NOT win - the packet has to leave via the egress gateway.
 *
 * The ordering fix consults egw_mcast_request_is_egress() before the subscriber
 * map. This unit test exercises that classifier directly against the real
 * cilium_egress_gw_policy_v4 map so the contract is pinned independently of the
 * full tail-call datapath:
 *
 *   1. multicast daddr + matching policy w/ real gateway  -> egress  (CEGP wins)
 *   2. multicast daddr + no policy                        -> local   (fanout kept)
 *   3. multicast daddr + excluded-CIDR / no-gateway       -> local   (pre-existing)
 *   4. unicast daddr   + matching policy                  -> local   (unicast CEGP
 *                                                            semantics untouched)
 *
 * Cases 2-4 returning "local" mean the caller keeps the pre-existing behavior,
 * which is the regression guard for AC "non-matching multicast and all unicast
 * CEGP traffic follow the pre-existing paths".
 *
 * The from-overlay (gateway-node) redirect is covered separately by
 * tc_egressgw_redirect_multicast.c.
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

/* IPv4 datapath reads the egress ifindex from this #define rather than the
 * policy struct (the IPv4 policy entry has no egress_ifindex field).
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
#define MCAST_GROUP_PFX		IPV4(232, 0, 0, 0)
#define MCAST_CIDR		4
/* A multicast group that is deliberately NOT placed under any policy. */
#define MCAST_GROUP_UNPOLICIED	IPV4(233, 7, 7, 7)

CHECK("tc", "tc_egressgw_origin_node_mcast_classify")
int egressgw_origin_node_mcast_classify(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	/* 1. multicast destination under a real-gateway policy must be
	 * classified as egress so the from-container path skips local fanout.
	 */
	TEST("mcast_policy_hit_is_egress", {
		add_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
					  GATEWAY_NODE_IP, EGRESS_IP);

		assert(egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
	});

	/* 2. multicast destination with no matching policy keeps local
	 * (cluster-internal) delivery - classifier returns false.
	 */
	TEST("mcast_no_policy_is_local", {
		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP_UNPOLICIED));
	});

	/* 3a. an excluded-CIDR policy is not an egress hit. */
	TEST("mcast_excluded_cidr_is_local", {
		add_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
					  EGRESS_GATEWAY_EXCLUDED_CIDR, 0);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
	});

	/* 3b. a no-gateway policy is not an egress hit either. */
	TEST("mcast_no_gateway_is_local", {
		add_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
					  EGRESS_GATEWAY_NO_GATEWAY, 0);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
	});

	/* 4. a unicast destination, even with a matching real-gateway policy,
	 * is never reclassified by this helper: the multicast-only guard short-
	 * circuits before the lookup, so unicast CEGP semantics are untouched.
	 */
	TEST("unicast_policy_is_not_mcast_egress", {
		add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
					  GATEWAY_NODE_IP, EGRESS_IP);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, EXTERNAL_SVC_IP));

		del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);
	});

	test_finish();
}
