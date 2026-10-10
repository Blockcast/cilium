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
 *   5. multicast daddr + matching *unicast* catch-all     -> local   (the policy
 *                                                            is not a multicast
 *                                                            policy - BLO-27931)
 *   5b. ...including while that catch-all's gateway is still unresolved, the
 *       agent-start transient that the from-lxc consuming site used to turn
 *       into DROP_NO_EGRESS_GATEWAY for every pod multicast send on the node.
 *
 * Cases 2-5 returning "local" mean the caller keeps the pre-existing behavior,
 * which is the regression guard for AC "non-matching multicast and all unicast
 * CEGP traffic follow the pre-existing paths".
 *
 * Case 1 holds for a remote gateway *and* a local one: the classifier is
 * deliberately locality-agnostic, because both placements have a working
 * egress path (remote is encapsulated to the gateway node by
 * egress_gw_handle_request(), local is SNATed in place by
 * egress_gw_mcast_pod_egress()).
 *
 * Which of those two applies is egw_gateway_is_local()'s decision, and it is
 * pinned here as well (BLO-27928). That helper is now the single owner of the
 * question: egress_gw_handle_request() uses it to route the packet, and
 * egress_gw_mcast_pod_egress() uses it to decide whether it is the node that
 * should emit. The second used to ask `gateway_ip == IPV4_DIRECT_ROUTING`
 * instead, so a multi-NIC node whose policy named a local host address other
 * than the direct-routing IP routed the packet locally and then dropped it as
 * remote - losing egress and, because this classifier had already suppressed
 * the subscriber-map fanout, cluster-local delivery too.
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

/* A second address this node owns, on another NIC. GATEWAY_NODE_IP stands in
 * for a gateway on a different node: it is deliberately never given a host
 * endpoint here.
 */
#define HOST_SECONDARY_IP	IPV4(10, 0, 1, 1)

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
#include "lib/endpoint.h"
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
		add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
						GATEWAY_NODE_IP, EGRESS_IP, IFACE_IFINDEX);

		assert(egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
	});

	/* 1b. ...and equally when the gateway is this node. The classifier is
	 * locality-agnostic on purpose: a local gateway is SNATed in place by
	 * egress_gw_mcast_pod_egress(), a remote one is encapsulated to its
	 * node, and both are "leaves via the egress gateway" as far as the
	 * subscriber-map suppression is concerned.
	 */
	TEST("mcast_local_gateway_is_also_egress", {
		endpoint_v4_add_entry(HOST_SECONDARY_IP, 0, 0, ENDPOINT_F_HOST,
				      0, 0, NULL, NULL);
		add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
						HOST_SECONDARY_IP, EGRESS_IP, IFACE_IFINDEX);

		assert(egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
		endpoint_v4_del_entry(HOST_SECONDARY_IP);
	});

	/* 1c. The multi-NIC case (BLO-27928). Any host endpoint of this node
	 * counts as local, not just the direct-routing address -- this is the
	 * predicate egress_gw_handle_request() routes on, and the one
	 * egress_gw_mcast_pod_egress() must agree with. Asking
	 * `gateway_ip == IPV4_DIRECT_ROUTING` here instead is what dropped
	 * these packets on both paths.
	 */
	TEST("gateway_locality_host_endpoint_is_local", {
		endpoint_v4_add_entry(HOST_SECONDARY_IP, 0, 0, ENDPOINT_F_HOST,
				      0, 0, NULL, NULL);

		assert(egw_gateway_is_local(HOST_SECONDARY_IP));

		endpoint_v4_del_entry(HOST_SECONDARY_IP);
	});

	/* 1d. ...and an address with no host endpoint is remote, so the packet
	 * is encapsulated to it rather than emitted here.
	 */
	TEST("gateway_locality_no_endpoint_is_remote", {
		assert(!egw_gateway_is_local(GATEWAY_NODE_IP));
	});

	/* 2. multicast destination with no matching policy keeps local
	 * (cluster-internal) delivery - classifier returns false.
	 */
	TEST("mcast_no_policy_is_local", {
		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP_UNPOLICIED));
	});

	/* 3a. an excluded-CIDR policy is not an egress hit. */
	TEST("mcast_excluded_cidr_is_local", {
		add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
						EGRESS_GATEWAY_EXCLUDED_CIDR, 0, 0);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
	});

	/* 3b. a no-gateway policy is not an egress hit either. */
	TEST("mcast_no_gateway_is_local", {
		add_egressgw_mcast_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR,
						EGRESS_GATEWAY_NO_GATEWAY, 0, 0);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, MCAST_GROUP_PFX, MCAST_CIDR);
	});

	/* 5. the regression this flag exists for (BLO-27931): an ordinary
	 * unicast catch-all policy LPM-matches every multicast destination,
	 * because `0.0.0.0/0` has a zero-length daddr prefix. It is not a
	 * multicast policy -- its prefix base address 0.0.0.0 is not multicast,
	 * so the control plane leaves PolicyConfig.multicast false and stamps
	 * no flag -- and classifying it as one would silently suppress
	 * cluster-local fanout on every cluster that runs ENABLE_MULTICAST
	 * alongside a catch-all CEGP, with no policy change by the operator.
	 *
	 * This is the case the rest of this file could not catch: every other
	 * policy here is installed at 232.0.0.0/4, which is a multicast prefix,
	 * so the packet-derived and policy-derived answers agree and the suite
	 * stayed green.
	 */
	TEST("mcast_unicast_catchall_policy_is_local", {
		add_egressgw_policy_entry(CLIENT_IP, 0, 0,
					  GATEWAY_NODE_IP, EGRESS_IP, IFACE_IFINDEX);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, 0, 0);
	});

	/* 5b. the same catch-all before its gateway has resolved. This is the
	 * shape that made the first consuming site (bpf_lxc.c's
	 * handle_ipv4_from_lxc() egress_gw_handle_request() call) worse than a
	 * mis-routed packet: with that site gated on egw_ipv4_is_mcast() alone,
	 * a catch-all sitting at the NO_GATEWAY sentinel -- a normal transient
	 * at agent start -- returned DROP_NO_EGRESS_GATEWAY for every pod
	 * multicast send on the node, after the entry-path classifier had
	 * already declined to suppress fanout. Both sites now ask this helper,
	 * so the answer is one value and the packet keeps local delivery.
	 */
	TEST("mcast_unicast_catchall_no_gateway_is_local", {
		add_egressgw_policy_entry(CLIENT_IP, 0, 0,
					  EGRESS_GATEWAY_NO_GATEWAY, 0, 0);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, MCAST_GROUP));

		del_egressgw_policy_entry(CLIENT_IP, 0, 0);
	});

	/* 4. a unicast destination, even with a matching real-gateway policy,
	 * is never reclassified by this helper: the multicast-only guard short-
	 * circuits before the lookup, so unicast CEGP semantics are untouched.
	 */
	TEST("unicast_policy_is_not_mcast_egress", {
		add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
					  GATEWAY_NODE_IP, EGRESS_IP, IFACE_IFINDEX);

		assert(!egw_mcast_request_is_egress(CLIENT_IP, EXTERNAL_SVC_IP));

		del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);
	});

	test_finish();
}
