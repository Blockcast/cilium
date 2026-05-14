/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "l4.h"
#include "l2_responder.h"
#include "proxy.h"
#include "proxy_hairpin.h"

#ifdef ENABLE_SIP_VERIFICATION
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_IPV6
	union v6addr valid = CONFIG(endpoint_ipv6);

	if (ipv6_addr_equals((union v6addr *)&ip6->saddr, &valid))
		return 1;

	/* Allow saddr that is a locally L2-announced VIP. The kernel AMT
	 * relay and similar in-pod modules bind to a Service ExternalIP and
	 * source packets with it; mirror b5b3b4b908 (sock4_skip_xlate) by
	 * trusting addresses present in the L2 responder map for this node.
	 */
	{
		struct l2_responder_v6_key l2key = {};

		l2key.ifindex = CONFIG(direct_routing_dev_ifindex);
		ipv6_addr_copy(&l2key.ip6, (union v6addr *)&ip6->saddr);
		if (map_lookup_elem(&cilium_l2_responder_v6, &l2key))
			return 1;
	}
	return 0;
#else
	return 0;
#endif
}

static __always_inline
int is_valid_lxc_src_ipv4(const struct iphdr *ip4 __maybe_unused)
{
#ifdef ENABLE_IPV4
	if (ip4->saddr == CONFIG(endpoint_ipv4).be32)
		return 1;

	/* Allow saddr that is a locally L2-announced VIP. See v6 comment. */
	{
		struct l2_responder_v4_key l2key = {};

		l2key.ip4 = ip4->saddr;
		l2key.ifindex = CONFIG(direct_routing_dev_ifindex);
		if (map_lookup_elem(&cilium_l2_responder_v4, &l2key))
			return 1;
	}
	return 0;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else /* ENABLE_SIP_VERIFICATION */
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
	return 1;
}

static __always_inline
int is_valid_lxc_src_ipv4(struct iphdr *ip4 __maybe_unused)
{
	return 1;
}
#endif /* ENABLE_SIP_VERIFICATION */
