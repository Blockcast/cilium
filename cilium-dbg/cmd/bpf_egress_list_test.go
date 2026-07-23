// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEgressPolicySemantics(t *testing.T) {
	tests := []struct {
		name            string
		destCIDR        string
		wantTraffic     string
		wantCTSemantics string
	}{
		{
			name:            "unicast IPv4",
			destCIDR:        "10.0.0.0/24",
			wantTraffic:     "unicast",
			wantCTSemantics: "ct-tracked",
		},
		{
			name:            "multicast IPv4",
			destCIDR:        "232.0.0.0/4",
			wantTraffic:     "multicast",
			wantCTSemantics: "ct-bypass",
		},
		{
			name:            "unicast IPv6",
			destCIDR:        "2001:db8::/64",
			wantTraffic:     "unicast",
			wantCTSemantics: "ct-tracked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traffic, ctSemantics := egressPolicySemantics(netip.MustParsePrefix(tt.destCIDR))
			require.Equal(t, tt.wantTraffic, traffic)
			require.Equal(t, tt.wantCTSemantics, ctSemantics)
		})
	}
}
