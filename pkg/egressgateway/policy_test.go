// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func getAsPolicyLabelSelectors(k8sLss []*slimv1.LabelSelector) (lss []*policyTypes.LabelSelector) {
	for _, ls := range k8sLss {
		lss = append(lss, policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, ls)))
	}
	return lss
}

func TestParseCEGPMulticastDestinationCIDRs(t *testing.T) {
	tests := []struct {
		name             string
		destinationCIDRs []string
		excludedCIDRs    []string
		wantErrContains  string
	}{
		{
			name:             "accept IPv4 SSM multicast prefix",
			destinationCIDRs: []string{"232.0.0.0/4"},
		},
		{
			name:             "reject IPv4 multicast prefix wider than multicast range",
			destinationCIDRs: []string{"224.0.0.0/3"},
			wantErrContains:  "IPv4 multicast prefixes must stay within 224.0.0.0/4",
		},
		{
			name:             "reject IPv6 multicast prefix",
			destinationCIDRs: []string{"ff00::/8"},
			wantErrContains:  "only IPv4 multicast egress gateway policies are supported",
		},
		{
			name:             "reject multicast excluded CIDR",
			destinationCIDRs: []string{"232.0.0.0/4"},
			excludedCIDRs:    []string{"232.1.1.1/32"},
			wantErrContains:  "multicast egress gateway policies bypass conntrack and cannot use excludedCIDRs",
		},
		{
			name:             "unicast regression",
			destinationCIDRs: []string{"1.1.1.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cegp, _ := newCEGP(&policyParams{
				name:             "policy-1",
				endpointLabels:   map[string]string{"app": "test"},
				destinationCIDRs: tt.destinationCIDRs,
				excludedCIDRs:    tt.excludedCIDRs,
				policyGwParams: []policyGatewayParams{{
					iface: "eth0",
				}},
			})

			config, err := ParseCEGP(cegp)
			if tt.wantErrContains != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErrContains)
				return
			}

			require.NoError(t, err)
			require.Len(t, config.dstCIDRs, len(tt.destinationCIDRs))
		})
	}
}

func TestPolicyConfig_updateMatchedEndpointIDs(t *testing.T) {
	type fields struct {
		id                types.NamespacedName
		endpointSelectors []*slimv1.LabelSelector
		nodeSelectors     []*slimv1.LabelSelector
		dstCIDRs          []netip.Prefix
		excludedCIDRs     []netip.Prefix
		policyGwConfigs   []policyGatewayConfig
		matchedEndpoints  map[endpointID]*endpointMetadata
		gatewayConfigs    []gatewayConfig
	}
	type args struct {
		epDataStore           map[endpointID]*endpointMetadata
		nodesAddresses2Labels map[string]map[string]string
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           int
		wantEndpointID endpointID
	}{
		{
			name: "Test updateMatchedEndpointIDs with endpoints and nodes",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:           1,
			wantEndpointID: endpointID("123456"),
		},
		{
			name: "Test updateMatchedEndpointIDs with namespaced endpoints and nodes",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"io.kubernetes.pod.namespace": "default",
						"app":                         "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"io.kubernetes.pod.namespace": "default",
							"app":                         "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:           1,
			wantEndpointID: endpointID("123456"),
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints and nodes with no match",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.11": {
						"node-name": "node1",
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints and nodes with no match label",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"bar": "bar",
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PolicyConfig{
				id:                tt.fields.id,
				endpointSelectors: getAsPolicyLabelSelectors(tt.fields.endpointSelectors),
				nodeSelectors:     getAsPolicyLabelSelectors(tt.fields.nodeSelectors),
				dstCIDRs:          tt.fields.dstCIDRs,
				excludedCIDRs:     tt.fields.excludedCIDRs,
				policyGwConfigs:   tt.fields.policyGwConfigs,
				matchedEndpoints:  tt.fields.matchedEndpoints,
				gatewayConfigs:    tt.fields.gatewayConfigs,
			}
			config.updateMatchedEndpointIDs(tt.args.epDataStore, tt.args.nodesAddresses2Labels)
			assert.Len(t, config.matchedEndpoints, tt.want)
			if tt.want > 0 {
				assert.Contains(t, config.matchedEndpoints, endpointID(tt.wantEndpointID))
			}
		})
	}
}
