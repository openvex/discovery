// SPDX-FileCopyrightText: Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package discovery_test

import (
	"fmt"
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"github.com/openvex/discovery/pkg/discovery"
	"github.com/openvex/discovery/pkg/discovery/discoveryfakes"
)

func TestProbePurl(t *testing.T) {
	syntErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		name    string
		prepare func(*discovery.Agent)
		mustErr bool
	}{
		{
			name: "success",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.FindDocumentsFromPurlReturns([]*vex.VEX{{}}, nil)
				a.SetImplementation(impl)
			},
			mustErr: false,
		},
		{
			name: "parsepParsePurl fails",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.ParsePurlReturns(&packageurl.PackageURL{}, syntErr)
				a.SetImplementation(impl)
			},
			mustErr: true,
		},
		{
			name: "GetPackageProbe fails",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.ParsePurlReturns(&packageurl.PackageURL{}, nil)
				impl.GetPackageProbeReturns(nil, syntErr)
				a.SetImplementation(impl)
			},
			mustErr: true,
		},
		{
			name: "FindDocumentsFromPurl fails",
			prepare: func(a *discovery.Agent) {
				impl := &discoveryfakes.FakeAgentImplementation{}
				impl.ParsePurlReturns(&packageurl.PackageURL{}, nil)
				impl.FindDocumentsFromPurlReturns(nil, syntErr)
				a.SetImplementation(impl)
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := discovery.NewAgent()
			tc.prepare(agent)
			docs, err := agent.ProbePurl("pkg:oci/scratch@sha256%3A0000000000000000000000000000000000000000000000000000000000000000")
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, docs)
		})
	}
}
