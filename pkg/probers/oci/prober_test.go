// SPDX-FileCopyrightText: Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/openvex/go-vex/pkg/vex"
	purl "github.com/package-url/packageurl-go"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/stretchr/testify/require"

	"github.com/openvex/discovery/pkg/discovery/options"
	"github.com/openvex/discovery/pkg/probers/oci/ocifakes"
)

func TestDownloadDocuments(t *testing.T) {
	impl := defaultImplementation{}
	for _, tc := range []struct {
		name      string
		options   options.Options
		reference string
		numDocs   int
		mustErr   bool
	}{
		{
			name:      "image with openvex",
			options:   options.Default,
			reference: "localhost:5000/wolfi-base:latest",
			numDocs:   1,
			mustErr:   false,
		},
		{
			name:      "no attestations",
			options:   options.Default,
			reference: "localhost:5000/notsigned:latest",
			mustErr:   false,
			numDocs:   0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := name.ParseReference(tc.reference)
			require.NoError(t, err)
			se, err := ociremote.SignedEntity(ref)
			require.NoError(t, err)

			docs, err := impl.DownloadDocuments(tc.options, se)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, docs, tc.numDocs)
		})
	}
}

func TestFindDocumentsFromPurl(t *testing.T) {
	prober := New()
	p, err := purl.FromString("pkg:oci/scratch@sha256%3A0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	syntErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		name    string
		options options.Options
		prepare func(*Prober)
		mustErr bool
	}{
		{
			name: "success",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.PurlToReferenceReturns(name.MustParseReference("scratch"), nil)
				impl.DownloadDocumentsReturns([]*vex.VEX{{}}, nil)
				p.impl = impl
			},
		},
		{
			name: "purltoreference fails",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.PurlToReferenceReturns(nil, syntErr)
				p.impl = impl
			},
			mustErr: true,
		},
		{
			name: "resolveimagereference fails",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.ResolveImageReferenceReturns(nil, syntErr)
				p.impl = impl
			},
			mustErr: true,
		},
		{
			name: "dowenloaddocuments fails",
			prepare: func(p *Prober) {
				impl := &ocifakes.FakeOciImplementation{}
				impl.DownloadDocumentsReturns(nil, syntErr)
				p.impl = impl
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.prepare(prober)
			docs, err := prober.FindDocumentsFromPurl(tc.options, p)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, docs)
		})
	}
}
